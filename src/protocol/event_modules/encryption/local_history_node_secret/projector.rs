//! Projector for local history range-node secrets.
//!
//! A node may carry `tombstone_node_id` naming an already-projected sibling
//! that this node retires. The event depends on that node, so the common
//! worker applies it only after the path node exists; the projector then
//! writes the new row and exact-deletes the retired row.
//!
//! Validation enforces the binary tree shape on both axes:
//!
//!   * Time tree (`bit_depth=0`): a non-leaf time node may parent another
//!     time node whose range is contained in the parent's range. The
//!     frontier root (`local_key_secret`) implicitly covers the whole time
//!     axis, so it can parent any time-tree node.
//!   * Bridge: a minute_node (`range_width=1, bit_depth=0`) may parent
//!     either another time-tree node (a tombstone-replacement chain) or
//!     a trie node at the same `range_start`.
//!   * Trie tree (`bit_depth>0`): a trie node sits at the same
//!     `range_start` as its parent and at a strictly greater `bit_depth`.
//!     Patricia compression is allowed: a parent's child may sit at any
//!     depth past the parent's depth.
//!
//! Tombstone-only sibling nodes are accepted regardless of the structural
//! parent/child relationship, as long as workspace+frontier match — the
//! tombstone target is the source itself.

use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput, TableDelete};

use super::super::local_key_secret;
use super::types::{LocalHistoryNodeSecret, TIME_TREE_BIT_DEPTH, TRIE_LEAF_BIT_DEPTH};
use super::{codec, schema};

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let node = codec::decode(&event.record.canonical_bytes)?;
    if event.record.workspace_id != Some(node.workspace_id) {
        return Err("local history node workspace metadata does not match event body".to_string());
    }
    let source_node = validate_source(event, &node)?;
    if let Some(source_node) = &source_node {
        validate_child_addressing(source_node, &node)?;
        if let Some(tombstone_node_id) = node.tombstone_node_id {
            if tombstone_node_id != node.source_secret_id {
                return Err(
                    "local history node tombstone must retire its source path node".to_string(),
                );
            }
        }
    } else if node.tombstone_node_id.is_some() {
        return Err("local history node cannot tombstone without a history source".to_string());
    }

    let mut output = ProjectionOutput::rows(vec![schema::local_history_node_secret_row(
        event.context.event_id,
        &node,
    )]);
    if let Some(tombstone_node_id) = node.tombstone_node_id {
        let retired = decode_history_node(event, tombstone_node_id)?;
        if retired.workspace_id != node.workspace_id
            || retired.removal_frontier_id != node.removal_frontier_id
        {
            return Err("local history node tombstone workspace or frontier mismatch".to_string());
        }
        if retired.range_start == node.range_start
            && retired.range_width == node.range_width
            && retired.bit_depth == node.bit_depth
            && retired.event_id_prefix == node.event_id_prefix
        {
            return Err("local history node cannot tombstone its own coordinate".to_string());
        }
        output.rows.push(schema::local_history_node_tombstone_row(
            &node,
            event.context.event_id,
            tombstone_node_id,
        ));
        output.deletes.push(TableDelete {
            table: schema::LOCAL_HISTORY_NODE_SECRETS,
            key: schema::local_history_node_secret_key(
                retired.workspace_id,
                retired.removal_frontier_id,
                retired.range_start,
                retired.range_width,
                retired.bit_depth,
                retired.event_id_prefix,
            ),
        });
    }
    Ok(output)
}

fn validate_source(
    event: &EventWithContext<'_>,
    node: &LocalHistoryNodeSecret,
) -> Result<Option<LocalHistoryNodeSecret>, String> {
    let source = event
        .context
        .dependency(&node.source_secret_id)
        .ok_or_else(|| "local history node source dependency is missing".to_string())?;
    if let Ok(source_node) = codec::decode(&source.canonical_bytes) {
        if source_node.workspace_id != node.workspace_id
            || source_node.removal_frontier_id != node.removal_frontier_id
        {
            return Err("local history node source workspace or frontier mismatch".to_string());
        }
        return Ok(Some(source_node));
    }
    let source_key = local_key_secret::codec::decode(&source.canonical_bytes)
        .map_err(|_| "local history node source dependency is not key material".to_string())?;
    if source_key.workspace_id != node.workspace_id
        || source_key.removal_frontier_id != node.removal_frontier_id
    {
        return Err("local history node source workspace or frontier mismatch".to_string());
    }
    Ok(None)
}

fn validate_child_addressing(
    source: &LocalHistoryNodeSecret,
    node: &LocalHistoryNodeSecret,
) -> Result<(), String> {
    // Tombstone-only sibling nodes bypass the structural relationship: they
    // are allowed as long as they retire the source they descend from. The
    // caller validates `tombstone_node_id == source_secret_id`.
    if node.tombstone_node_id.is_some() {
        return Ok(());
    }

    // Trie children must sit at the same minute slot as their parent.
    if node.bit_depth > TIME_TREE_BIT_DEPTH {
        if source.range_start != node.range_start {
            return Err(
                "local history node trie child must share its parent's range_start".to_string(),
            );
        }
        if node.bit_depth <= source.bit_depth {
            return Err(
                "local history node trie child bit_depth must exceed its parent's".to_string(),
            );
        }
        if source.bit_depth >= TRIE_LEAF_BIT_DEPTH {
            return Err("local history node leaf cannot have children".to_string());
        }
        // Source must cover the child's prefix: the parent's prefix bits
        // must match the child's prefix bits up to the parent's depth.
        let masked = super::types::mask_prefix_to_depth(node.event_id_prefix, source.bit_depth);
        if masked != source.event_id_prefix {
            return Err(
                "local history node trie child prefix must extend its parent's prefix".to_string(),
            );
        }
        return Ok(());
    }

    // Time-tree children: the parent must be a time-tree node (bit_depth=0)
    // strictly larger in range_width than the child, and the child must lie
    // inside the parent's range.
    if source.bit_depth != TIME_TREE_BIT_DEPTH {
        return Err(
            "local history node time-tree child cannot descend from a trie node".to_string(),
        );
    }
    if source.range_width <= node.range_width {
        return Err(
            "local history node time-tree child must have a strictly smaller range_width"
                .to_string(),
        );
    }
    let parent_end = source.range_start.saturating_add(source.range_width);
    let child_end = node.range_start.saturating_add(node.range_width);
    if node.range_start < source.range_start || child_end > parent_end {
        return Err(
            "local history node time-tree child range is outside its parent's range".to_string(),
        );
    }
    Ok(())
}

fn decode_history_node(
    event: &EventWithContext<'_>,
    node_id: [u8; 32],
) -> Result<LocalHistoryNodeSecret, String> {
    let record = event
        .context
        .dependency(&node_id)
        .ok_or_else(|| "local history node tombstone dependency is missing".to_string())?;
    codec::decode(&record.canonical_bytes)
        .map_err(|_| "local history node tombstone dependency is not a history node".to_string())
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::types::event_id;
    use crate::protocol::event_modules::worker::{
        DependencyContext, EventContext, EventWithContext,
    };

    use super::super::super::local_key_secret;
    use super::super::commands;
    use super::super::types::TRIE_LEAF_BIT_DEPTH;
    use super::*;

    type Record = crate::protocol::event_modules::types::EventRecord;

    fn key_secret_record() -> Record {
        local_key_secret::commands::from_key_secret([1; 32], [2; 32], [7; 32])
            .expect("key secret")
            .events[0]
            .record()
            .clone()
    }

    fn time_split_record(
        parent_secret_id: [u8; 32],
        parent_secret: [u8; 32],
        parent_range_start: u64,
        parent_range_width: u64,
        child_side: u8,
        child_range_start: u64,
        child_range_width: u64,
        tombstone_node_id: Option<[u8; 32]>,
    ) -> Record {
        commands::derive_time_split(commands::DeriveTimeSplit {
            workspace_id: [1; 32],
            removal_frontier_id: [2; 32],
            parent_secret_id,
            parent_secret,
            parent_range_start,
            parent_range_width,
            child_side,
            child_range_start,
            child_range_width,
            tombstone_node_id,
        })
        .expect("derive time split")
        .events[0]
            .record()
            .clone()
    }

    fn trie_split_record(
        parent_secret_id: [u8; 32],
        parent_secret: [u8; 32],
        range_start: u64,
        parent_bit_depth: u16,
        parent_event_id_prefix: [u8; 32],
        child_side: u8,
        child_bit_depth: u16,
        child_event_id_prefix: [u8; 32],
        tombstone_node_id: Option<[u8; 32]>,
    ) -> Record {
        commands::derive_trie_split(commands::DeriveTrieSplit {
            workspace_id: [1; 32],
            removal_frontier_id: [2; 32],
            parent_secret_id,
            parent_secret,
            range_start,
            parent_bit_depth,
            parent_event_id_prefix,
            child_side,
            child_bit_depth,
            child_event_id_prefix,
            tombstone_node_id,
        })
        .expect("derive trie split")
        .events[0]
            .record()
            .clone()
    }

    fn event_with_context<'a>(
        record: &'a Record,
        deps: Vec<([u8; 32], Record)>,
    ) -> EventWithContext<'a> {
        EventWithContext {
            record,
            context: EventContext {
                event_id: event_id(&record.canonical_bytes),
                dependencies: deps
                    .into_iter()
                    .map(|(event_id, record)| DependencyContext { event_id, record })
                    .collect(),
                labels: Vec::new(),
                receive: None,
            },
        }
    }

    #[test]
    fn projects_minute_node_row_from_root_key_secret() {
        let key_record = key_secret_record();
        let key_id = event_id(&key_record.canonical_bytes);
        let record = time_split_record(key_id, [7; 32], 0, u64::MAX, 0, 1_700_000, 1, None);
        let event = event_with_context(&record, vec![(key_id, key_record)]);

        let output = project(&event).expect("project minute_node");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::LOCAL_HISTORY_NODE_SECRETS);
        let row = schema::decode_local_history_node_secret_row(
            &output.rows[0].key,
            &output.rows[0].value,
        )
        .expect("decode row");
        assert_eq!(row.range_start, 1_700_000);
        assert_eq!(row.range_width, 1);
        assert_eq!(row.bit_depth, 0);
        assert_eq!(row.event_id_prefix, [0; 32]);
    }

    #[test]
    fn projects_trie_leaf_under_minute_node() {
        let key_record = key_secret_record();
        let key_id = event_id(&key_record.canonical_bytes);
        let minute_record = time_split_record(key_id, [7; 32], 0, u64::MAX, 0, 1_700_000, 1, None);
        let minute_id = event_id(&minute_record.canonical_bytes);
        let minute = codec::decode(&minute_record.canonical_bytes).expect("minute");
        let leaf_id_in_minute = [9; 32];
        let leaf_record = trie_split_record(
            minute_id,
            minute.node_secret,
            1_700_000,
            0,
            [0; 32],
            0,
            TRIE_LEAF_BIT_DEPTH,
            leaf_id_in_minute,
            None,
        );
        let event = event_with_context(
            &leaf_record,
            vec![(key_id, key_record), (minute_id, minute_record)],
        );

        let output = project(&event).expect("project leaf");

        assert_eq!(output.rows.len(), 1);
        let row = schema::decode_local_history_node_secret_row(
            &output.rows[0].key,
            &output.rows[0].value,
        )
        .expect("decode leaf");
        assert_eq!(row.bit_depth, TRIE_LEAF_BIT_DEPTH);
        assert_eq!(row.event_id_prefix, leaf_id_in_minute);
    }

    #[test]
    fn rejects_source_from_other_frontier() {
        let key_record = key_secret_record();
        let key_id = event_id(&key_record.canonical_bytes);
        let record = commands::derive_time_split(commands::DeriveTimeSplit {
            workspace_id: [1; 32],
            removal_frontier_id: [9; 32],
            parent_secret_id: key_id,
            parent_secret: [7; 32],
            parent_range_start: 0,
            parent_range_width: u64::MAX,
            child_side: 0,
            child_range_start: 1_700_000,
            child_range_width: 1,
            tombstone_node_id: None,
        })
        .expect("derive")
        .events[0]
            .record()
            .clone();
        let event = event_with_context(&record, vec![(key_id, key_record)]);

        assert_eq!(
            project(&event).expect_err("wrong frontier must fail"),
            "local history node source workspace or frontier mismatch"
        );
    }

    #[test]
    fn trie_leaf_in_different_minute_than_parent_is_rejected() {
        let key_record = key_secret_record();
        let key_id = event_id(&key_record.canonical_bytes);
        let minute_record = time_split_record(key_id, [7; 32], 0, u64::MAX, 0, 1_700_000, 1, None);
        let minute_id = event_id(&minute_record.canonical_bytes);
        let minute = codec::decode(&minute_record.canonical_bytes).expect("minute");
        let leaf_record = trie_split_record(
            minute_id,
            minute.node_secret,
            1_700_001,
            0,
            [0; 32],
            0,
            TRIE_LEAF_BIT_DEPTH,
            [9; 32],
            None,
        );
        let event = event_with_context(
            &leaf_record,
            vec![(key_id, key_record), (minute_id, minute_record)],
        );

        let err = project(&event).expect_err("non-matching minute must fail");
        assert!(
            err.contains("range_start"),
            "expected range_start error, got {err}"
        );
    }
}

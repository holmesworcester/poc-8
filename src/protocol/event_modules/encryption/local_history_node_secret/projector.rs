//! Projector for local history range-node secrets.
//!
//! A sibling node can name an already-projected local node to retire. The event
//! depends on that node, so the common worker applies the sibling only after the
//! path node exists, then writes the sibling row and purges the retired row.
//!
//! After the per-message FS leaf-coord redesign the tree shape is:
//!
//! ```text
//!   local_key_secret (frontier root, range_width=1, event_id_in_minute=None)
//!     └── minute_node (range_start=unix_minute, range_width=1, event_id_in_minute=None)
//!           ├── leaf (range_start=unix_minute, range_width=1, event_id_in_minute=Some(nonce_a))
//!           └── leaf (range_start=unix_minute, range_width=1, event_id_in_minute=Some(nonce_b))
//! ```
//!
//! The projector validates that:
//!   - A minute_node's source is a `local_key_secret` (frontier root) under
//!     the same workspace and frontier.
//!   - A per-message leaf's source is a `local_history_node_secret` minute_node
//!     under the same workspace and frontier with the same `range_start`
//!     (i.e. the leaf lives in the same minute as its parent minute_node).

use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput, TableDelete};

use super::super::local_key_secret;
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
            && retired.event_id_in_minute == node.event_id_in_minute
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
                retired.event_id_in_minute,
            ),
        });
    }
    Ok(output)
}

fn validate_source(
    event: &EventWithContext<'_>,
    node: &super::types::LocalHistoryNodeSecret,
) -> Result<Option<super::types::LocalHistoryNodeSecret>, String> {
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
    source: &super::types::LocalHistoryNodeSecret,
    node: &super::types::LocalHistoryNodeSecret,
) -> Result<(), String> {
    // Two valid parent/child relationships in the new tree:
    //   * minute_node parented by another minute_node only when the child
    //     retires the parent (a tombstone path); for non-tombstone derivation
    //     a minute_node is sourced from the frontier root, which is a
    //     `local_key_secret` and reaches `validate_source -> Ok(None)` instead
    //     of this function.
    //   * leaf (event_id_in_minute = Some) parented by a minute_node
    //     (event_id_in_minute = None) at the same `range_start`.
    let same_minute = source.range_start == node.range_start && source.range_width == 1;
    let parent_is_minute_node = source.event_id_in_minute.is_none() && source.range_width == 1;
    let child_is_leaf = node.event_id_in_minute.is_some() && node.range_width == 1;
    if same_minute && parent_is_minute_node && child_is_leaf {
        return Ok(());
    }
    if node.tombstone_node_id.is_some() {
        // Tombstone-only sibling node: allowed regardless of the standard
        // parent/child relationship as long as workspace+frontier match. The
        // tombstone target is the source itself; the validity of the retire
        // is checked by the caller via the `tombstone_node_id == source`
        // rule.
        return Ok(());
    }
    Err("local history node coordinate is not a valid child of the source range".to_string())
}

fn decode_history_node(
    event: &EventWithContext<'_>,
    node_id: [u8; 32],
) -> Result<super::types::LocalHistoryNodeSecret, String> {
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
    use super::*;

    type Record = crate::protocol::event_modules::types::EventRecord;

    fn key_secret_record() -> Record {
        local_key_secret::commands::from_key_secret([1; 32], [2; 32], [7; 32])
            .expect("key secret")
            .events[0]
            .record()
            .clone()
    }

    fn history_record(
        source_secret_id: [u8; 32],
        source_secret: [u8; 32],
        range_start: u64,
        range_width: u64,
        event_id_in_minute: Option<[u8; 32]>,
        tombstone_node_id: Option<[u8; 32]>,
    ) -> Record {
        commands::derive(commands::DeriveHistoryNodeSecret {
            workspace_id: [1; 32],
            removal_frontier_id: [2; 32],
            source_secret_id,
            source_secret,
            range_start,
            range_width,
            event_id_in_minute,
            tombstone_node_id,
        })
        .expect("derive node")
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
    fn projects_minute_node_row_from_valid_key_secret_source() {
        let key_record = key_secret_record();
        let key_id = event_id(&key_record.canonical_bytes);
        let record = history_record(key_id, [7; 32], 1_700_000, 1, None, None);
        let event = event_with_context(&record, vec![(key_id, key_record)]);

        let output = project(&event).expect("project minute node");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::LOCAL_HISTORY_NODE_SECRETS);
        let row = schema::decode_local_history_node_secret_row(
            &output.rows[0].key,
            &output.rows[0].value,
        )
        .expect("decode row");
        assert_eq!(row.range_start, 1_700_000);
        assert_eq!(row.range_width, 1);
        assert_eq!(row.event_id_in_minute, None);
        assert_eq!(row.local_history_node_secret_id, event.context.event_id);
    }

    #[test]
    fn projects_per_message_leaf_under_minute_node() {
        let key_record = key_secret_record();
        let key_id = event_id(&key_record.canonical_bytes);
        let minute_record = history_record(key_id, [7; 32], 1_700_000, 1, None, None);
        let minute_id = event_id(&minute_record.canonical_bytes);
        let minute = codec::decode(&minute_record.canonical_bytes).expect("minute");
        let leaf_nonce = [9; 32];
        let leaf_record = history_record(
            minute_id,
            minute.node_secret,
            1_700_000,
            1,
            Some(leaf_nonce),
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
        assert_eq!(row.event_id_in_minute, Some(leaf_nonce));
    }

    #[test]
    fn rejects_source_from_other_frontier() {
        let key_record = key_secret_record();
        let key_id = event_id(&key_record.canonical_bytes);
        let record = commands::derive(commands::DeriveHistoryNodeSecret {
            workspace_id: [1; 32],
            removal_frontier_id: [9; 32],
            source_secret_id: key_id,
            source_secret: [7; 32],
            range_start: 1_700_000,
            range_width: 1,
            event_id_in_minute: None,
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
    fn leaf_in_different_minute_than_source_is_rejected() {
        let key_record = key_secret_record();
        let key_id = event_id(&key_record.canonical_bytes);
        let minute_record = history_record(key_id, [7; 32], 1_700_000, 1, None, None);
        let minute_id = event_id(&minute_record.canonical_bytes);
        let minute = codec::decode(&minute_record.canonical_bytes).expect("minute");
        // Authoring a leaf at a different unix_minute than its parent
        // minute_node is structurally invalid.
        let leaf_record = history_record(
            minute_id,
            minute.node_secret,
            1_700_001,
            1,
            Some([9; 32]),
            None,
        );
        let event = event_with_context(
            &leaf_record,
            vec![(key_id, key_record), (minute_id, minute_record)],
        );

        let err = project(&event).expect_err("non-matching minute must fail");
        assert!(
            err.contains("not a valid child"),
            "expected child range error, got {err}"
        );
    }
}

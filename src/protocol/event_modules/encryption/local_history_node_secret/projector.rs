//! Projector for local history range-node secrets.
//!
//! A sibling node can name an already-projected local node to retire. The event
//! depends on that node, so the common worker applies the sibling only after the
//! path node exists, then writes the sibling row and purges the retired row.

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
        validate_child_range(source_node, &node)?;
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
        if retired.range_start == node.range_start && retired.range_width == node.range_width {
            return Err("local history node cannot tombstone its own range".to_string());
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

fn validate_child_range(
    source: &super::types::LocalHistoryNodeSecret,
    node: &super::types::LocalHistoryNodeSecret,
) -> Result<(), String> {
    let child_width = source
        .range_width
        .checked_div(2)
        .filter(|width| *width > 0)
        .ok_or_else(|| "local history node source range cannot be split".to_string())?;
    if node.range_width != child_width {
        return Err("local history node range must be one child of the source range".to_string());
    }
    let right_start = source
        .range_start
        .checked_add(child_width)
        .ok_or_else(|| "local history node source range overflows".to_string())?;
    if node.range_start != source.range_start && node.range_start != right_start {
        return Err("local history node range must be one child of the source range".to_string());
    }
    Ok(())
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
        tombstone_node_id: Option<[u8; 32]>,
    ) -> Record {
        commands::derive(commands::DeriveHistoryNodeSecret {
            workspace_id: [1; 32],
            removal_frontier_id: [2; 32],
            source_secret_id,
            source_secret,
            range_start,
            range_width,
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
    fn projects_node_row_from_valid_source_secret() {
        let key_record = key_secret_record();
        let key_id = event_id(&key_record.canonical_bytes);
        let record = history_record(key_id, [7; 32], 0, 8, None);
        let event = event_with_context(&record, vec![(key_id, key_record)]);

        let output = project(&event).expect("project node");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::LOCAL_HISTORY_NODE_SECRETS);
        let row = schema::decode_local_history_node_secret_row(
            &output.rows[0].key,
            &output.rows[0].value,
        )
        .expect("decode row");
        assert_eq!(row.range_start, 0);
        assert_eq!(row.range_width, 8);
        assert_eq!(row.local_history_node_secret_id, event.context.event_id);
    }

    #[test]
    fn sibling_node_tombstones_retired_path_node_by_exact_row_key() {
        let key_record = key_secret_record();
        let key_id = event_id(&key_record.canonical_bytes);
        let parent_record = history_record(key_id, [7; 32], 0, 8, None);
        let parent_id = event_id(&parent_record.canonical_bytes);
        let parent = codec::decode(&parent_record.canonical_bytes).expect("parent");
        let sibling_record = history_record(parent_id, parent.node_secret, 4, 4, Some(parent_id));
        let event = event_with_context(
            &sibling_record,
            vec![(key_id, key_record), (parent_id, parent_record)],
        );

        let output = project(&event).expect("project sibling");

        assert_eq!(output.rows.len(), 2);
        assert_eq!(output.deletes.len(), 1);
        assert_eq!(output.rows[1].table, schema::LOCAL_HISTORY_NODE_TOMBSTONES);
        assert_eq!(
            output.deletes[0].key,
            schema::local_history_node_secret_key([1; 32], [2; 32], 0, 8)
        );
        let row = schema::decode_local_history_node_tombstone_row(
            &output.rows[1].key,
            &output.rows[1].value,
        )
        .expect("decode tombstone");
        assert_eq!(row.tombstone_node_id, parent_id);
        assert_eq!(row.replacement_node_id, event.context.event_id);
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
            range_start: 0,
            range_width: 8,
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
    fn rejects_history_node_that_is_not_source_child() {
        let key_record = key_secret_record();
        let key_id = event_id(&key_record.canonical_bytes);
        let parent_record = history_record(key_id, [7; 32], 0, 8, None);
        let parent_id = event_id(&parent_record.canonical_bytes);
        let parent = codec::decode(&parent_record.canonical_bytes).expect("parent");
        let record = history_record(parent_id, parent.node_secret, 8, 4, None);
        let event = event_with_context(&record, vec![(parent_id, parent_record)]);

        assert_eq!(
            project(&event).expect_err("non-child range must fail"),
            "local history node range must be one child of the source range"
        );
    }
}

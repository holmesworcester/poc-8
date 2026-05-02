use std::collections::HashMap;

use crate::event_modules::{LabelOp, Projection, RowOp, SqlValue};
use crate::pipeline::EventId;

use super::codec::{ReactionEvent, TYPE_NAME};

pub const TABLES: &[&str] = &[
    "
    CREATE TABLE IF NOT EXISTS reactions (
        event_id BLOB PRIMARY KEY NOT NULL,
        workspace_id BLOB NOT NULL,
        message_event_id BLOB NOT NULL,
        emoji TEXT NOT NULL,
        source_event_id BLOB NOT NULL
    );
    ",
    "CREATE INDEX IF NOT EXISTS idx_reactions_message ON reactions(message_event_id);",
];

pub fn project(
    event_id: EventId,
    event: &ReactionEvent,
    labels: &HashMap<EventId, Vec<String>>,
) -> Projection {
    if labels
        .get(&event.message_event_id)
        .is_some_and(|labels| labels.iter().any(|label| label == "deleted"))
    {
        return Projection::default();
    }

    Projection {
        row_ops: vec![RowOp::upsert(
            "reactions",
            &[
                "event_id",
                "workspace_id",
                "message_event_id",
                "emoji",
                "source_event_id",
            ],
            vec![
                SqlValue::Blob(event_id.to_vec()),
                SqlValue::Blob(event.workspace_id.to_vec()),
                SqlValue::Blob(event.message_event_id.to_vec()),
                SqlValue::Text(event.emoji.clone()),
                SqlValue::Blob(event_id.to_vec()),
            ],
        )],
        labels: vec![LabelOp {
            subject_event_id: event_id,
            label: TYPE_NAME.to_string(),
        }],
        ..Projection::default()
    }
}

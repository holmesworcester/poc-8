use std::collections::HashMap;

use crate::event_modules::{LabelOp, OutboxOp, Projection, ProjectionContext, RowOp, SqlValue};
use crate::pipeline::EventId;

use super::codec::{MessageEvent, TYPE_NAME};

pub const TABLES: &[&str] = &[
    "
    CREATE TABLE IF NOT EXISTS messages (
        event_id BLOB PRIMARY KEY NOT NULL,
        workspace_id BLOB NOT NULL,
        reply_to_event_id BLOB NOT NULL,
        body TEXT NOT NULL,
        source_event_id BLOB NOT NULL
    );
    ",
    "CREATE INDEX IF NOT EXISTS idx_messages_workspace ON messages(workspace_id);",
];

pub fn project(
    event_id: EventId,
    event: &MessageEvent,
    labels: &HashMap<EventId, Vec<String>>,
    context: &ProjectionContext,
) -> Projection {
    if labels
        .get(&event.reply_to_event_id)
        .is_some_and(|labels| labels.iter().any(|label| label == "deleted"))
    {
        return Projection::default();
    }

    let mut projection = Projection {
        row_ops: vec![RowOp::upsert(
            "messages",
            &[
                "event_id",
                "workspace_id",
                "reply_to_event_id",
                "body",
                "source_event_id",
            ],
            vec![
                SqlValue::Blob(event_id.to_vec()),
                SqlValue::Blob(event.workspace_id.to_vec()),
                SqlValue::Blob(event.reply_to_event_id.to_vec()),
                SqlValue::Text(event.body.clone()),
                SqlValue::Blob(event_id.to_vec()),
            ],
        )],
        labels: vec![LabelOp {
            subject_event_id: event_id,
            label: TYPE_NAME.to_string(),
        }],
        ..Projection::default()
    };

    if event.fanout_connection_id != [0; 32]
        && Some(event.fanout_connection_id) != context.origin_connection_id
    {
        projection.outbox.push(OutboxOp {
            connection_id: event.fanout_connection_id,
            event_id,
        });
    }

    projection
}

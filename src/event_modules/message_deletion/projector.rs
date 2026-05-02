use crate::event_modules::{LabelOp, Projection, RowOp, SqlValue};
use crate::pipeline::EventId;

use super::codec::{MessageDeletionEvent, TYPE_NAME};

pub const TABLES: &[&str] = &["
    CREATE TABLE IF NOT EXISTS deleted_messages (
        message_event_id BLOB PRIMARY KEY NOT NULL,
        deletion_event_id BLOB NOT NULL
    );
"];

pub fn project(event_id: EventId, event: &MessageDeletionEvent) -> Projection {
    Projection {
        row_ops: vec![RowOp::upsert(
            "deleted_messages",
            &["message_event_id", "deletion_event_id"],
            vec![
                SqlValue::Blob(event.message_event_id.to_vec()),
                SqlValue::Blob(event_id.to_vec()),
            ],
        )],
        labels: vec![
            LabelOp {
                subject_event_id: event.message_event_id,
                label: "deleted".to_string(),
            },
            LabelOp {
                subject_event_id: event_id,
                label: TYPE_NAME.to_string(),
            },
        ],
        ..Projection::default()
    }
}

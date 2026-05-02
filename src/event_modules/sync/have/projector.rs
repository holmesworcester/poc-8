use crate::event_modules::{LabelOp, Projection, RowOp, SqlValue};
use crate::pipeline::EventId;

use super::codec::{SyncHaveEvent, TYPE_NAME};

pub const TABLE: &str = "
    CREATE TABLE IF NOT EXISTS sync_have (
        event_id BLOB PRIMARY KEY NOT NULL,
        workspace_id BLOB NOT NULL,
        connection_id BLOB NOT NULL,
        have_event_id BLOB NOT NULL
    );
    ";

pub fn project(event_id: EventId, event: &SyncHaveEvent) -> Projection {
    Projection {
        row_ops: vec![RowOp::upsert(
            "sync_have",
            &["event_id", "workspace_id", "connection_id", "have_event_id"],
            vec![
                SqlValue::Blob(event_id.to_vec()),
                SqlValue::Blob(event.workspace_id.to_vec()),
                SqlValue::Blob(event.connection_id.to_vec()),
                SqlValue::Blob(event.have_event_id.to_vec()),
            ],
        )],
        labels: vec![LabelOp {
            subject_event_id: event_id,
            label: TYPE_NAME.to_string(),
        }],
        ..Projection::default()
    }
}

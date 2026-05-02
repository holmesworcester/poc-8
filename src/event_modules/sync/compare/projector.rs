use crate::event_modules::{LabelOp, Projection, RowOp, SqlValue};
use crate::pipeline::EventId;

use super::codec::{SyncCompareEvent, TYPE_NAME};

pub const TABLE: &str = "
    CREATE TABLE IF NOT EXISTS sync_compares (
        event_id BLOB PRIMARY KEY NOT NULL,
        workspace_id BLOB NOT NULL,
        connection_id BLOB NOT NULL,
        root BLOB NOT NULL
    );
    ";

pub fn project(event_id: EventId, event: &SyncCompareEvent) -> Projection {
    Projection {
        row_ops: vec![RowOp::upsert(
            "sync_compares",
            &["event_id", "workspace_id", "connection_id", "root"],
            vec![
                SqlValue::Blob(event_id.to_vec()),
                SqlValue::Blob(event.workspace_id.to_vec()),
                SqlValue::Blob(event.connection_id.to_vec()),
                SqlValue::Blob(event.root.to_vec()),
            ],
        )],
        labels: vec![LabelOp {
            subject_event_id: event_id,
            label: TYPE_NAME.to_string(),
        }],
        ..Projection::default()
    }
}

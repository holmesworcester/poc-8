use crate::event_modules::{LabelOp, Projection, RowOp, SqlValue};
use crate::pipeline::EventId;

use super::codec::{FileEvent, TYPE_NAME};

pub const TABLES: &[&str] = &[
    "
    CREATE TABLE IF NOT EXISTS files (
        event_id BLOB PRIMARY KEY NOT NULL,
        workspace_id BLOB NOT NULL,
        name TEXT NOT NULL,
        byte_len INTEGER NOT NULL,
        content_hash TEXT NOT NULL,
        bytes BLOB NOT NULL,
        source_event_id BLOB NOT NULL
    );
    ",
    "CREATE INDEX IF NOT EXISTS idx_files_workspace ON files(workspace_id);",
];

pub fn project(event_id: EventId, event: &FileEvent) -> Projection {
    Projection {
        row_ops: vec![RowOp::upsert(
            "files",
            &[
                "event_id",
                "workspace_id",
                "name",
                "byte_len",
                "content_hash",
                "bytes",
                "source_event_id",
            ],
            vec![
                SqlValue::Blob(event_id.to_vec()),
                SqlValue::Blob(event.workspace_id.to_vec()),
                SqlValue::Text(event.name.clone()),
                SqlValue::Integer(event.bytes.len() as i64),
                SqlValue::Text(blake3::hash(&event.bytes).to_hex().to_string()),
                SqlValue::Blob(event.bytes.clone()),
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

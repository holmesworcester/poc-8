use crate::event_modules::{LabelOp, Projection, RowOp, SqlValue};
use crate::pipeline::EventId;

use super::codec::{ConnectionEvent, TYPE_NAME};

pub const TABLES: &[&str] = &[
    "
    CREATE TABLE IF NOT EXISTS connections (
        connection_id BLOB PRIMARY KEY NOT NULL,
        workspace_id BLOB NOT NULL,
        peer_id BLOB NOT NULL,
        source_event_id BLOB NOT NULL
    );
    ",
    "CREATE INDEX IF NOT EXISTS idx_connections_workspace ON connections(workspace_id);",
];

pub fn project(event_id: EventId, event: &ConnectionEvent) -> Projection {
    Projection {
        row_ops: vec![RowOp::upsert(
            "connections",
            &[
                "connection_id",
                "workspace_id",
                "peer_id",
                "source_event_id",
            ],
            vec![
                SqlValue::Blob(event.connection_id.to_vec()),
                SqlValue::Blob(event.workspace_id.to_vec()),
                SqlValue::Blob(event.peer_id.to_vec()),
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

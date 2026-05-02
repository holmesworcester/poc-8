use crate::event_modules::{LabelOp, Projection, RowOp, SqlValue};
use crate::pipeline::EventId;

use super::codec::{WorkspaceEvent, TYPE_NAME};

pub const TABLES: &[&str] = &["
    CREATE TABLE IF NOT EXISTS workspaces (
        workspace_id BLOB PRIMARY KEY NOT NULL,
        name TEXT NOT NULL,
        source_event_id BLOB NOT NULL
    );
"];

pub fn project(event_id: EventId, event: &WorkspaceEvent) -> Projection {
    Projection {
        row_ops: vec![RowOp::upsert(
            "workspaces",
            &["workspace_id", "name", "source_event_id"],
            vec![
                SqlValue::Blob(event.workspace_id.to_vec()),
                SqlValue::Text(event.name.clone()),
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

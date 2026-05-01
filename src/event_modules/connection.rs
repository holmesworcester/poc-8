use crate::pipeline::{ConnectionId, EventId, WorkspaceId};

use super::{LabelOp, Projection, RowOp, SqlValue};

pub const TYPE_CODE: u8 = 3;
pub const TYPE_NAME: &str = "connection";
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionEvent {
    pub workspace_id: WorkspaceId,
    pub connection_id: ConnectionId,
    pub workspace_event_id: EventId,
    pub peer_id: [u8; 32],
}

pub fn encode_connection(
    workspace_id: WorkspaceId,
    connection_id: ConnectionId,
    workspace_event_id: EventId,
    peer_id: [u8; 32],
) -> Vec<u8> {
    let mut out = vec![TYPE_CODE];
    out.extend_from_slice(&workspace_id);
    out.extend_from_slice(&connection_id);
    out.extend_from_slice(&workspace_event_id);
    out.extend_from_slice(&peer_id);
    out
}

pub fn decode(cursor: &mut super::codec::Cursor<'_>) -> Result<ConnectionEvent, super::EventError> {
    let workspace_id = cursor.id()?;
    let connection_id = cursor.id()?;
    let workspace_event_id = cursor.id()?;
    let peer_id = cursor.id()?;
    cursor.finish()?;
    Ok(ConnectionEvent {
        workspace_id,
        connection_id,
        workspace_event_id,
        peer_id,
    })
}

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

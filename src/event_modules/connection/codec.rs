use crate::event_modules::{codec, EventError};
use crate::pipeline::{ConnectionId, EventId, WorkspaceId};

pub const TYPE_CODE: u8 = 3;
pub const TYPE_NAME: &str = "connection";

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

pub fn decode(cursor: &mut codec::Cursor<'_>) -> Result<ConnectionEvent, EventError> {
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

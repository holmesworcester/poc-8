use crate::event_modules::{codec, EventError};
use crate::pipeline::{ConnectionId, EventId, WorkspaceId};

pub const TYPE_CODE: u8 = 5;
pub const TYPE_NAME: &str = "sync_have";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncHaveEvent {
    pub workspace_id: WorkspaceId,
    pub connection_id: ConnectionId,
    pub have_event_id: EventId,
}

pub fn encode(
    workspace_id: WorkspaceId,
    connection_id: ConnectionId,
    have_event_id: EventId,
) -> Vec<u8> {
    codec::encode_three_id_event(TYPE_CODE, workspace_id, connection_id, have_event_id)
}

pub fn decode(cursor: &mut codec::Cursor<'_>) -> Result<SyncHaveEvent, EventError> {
    let (workspace_id, connection_id, have_event_id) = cursor.three_ids()?;
    Ok(SyncHaveEvent {
        workspace_id,
        connection_id,
        have_event_id,
    })
}

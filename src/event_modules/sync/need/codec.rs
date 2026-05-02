use crate::event_modules::{codec, EventError};
use crate::pipeline::{ConnectionId, EventId, WorkspaceId};

pub const TYPE_CODE: u8 = 6;
pub const TYPE_NAME: &str = "sync_need";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncNeedEvent {
    pub workspace_id: WorkspaceId,
    pub connection_id: ConnectionId,
    pub needed_event_id: EventId,
}

pub fn encode(
    workspace_id: WorkspaceId,
    connection_id: ConnectionId,
    needed_event_id: EventId,
) -> Vec<u8> {
    codec::encode_three_id_event(TYPE_CODE, workspace_id, connection_id, needed_event_id)
}

pub fn decode(cursor: &mut codec::Cursor<'_>) -> Result<SyncNeedEvent, EventError> {
    let (workspace_id, connection_id, needed_event_id) = cursor.three_ids()?;
    Ok(SyncNeedEvent {
        workspace_id,
        connection_id,
        needed_event_id,
    })
}

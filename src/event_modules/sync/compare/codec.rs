use crate::event_modules::{codec, EventError};
use crate::pipeline::{ConnectionId, WorkspaceId};

pub const TYPE_CODE: u8 = 4;
pub const TYPE_NAME: &str = "sync_compare";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncCompareEvent {
    pub workspace_id: WorkspaceId,
    pub connection_id: ConnectionId,
    pub root: [u8; 32],
}

pub fn encode(workspace_id: WorkspaceId, connection_id: ConnectionId, root: [u8; 32]) -> Vec<u8> {
    codec::encode_three_id_event(TYPE_CODE, workspace_id, connection_id, root)
}

pub fn decode(cursor: &mut codec::Cursor<'_>) -> Result<SyncCompareEvent, EventError> {
    let (workspace_id, connection_id, root) = cursor.three_ids()?;
    Ok(SyncCompareEvent {
        workspace_id,
        connection_id,
        root,
    })
}

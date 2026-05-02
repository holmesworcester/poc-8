use crate::event_modules::{codec, EventError};
use crate::pipeline::WorkspaceId;

pub const TYPE_CODE: u8 = 1;
pub const TYPE_NAME: &str = "workspace";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceEvent {
    pub workspace_id: WorkspaceId,
    pub name: String,
}

pub fn encode_workspace(workspace_id: WorkspaceId, name: &str) -> Vec<u8> {
    let mut out = vec![TYPE_CODE];
    out.extend_from_slice(&workspace_id);
    codec::put_string_u16(&mut out, name);
    out
}

pub fn decode(cursor: &mut codec::Cursor<'_>) -> Result<WorkspaceEvent, EventError> {
    let workspace_id = cursor.id()?;
    let name = cursor.string_u16()?;
    cursor.finish()?;
    Ok(WorkspaceEvent { workspace_id, name })
}

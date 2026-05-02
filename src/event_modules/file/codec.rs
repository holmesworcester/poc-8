use crate::event_modules::{codec, EventError};
use crate::pipeline::{EventId, WorkspaceId};

pub const TYPE_CODE: u8 = 9;
pub const TYPE_NAME: &str = "file";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEvent {
    pub workspace_id: WorkspaceId,
    pub workspace_event_id: EventId,
    pub name: String,
    pub bytes: Vec<u8>,
}

pub fn encode_file(
    workspace_id: WorkspaceId,
    workspace_event_id: EventId,
    name: &str,
    bytes: &[u8],
) -> Vec<u8> {
    let mut out = vec![TYPE_CODE];
    out.extend_from_slice(&workspace_id);
    out.extend_from_slice(&workspace_event_id);
    codec::put_string_u16(&mut out, name);
    codec::put_bytes_u64(&mut out, bytes);
    out
}

pub fn decode(cursor: &mut codec::Cursor<'_>) -> Result<FileEvent, EventError> {
    let workspace_id = cursor.id()?;
    let workspace_event_id = cursor.id()?;
    let name = cursor.string_u16()?;
    let bytes = cursor.bytes_u64()?;
    cursor.finish()?;
    Ok(FileEvent {
        workspace_id,
        workspace_event_id,
        name,
        bytes,
    })
}

use crate::event_modules::{codec, EventError};
use crate::pipeline::{EventId, WorkspaceId};

pub const TYPE_CODE: u8 = 8;
pub const TYPE_NAME: &str = "message_deletion";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageDeletionEvent {
    pub workspace_id: WorkspaceId,
    pub message_event_id: EventId,
}

pub fn encode_message_deletion(workspace_id: WorkspaceId, message_event_id: EventId) -> Vec<u8> {
    let mut out = vec![TYPE_CODE];
    out.extend_from_slice(&workspace_id);
    out.extend_from_slice(&message_event_id);
    out
}

pub fn decode(cursor: &mut codec::Cursor<'_>) -> Result<MessageDeletionEvent, EventError> {
    let workspace_id = cursor.id()?;
    let message_event_id = cursor.id()?;
    cursor.finish()?;
    Ok(MessageDeletionEvent {
        workspace_id,
        message_event_id,
    })
}

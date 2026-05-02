use crate::event_modules::{codec, EventError};
use crate::pipeline::{EventId, WorkspaceId};

pub const TYPE_CODE: u8 = 7;
pub const TYPE_NAME: &str = "reaction";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactionEvent {
    pub workspace_id: WorkspaceId,
    pub message_event_id: EventId,
    pub emoji: String,
}

pub fn encode_reaction(
    workspace_id: WorkspaceId,
    message_event_id: EventId,
    emoji: &str,
) -> Vec<u8> {
    let mut out = vec![TYPE_CODE];
    out.extend_from_slice(&workspace_id);
    out.extend_from_slice(&message_event_id);
    codec::put_string_u16(&mut out, emoji);
    out
}

pub fn decode(cursor: &mut codec::Cursor<'_>) -> Result<ReactionEvent, EventError> {
    let workspace_id = cursor.id()?;
    let message_event_id = cursor.id()?;
    let emoji = cursor.string_u16()?;
    cursor.finish()?;
    Ok(ReactionEvent {
        workspace_id,
        message_event_id,
        emoji,
    })
}

use crate::event_modules::{codec, EventError};
use crate::pipeline::{ConnectionId, EventId, WorkspaceId};

pub const TYPE_CODE: u8 = 2;
pub const TYPE_NAME: &str = "message";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEvent {
    pub workspace_id: WorkspaceId,
    pub workspace_event_id: EventId,
    pub reply_to_event_id: EventId,
    pub fanout_connection_id: ConnectionId,
    pub body: String,
}

pub fn encode_message(
    workspace_id: WorkspaceId,
    workspace_event_id: EventId,
    reply_to_event_id: EventId,
    fanout_connection_id: ConnectionId,
    body: &str,
) -> Vec<u8> {
    let mut out = vec![TYPE_CODE];
    out.extend_from_slice(&workspace_id);
    out.extend_from_slice(&workspace_event_id);
    out.extend_from_slice(&reply_to_event_id);
    out.extend_from_slice(&fanout_connection_id);
    codec::put_string_u32(&mut out, body);
    out
}

pub fn decode(cursor: &mut codec::Cursor<'_>) -> Result<MessageEvent, EventError> {
    let workspace_id = cursor.id()?;
    let workspace_event_id = cursor.id()?;
    let reply_to_event_id = cursor.id()?;
    let fanout_connection_id = cursor.id()?;
    let body = cursor.string_u32()?;
    cursor.finish()?;
    Ok(MessageEvent {
        workspace_id,
        workspace_event_id,
        reply_to_event_id,
        fanout_connection_id,
        body,
    })
}

use crate::event_modules::{codec, EventError};
use crate::pipeline::{EventId, WorkspaceId};

pub const TYPE_INVITE: u8 = 11;
pub const TYPE_INVITE_ACCEPTED: u8 = 12;
pub const INVITE_TYPE_NAME: &str = "invite";
pub const INVITE_ACCEPTED_TYPE_NAME: &str = "invite_accepted";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteEvent {
    pub workspace_id: WorkspaceId,
    pub workspace_event_id: EventId,
    pub invite_id: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteAcceptedEvent {
    pub workspace_id: WorkspaceId,
    pub invite_event_id: EventId,
    pub account_id: [u8; 32],
    pub username: String,
    pub device_name: String,
}

pub fn encode_invite(
    workspace_id: WorkspaceId,
    workspace_event_id: EventId,
    invite_id: [u8; 32],
) -> Vec<u8> {
    let mut out = vec![TYPE_INVITE];
    out.extend_from_slice(&workspace_id);
    out.extend_from_slice(&workspace_event_id);
    out.extend_from_slice(&invite_id);
    out
}

pub fn encode_invite_accepted(
    workspace_id: WorkspaceId,
    invite_event_id: EventId,
    account_id: [u8; 32],
    username: &str,
    device_name: &str,
) -> Vec<u8> {
    let mut out = vec![TYPE_INVITE_ACCEPTED];
    out.extend_from_slice(&workspace_id);
    out.extend_from_slice(&invite_event_id);
    out.extend_from_slice(&account_id);
    codec::put_string_u16(&mut out, username);
    codec::put_string_u16(&mut out, device_name);
    out
}

pub fn decode_invite(cursor: &mut codec::Cursor<'_>) -> Result<InviteEvent, EventError> {
    let workspace_id = cursor.id()?;
    let workspace_event_id = cursor.id()?;
    let invite_id = cursor.id()?;
    cursor.finish()?;
    Ok(InviteEvent {
        workspace_id,
        workspace_event_id,
        invite_id,
    })
}

pub fn decode_invite_accepted(
    cursor: &mut codec::Cursor<'_>,
) -> Result<InviteAcceptedEvent, EventError> {
    let workspace_id = cursor.id()?;
    let invite_event_id = cursor.id()?;
    let account_id = cursor.id()?;
    let username = cursor.string_u16()?;
    let device_name = cursor.string_u16()?;
    cursor.finish()?;
    Ok(InviteAcceptedEvent {
        workspace_id,
        invite_event_id,
        account_id,
        username,
        device_name,
    })
}

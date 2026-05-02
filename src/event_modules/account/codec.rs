use crate::event_modules::{codec, EventError};
use crate::pipeline::{EventId, WorkspaceId};

pub const TYPE_CODE: u8 = 10;
pub const TYPE_NAME: &str = "account";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountEvent {
    pub workspace_id: WorkspaceId,
    pub workspace_event_id: EventId,
    pub account_id: [u8; 32],
    pub username: String,
    pub device_name: String,
}

pub fn encode_account(
    workspace_id: WorkspaceId,
    workspace_event_id: EventId,
    account_id: [u8; 32],
    username: &str,
    device_name: &str,
) -> Vec<u8> {
    let mut out = vec![TYPE_CODE];
    out.extend_from_slice(&workspace_id);
    out.extend_from_slice(&workspace_event_id);
    out.extend_from_slice(&account_id);
    codec::put_string_u16(&mut out, username);
    codec::put_string_u16(&mut out, device_name);
    out
}

pub fn decode(cursor: &mut codec::Cursor<'_>) -> Result<AccountEvent, EventError> {
    let workspace_id = cursor.id()?;
    let workspace_event_id = cursor.id()?;
    let account_id = cursor.id()?;
    let username = cursor.string_u16()?;
    let device_name = cursor.string_u16()?;
    cursor.finish()?;
    Ok(AccountEvent {
        workspace_id,
        workspace_event_id,
        account_id,
        username,
        device_name,
    })
}

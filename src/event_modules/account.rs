use crate::pipeline::{EventId, WorkspaceId};

use super::{LabelOp, Projection, RowOp, SqlValue};

pub const TYPE_CODE: u8 = 10;
pub const TYPE_NAME: &str = "account";
pub const TABLES: &[&str] = &[
    "
    CREATE TABLE IF NOT EXISTS accounts (
        account_id BLOB PRIMARY KEY NOT NULL,
        workspace_id BLOB NOT NULL,
        username TEXT NOT NULL,
        device_name TEXT NOT NULL,
        source_event_id BLOB NOT NULL
    );
    ",
    "CREATE INDEX IF NOT EXISTS idx_accounts_workspace ON accounts(workspace_id);",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountEvent {
    pub workspace_id: WorkspaceId,
    pub workspace_event_id: EventId,
    pub account_id: [u8; 32],
    pub username: String,
    pub device_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateAccountInput {
    pub workspace_id: WorkspaceId,
    pub workspace_event_id: EventId,
    pub username: String,
    pub device_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateAccountOutput {
    pub account_id: [u8; 32],
    pub event_id: EventId,
    pub username: String,
    pub device_name: String,
}

pub fn create<W: super::EventWriter>(
    writer: &mut W,
    input: CreateAccountInput,
) -> Result<CreateAccountOutput, W::Error> {
    let account_id = derive_account_id(input.workspace_id, &input.username, &input.device_name);
    let bytes = encode_account(
        input.workspace_id,
        input.workspace_event_id,
        account_id,
        &input.username,
        &input.device_name,
    );
    let written = writer.append_apply(bytes)?;
    Ok(CreateAccountOutput {
        account_id,
        event_id: written.event_id,
        username: input.username,
        device_name: input.device_name,
    })
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
    super::codec::put_string_u16(&mut out, username);
    super::codec::put_string_u16(&mut out, device_name);
    out
}

fn derive_account_id(workspace_id: WorkspaceId, username: &str, device_name: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"account:");
    hasher.update(&workspace_id);
    hasher.update(username.as_bytes());
    hasher.update(b"\0");
    hasher.update(device_name.as_bytes());
    *hasher.finalize().as_bytes()
}

pub fn decode(cursor: &mut super::codec::Cursor<'_>) -> Result<AccountEvent, super::EventError> {
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

pub fn account_row(
    account_id: [u8; 32],
    workspace_id: WorkspaceId,
    username: &str,
    device_name: &str,
    source_event_id: EventId,
) -> RowOp {
    RowOp::upsert(
        "accounts",
        &[
            "account_id",
            "workspace_id",
            "username",
            "device_name",
            "source_event_id",
        ],
        vec![
            SqlValue::Blob(account_id.to_vec()),
            SqlValue::Blob(workspace_id.to_vec()),
            SqlValue::Text(username.to_string()),
            SqlValue::Text(device_name.to_string()),
            SqlValue::Blob(source_event_id.to_vec()),
        ],
    )
}

pub fn project(event_id: EventId, event: &AccountEvent) -> Projection {
    Projection {
        row_ops: vec![account_row(
            event.account_id,
            event.workspace_id,
            &event.username,
            &event.device_name,
            event_id,
        )],
        labels: vec![LabelOp {
            subject_event_id: event_id,
            label: TYPE_NAME.to_string(),
        }],
        ..Projection::default()
    }
}

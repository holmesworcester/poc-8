use crate::pipeline::{EventId, WorkspaceId};

use super::{LabelOp, Projection, RowOp, SqlValue, WriteStatus};

pub const TYPE_INVITE: u8 = 11;
pub const TYPE_INVITE_ACCEPTED: u8 = 12;
pub const INVITE_TYPE_NAME: &str = "invite";
pub const INVITE_ACCEPTED_TYPE_NAME: &str = "invite_accepted";
pub const TABLES: &[&str] = &[
    "
    CREATE TABLE IF NOT EXISTS invites (
        event_id BLOB PRIMARY KEY NOT NULL,
        workspace_id BLOB NOT NULL,
        invite_id BLOB NOT NULL,
        source_event_id BLOB NOT NULL
    );
    ",
    "CREATE INDEX IF NOT EXISTS idx_invites_workspace ON invites(workspace_id);",
    "
    CREATE TABLE IF NOT EXISTS invite_acceptances (
        account_id BLOB PRIMARY KEY NOT NULL,
        workspace_id BLOB NOT NULL,
        invite_event_id BLOB NOT NULL,
        source_event_id BLOB NOT NULL
    );
    ",
    "CREATE INDEX IF NOT EXISTS idx_invite_acceptances_workspace ON invite_acceptances(workspace_id);",
];

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateInviteInput {
    pub workspace_id: WorkspaceId,
    pub workspace_event_id: EventId,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateInviteOutput {
    pub invite_id: [u8; 32],
    pub event_id: EventId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptInviteInput {
    pub workspace_id: WorkspaceId,
    pub invite_event_id: EventId,
    pub username: String,
    pub device_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptInviteOutput {
    pub account_id: [u8; 32],
    pub event_id: EventId,
    pub username: String,
    pub device_name: String,
    pub status: AcceptInviteStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptInviteStatus {
    Ready,
    BlockedUntilInviteSync,
}

pub fn create<W: super::EventWriter>(
    writer: &mut W,
    input: CreateInviteInput,
) -> Result<CreateInviteOutput, W::Error> {
    let invite_id = derive_invite_id(input.workspace_id, &input.nonce);
    let bytes = encode_invite(input.workspace_id, input.workspace_event_id, invite_id);
    let written = writer.append_apply(bytes)?;
    Ok(CreateInviteOutput {
        invite_id,
        event_id: written.event_id,
    })
}

pub fn accept<W: super::EventWriter>(
    writer: &mut W,
    input: AcceptInviteInput,
) -> Result<AcceptInviteOutput, W::Error> {
    let account_id =
        derive_invited_account_id(input.workspace_id, &input.username, &input.device_name);
    let bytes = encode_invite_accepted(
        input.workspace_id,
        input.invite_event_id,
        account_id,
        &input.username,
        &input.device_name,
    );
    let written = writer.append_apply(bytes)?;
    let status = match written.status {
        WriteStatus::Blocked { .. } => AcceptInviteStatus::BlockedUntilInviteSync,
        WriteStatus::Applied | WriteStatus::AlreadyApplied => AcceptInviteStatus::Ready,
    };
    Ok(AcceptInviteOutput {
        account_id,
        event_id: written.event_id,
        username: input.username,
        device_name: input.device_name,
        status,
    })
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
    super::codec::put_string_u16(&mut out, username);
    super::codec::put_string_u16(&mut out, device_name);
    out
}

fn derive_invited_account_id(
    workspace_id: WorkspaceId,
    username: &str,
    device_name: &str,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"account:");
    hasher.update(&workspace_id);
    hasher.update(username.as_bytes());
    hasher.update(b"\0");
    hasher.update(device_name.as_bytes());
    *hasher.finalize().as_bytes()
}

fn derive_invite_id(workspace_id: WorkspaceId, nonce: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"invite:");
    hasher.update(&workspace_id);
    hasher.update(nonce);
    *hasher.finalize().as_bytes()
}

pub fn decode_invite(
    cursor: &mut super::codec::Cursor<'_>,
) -> Result<InviteEvent, super::EventError> {
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
    cursor: &mut super::codec::Cursor<'_>,
) -> Result<InviteAcceptedEvent, super::EventError> {
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

pub fn project_invite(event_id: EventId, event: &InviteEvent) -> Projection {
    Projection {
        row_ops: vec![RowOp::upsert(
            "invites",
            &["event_id", "workspace_id", "invite_id", "source_event_id"],
            vec![
                SqlValue::Blob(event_id.to_vec()),
                SqlValue::Blob(event.workspace_id.to_vec()),
                SqlValue::Blob(event.invite_id.to_vec()),
                SqlValue::Blob(event_id.to_vec()),
            ],
        )],
        labels: vec![LabelOp {
            subject_event_id: event_id,
            label: INVITE_TYPE_NAME.to_string(),
        }],
        ..Projection::default()
    }
}

pub fn project_invite_accepted(event_id: EventId, event: &InviteAcceptedEvent) -> Projection {
    Projection {
        row_ops: vec![
            super::account::account_row(
                event.account_id,
                event.workspace_id,
                &event.username,
                &event.device_name,
                event_id,
            ),
            RowOp::upsert(
                "invite_acceptances",
                &[
                    "account_id",
                    "workspace_id",
                    "invite_event_id",
                    "source_event_id",
                ],
                vec![
                    SqlValue::Blob(event.account_id.to_vec()),
                    SqlValue::Blob(event.workspace_id.to_vec()),
                    SqlValue::Blob(event.invite_event_id.to_vec()),
                    SqlValue::Blob(event_id.to_vec()),
                ],
            ),
        ],
        labels: vec![LabelOp {
            subject_event_id: event_id,
            label: INVITE_ACCEPTED_TYPE_NAME.to_string(),
        }],
        ..Projection::default()
    }
}

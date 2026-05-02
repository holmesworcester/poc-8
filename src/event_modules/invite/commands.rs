use crate::event_modules::{EventWriter, WriteStatus};
use crate::pipeline::{EventId, WorkspaceId};

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

pub fn create<W: EventWriter>(
    writer: &mut W,
    input: CreateInviteInput,
) -> Result<CreateInviteOutput, W::Error> {
    let invite_id = derive_invite_id(input.workspace_id, &input.nonce);
    let bytes =
        super::codec::encode_invite(input.workspace_id, input.workspace_event_id, invite_id);
    let written = writer.append_apply(bytes)?;
    Ok(CreateInviteOutput {
        invite_id,
        event_id: written.event_id,
    })
}

pub fn accept<W: EventWriter>(
    writer: &mut W,
    input: AcceptInviteInput,
) -> Result<AcceptInviteOutput, W::Error> {
    let account_id =
        derive_invited_account_id(input.workspace_id, &input.username, &input.device_name);
    let bytes = super::codec::encode_invite_accepted(
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

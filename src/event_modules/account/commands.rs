use crate::event_modules::EventWriter;
use crate::pipeline::{EventId, WorkspaceId};

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

pub fn create<W: EventWriter>(
    writer: &mut W,
    input: CreateAccountInput,
) -> Result<CreateAccountOutput, W::Error> {
    let account_id = derive_account_id(input.workspace_id, &input.username, &input.device_name);
    let bytes = super::codec::encode_account(
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

fn derive_account_id(workspace_id: WorkspaceId, username: &str, device_name: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"account:");
    hasher.update(&workspace_id);
    hasher.update(username.as_bytes());
    hasher.update(b"\0");
    hasher.update(device_name.as_bytes());
    *hasher.finalize().as_bytes()
}

use crate::event_modules::EventWriter;
use crate::pipeline::{EventId, WorkspaceId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendFileInput {
    pub workspace_id: WorkspaceId,
    pub workspace_event_id: EventId,
    pub name: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendFileOutput {
    pub event_id: EventId,
    pub name: String,
    pub byte_len: usize,
    pub content_hash: String,
}

pub fn send<W: EventWriter>(
    writer: &mut W,
    input: SendFileInput,
) -> Result<SendFileOutput, W::Error> {
    let content_hash = blake3::hash(&input.bytes).to_hex().to_string();
    let byte_len = input.bytes.len();
    let bytes = super::codec::encode_file(
        input.workspace_id,
        input.workspace_event_id,
        &input.name,
        &input.bytes,
    );
    let written = writer.append_apply(bytes)?;
    Ok(SendFileOutput {
        event_id: written.event_id,
        name: input.name,
        byte_len,
        content_hash,
    })
}

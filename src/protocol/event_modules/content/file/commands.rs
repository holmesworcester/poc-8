//! Commands for creating file descriptors.

use crate::core::crypto::{Ed25519PrivateKey, Hash};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::CommandOutput;

use super::codec;
use super::types::FileEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateFile {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub message_id: EventId,
    pub author_user_id: EventId,
    pub signer_endpoint_shared_id: EventId,
    pub signer_private_key: Ed25519PrivateKey,
    pub file_id: EventId,
    pub blob_bytes: u64,
    pub total_slices: u32,
    pub slice_bytes: u32,
    pub root_hash: Hash,
    pub filename: String,
    pub mime_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateFileOutput {
    pub file_event_id: EventId,
    pub file_id: EventId,
    pub blob_bytes: u64,
    pub total_slices: u32,
    pub slice_bytes: u32,
    pub root_hash: Hash,
    pub filename: String,
    pub mime_type: String,
}

pub fn create(input: CreateFile) -> Result<CommandOutput<CreateFileOutput>, String> {
    let event = FileEvent {
        workspace_id: input.workspace_id,
        created_at_ms: input.created_at_ms,
        message_id: input.message_id,
        author_user_id: input.author_user_id,
        file_id: input.file_id,
        blob_bytes: input.blob_bytes,
        total_slices: input.total_slices,
        slice_bytes: input.slice_bytes,
        root_hash: input.root_hash,
        filename: input.filename,
        mime_type: input.mime_type,
    };
    let payload = codec::encode(&event)?;
    let envelope = codec::sign(
        input.signer_endpoint_shared_id,
        &input.signer_private_key,
        payload,
    );
    let bytes = codec::encode_signed(&envelope);
    let record = codec::signed_record_from_bytes(bytes)?;
    let file_event_id = crate::protocol::event_modules::types::event_id(&record.canonical_bytes);
    Ok(CommandOutput::with_events(
        CreateFileOutput {
            file_event_id,
            file_id: event.file_id,
            blob_bytes: event.blob_bytes,
            total_slices: event.total_slices,
            slice_bytes: event.slice_bytes,
            root_hash: event.root_hash,
            filename: event.filename,
            mime_type: event.mime_type,
        },
        vec![record],
    ))
}

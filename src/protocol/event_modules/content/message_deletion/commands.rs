//! Commands for deleting messages.
//!
//! A delete command emits one signed deletion event for the common pipeline.
//! It does not inspect the target message row, write tombstones, or purge event
//! bytes; those decisions require projected state and belong to the projector
//! and content purge worker.

use crate::core::crypto::Ed25519PrivateKey;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::CommandOutput;

use super::codec;
use super::types::MessageDeletionEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteMessage {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub target_message_id: EventId,
    pub author_user_id: EventId,
    pub signer_endpoint_shared_id: EventId,
    pub signer_private_key: Ed25519PrivateKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteMessageOutput {
    pub deletion_id: EventId,
    pub target_message_id: EventId,
}

pub fn delete(input: DeleteMessage) -> Result<CommandOutput<DeleteMessageOutput>, String> {
    let event = MessageDeletionEvent {
        workspace_id: input.workspace_id,
        created_at_ms: input.created_at_ms,
        target_message_id: input.target_message_id,
        author_user_id: input.author_user_id,
    };
    let payload = codec::encode(&event);
    let envelope = codec::sign(
        input.signer_endpoint_shared_id,
        &input.signer_private_key,
        payload,
    );
    let bytes = codec::encode_signed(&envelope);
    let record = codec::signed_record_from_bytes(bytes)?;
    let deletion_id = crate::protocol::event_modules::types::event_id(&record.canonical_bytes);
    Ok(CommandOutput::with_events(
        DeleteMessageOutput {
            deletion_id,
            target_message_id: event.target_message_id,
        },
        vec![record],
    ))
}

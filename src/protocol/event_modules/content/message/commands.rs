//! Commands for sending messages.
//!
//! The send command takes explicit signing material plus the message body and
//! returns one proposed signed message event. The CLI is responsible for
//! resolving local endpoint material, workspace memberships, and user identity
//! before calling this command.

use crate::core::crypto::Ed25519PrivateKey;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::CommandOutput;

use super::codec;
use super::types::MessageEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendMessage {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub author_user_id: EventId,
    pub signer_endpoint_shared_id: EventId,
    pub signer_private_key: Ed25519PrivateKey,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendMessageOutput {
    pub message_id: EventId,
    pub workspace_id: EventId,
    pub author_user_id: EventId,
    pub created_at_ms: u64,
    pub text: String,
}

pub fn send(input: SendMessage) -> Result<CommandOutput<SendMessageOutput>, String> {
    if input.text.trim().is_empty() {
        return Err("message text must not be empty".to_string());
    }
    let event = MessageEvent {
        workspace_id: input.workspace_id,
        created_at_ms: input.created_at_ms,
        author_user_id: input.author_user_id,
        text: input.text,
    };
    let payload = codec::encode(&event)?;
    let envelope = codec::sign(
        input.signer_endpoint_shared_id,
        &input.signer_private_key,
        payload,
    );
    let bytes = codec::encode_signed(&envelope);
    let record = codec::signed_record_from_bytes(bytes)?;
    let value = SendMessageOutput {
        message_id: crate::protocol::event_modules::types::event_id(&record.canonical_bytes),
        workspace_id: event.workspace_id,
        author_user_id: event.author_user_id,
        created_at_ms: event.created_at_ms,
        text: event.text,
    };
    Ok(CommandOutput::with_events(value, vec![record]))
}

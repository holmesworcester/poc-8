//! Commands for sending messages.
//!
//! The send command takes explicit signing material plus the message body and
//! returns one proposed signed message event. The CLI is responsible for
//! resolving local endpoint material, workspace memberships, user identity, and
//! the per-message history-tree leaf key before calling this command. Each
//! message is encrypted with a per-message leaf key so deletion can retire that
//! specific leaf without revoking decryption for the rest of the frontier.

use crate::core::crypto::{self, Ed25519PrivateKey, XChaCha20Poly1305Key};
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
    pub removal_frontier_id: EventId,
    pub local_history_node_secret_id: EventId,
    /// Per-message random committed in canonical bytes. The leaf
    /// `local_history_node_secret_id` is derived from this nonce; both
    /// sender and receiver derive the same leaf id by replaying the same
    /// nonce through `blake3_keyed_hash`.
    pub leaf_nonce: EventId,
    pub leaf_node_secret: XChaCha20Poly1305Key,
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
    if input.leaf_nonce.iter().all(|byte| *byte == 0) {
        return Err("message leaf_nonce must not be zero".to_string());
    }
    let plaintext = codec::encode_text_slot(&input.text)?;
    let mut event = MessageEvent {
        workspace_id: input.workspace_id,
        created_at_ms: input.created_at_ms,
        author_user_id: input.author_user_id,
        removal_frontier_id: input.removal_frontier_id,
        local_history_node_secret_id: input.local_history_node_secret_id,
        leaf_nonce: input.leaf_nonce,
        nonce: crypto::random_xchacha20poly1305_nonce(),
        ciphertext: [0; super::types::MESSAGE_CIPHERTEXT_BYTES],
    };
    let ciphertext = crypto::xchacha20poly1305_encrypt(
        &input.leaf_node_secret,
        &codec::associated_data(&event, input.signer_endpoint_shared_id),
        &event.nonce,
        &plaintext,
    )?;
    event.ciphertext = ciphertext
        .try_into()
        .map_err(|_| "message ciphertext length mismatch".to_string())?;

    let payload = codec::encode(&event);
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
        text: input.text,
    };
    Ok(CommandOutput::with_events(value, vec![record]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_proposes_signed_ciphertext_without_plaintext_bytes() {
        let output = send(SendMessage {
            workspace_id: [1; 32],
            created_at_ms: 10,
            author_user_id: [2; 32],
            signer_endpoint_shared_id: [3; 32],
            signer_private_key: [9; 32],
            removal_frontier_id: [4; 32],
            local_history_node_secret_id: [5; 32],
            leaf_nonce: [11; 32],
            leaf_node_secret: [6; 32],
            text: "private message".to_string(),
        })
        .expect("send");
        let record = output.events[0].record();

        assert!(!record
            .canonical_bytes
            .windows("private message".len())
            .any(|window| window == b"private message"));
        assert_eq!(
            record.dependencies,
            vec![[3; 32], [1; 32], [2; 32], [4; 32], [5; 32]]
        );

        let envelope = codec::decode_signed(&record.canonical_bytes).expect("signed");
        let event = codec::decode(&envelope.payload).expect("event");
        assert_eq!(event.leaf_nonce, [11; 32]);
        let plaintext = crypto::xchacha20poly1305_decrypt(
            &[6; 32],
            &codec::associated_data(&event, [3; 32]),
            &event.nonce,
            &event.ciphertext,
        )
        .expect("decrypt");
        assert_eq!(
            codec::decode_text_slot(&plaintext).expect("decode text"),
            "private message"
        );
    }
}

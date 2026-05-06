//! Message event types.
//!
//! A message is a workspace-scoped chat post written by an authenticated user.
//! The shared event carries ciphertext only. The plaintext row is a local
//! projection artifact created after the projector proves the signer and opens
//! the ciphertext with the local key-secret event named by the message.

use crate::core::crypto::{
    Ed25519PublicKey, Ed25519Signature, XChaCha20Poly1305Nonce, XCHACHA20_POLY1305_TAG_BYTES,
};
use crate::protocol::event_modules::types::EventId;

pub const MESSAGE_TEXT_BYTES: usize = 1024;
pub const MESSAGE_CIPHERTEXT_BYTES: usize = MESSAGE_TEXT_BYTES + XCHACHA20_POLY1305_TAG_BYTES;
pub type MessageCiphertext = [u8; MESSAGE_CIPHERTEXT_BYTES];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEvent {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub author_user_id: EventId,
    pub removal_frontier_id: EventId,
    pub local_key_secret_id: EventId,
    pub nonce: XChaCha20Poly1305Nonce,
    pub ciphertext: MessageCiphertext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessagePlaintext {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub author_user_id: EventId,
    pub removal_frontier_id: EventId,
    pub local_key_secret_id: EventId,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedMessageEnvelope {
    pub signer_endpoint_shared_id: EventId,
    pub signer_public_key: Ed25519PublicKey,
    pub payload: Vec<u8>,
    pub signature: Ed25519Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRow {
    pub workspace_id: EventId,
    pub message_id: EventId,
    pub created_at_ms: u64,
    pub author_user_id: EventId,
    pub signer_endpoint_shared_id: EventId,
    pub text: String,
}

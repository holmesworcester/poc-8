//! Message event types.
//!
//! A message is a workspace-scoped chat post written by an authenticated user.
//! The shared event carries ciphertext only. The plaintext row is a local
//! projection artifact created after the projector proves the signer and opens
//! the ciphertext with the local history node leaf event named by the message.
//!
//! Each message is encrypted with a per-message leaf key derived through the
//! HKDF history-node range tree. The leaf range is deterministic from the
//! message's `created_at_ms`: `range_start = 2 * created_at_ms`, `range_width = 1`.
//! Both sender and receiver compute the same leaf id from `local_key_secret`
//! root through one intermediate path-node at width=2. On message deletion the
//! intermediate path-node is retired through a sibling-tombstone leaf, making
//! the leaf un-rederivable from any retained workspace material.

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
    pub local_history_node_secret_id: EventId,
    pub nonce: XChaCha20Poly1305Nonce,
    pub ciphertext: MessageCiphertext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessagePlaintext {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub author_user_id: EventId,
    pub removal_frontier_id: EventId,
    pub local_history_node_secret_id: EventId,
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

/// The deterministic range of the per-message history leaf node.
///
/// Multiplying by two reserves one sibling slot at `2*ts + 1` for the
/// tombstone leaf emitted on deletion; this guarantees each message has a
/// dedicated width-2 intermediate path node above its leaf so retiring that
/// intermediate cannot leak into a neighbour message's path.
pub fn leaf_range_start(created_at_ms: u64) -> u64 {
    created_at_ms.saturating_mul(2)
}

pub const LEAF_RANGE_WIDTH: u64 = 1;
pub const LEAF_PARENT_WIDTH: u64 = 2;

/// The deterministic range of the intermediate path node that sits between the
/// leaf and the `local_key_secret` root.
pub fn intermediate_parent_range_start(created_at_ms: u64) -> u64 {
    leaf_range_start(created_at_ms)
}

/// The deterministic range_start of the sibling-tombstone leaf used to retire
/// the intermediate parent on deletion.
pub fn tombstone_sibling_range_start(created_at_ms: u64) -> u64 {
    leaf_range_start(created_at_ms).saturating_add(1)
}

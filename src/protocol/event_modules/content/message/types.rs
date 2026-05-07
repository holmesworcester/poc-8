//! Message event types.
//!
//! A message is a workspace-scoped chat post written by an authenticated user.
//! The shared event carries ciphertext only. The plaintext row is a local
//! projection artifact created after the projector proves the signer and opens
//! the ciphertext with the local history node leaf event named by the message.
//!
//! Each message is encrypted with a per-message leaf key derived from a
//! per-minute coarse-cover node. The leaf coordinate is
//! `(workspace_id, removal_frontier_id, unix_minute, leaf_nonce)`:
//!
//!   * `unix_minute` = `created_at_ms / 60_000`. All messages authored in the
//!     same minute share one minute_node above their leaves so a future
//!     disappearing-message slice can puncture the minute_node and retire the
//!     whole minute at once.
//!   * `leaf_nonce` is a fresh 32-byte random committed in the canonical
//!     bytes at authoring time. Two peers authoring at the same `created_at_ms`
//!     carry independently random `leaf_nonce` values, so their leaves cannot
//!     collide on the same `(unix_minute, leaf_nonce)` slot.
//!
//! On manual delete, the leaf event canonical bytes are purged. The minute_node
//! survives so other messages in the same minute keep decrypting.

use crate::core::crypto::{
    Ed25519PublicKey, Ed25519Signature, XChaCha20Poly1305Nonce, XCHACHA20_POLY1305_TAG_BYTES,
};
use crate::protocol::event_modules::types::EventId;

pub const MESSAGE_TEXT_BYTES: usize = 1024;
pub const MESSAGE_CIPHERTEXT_BYTES: usize = MESSAGE_TEXT_BYTES + XCHACHA20_POLY1305_TAG_BYTES;
pub type MessageCiphertext = [u8; MESSAGE_CIPHERTEXT_BYTES];

/// Number of milliseconds in a minute. The unit of the per-minute history
/// cover is one minute, matching the disappearing-messages plan.
pub const UNIX_MINUTE_MS: u64 = 60_000;

/// Width of the per-message leaf range. Always 1.
pub const LEAF_RANGE_WIDTH: u64 = 1;

/// Compute the `unix_minute` slot for a `created_at_ms` value.
pub fn unix_minute_for(created_at_ms: u64) -> u64 {
    created_at_ms / UNIX_MINUTE_MS
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEvent {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub author_user_id: EventId,
    pub removal_frontier_id: EventId,
    pub local_history_node_secret_id: EventId,
    /// Per-message random committed in canonical bytes. Together with
    /// `unix_minute_for(created_at_ms)` it pins the leaf coordinate that
    /// derives this message's AEAD key.
    pub leaf_nonce: EventId,
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
    pub leaf_nonce: EventId,
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

//! Message event types.
//!
//! A message is a workspace-scoped chat post written by an authenticated user.
//! The shared event carries ciphertext only. The plaintext row is a local
//! projection artifact created after the projector proves the signer and opens
//! the ciphertext with the local history node leaf event named by the message.
//!
//! Each message is encrypted with a per-message leaf key derived from a
//! per-minute coarse-cover node. The leaf coordinate is
//! `(workspace_id, removal_frontier_id, unix_minute, event_id_in_minute)`,
//! where `event_id_in_minute` is **deterministic** from the message's
//! identifying canonical fields:
//!
//!   * `unix_minute` = `created_at_ms / 60_000`. All messages authored in the
//!     same minute share one minute_node above their leaves so a future
//!     disappearing-message slice can puncture the minute_node and retire the
//!     whole minute at once.
//!   * `event_id_in_minute` = `BLAKE3-keyed-hash` over a domain tag plus
//!     `(workspace_id, author_user_id, removal_frontier_id, created_at_ms)`.
//!     Two clients independently authoring the same logical message at the
//!     same `created_at_ms` collapse to one leaf coordinate; replay is
//!     idempotent.
//!
//! On manual delete, the leaf event canonical bytes are purged. The minute_node
//! survives so other messages in the same minute keep decrypting.

use crate::core::crypto::{
    self, Ed25519PublicKey, Ed25519Signature, XChaCha20Poly1305Nonce, XCHACHA20_POLY1305_TAG_BYTES,
};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::Writer;

pub const MESSAGE_TEXT_BYTES: usize = 1024;
pub const MESSAGE_CIPHERTEXT_BYTES: usize = MESSAGE_TEXT_BYTES + XCHACHA20_POLY1305_TAG_BYTES;
pub type MessageCiphertext = [u8; MESSAGE_CIPHERTEXT_BYTES];

/// Number of milliseconds in a minute. The unit of the per-minute history
/// cover is one minute, matching the disappearing-messages plan.
pub const UNIX_MINUTE_MS: u64 = 60_000;

/// Width of the per-message leaf range. Always 1.
pub const LEAF_RANGE_WIDTH: u64 = 1;

/// Domain-separation tag for the message leaf-coord derivation. Bumping this
/// tag forces re-derivation: changing the tag changes the BLAKE3 keyed-hash
/// output for the same logical message.
pub const MESSAGE_LEAF_COORD_DOMAIN: &[u8] = b"topo message leaf coord v1";

/// Compute the `unix_minute` slot for a `created_at_ms` value.
pub fn unix_minute_for(created_at_ms: u64) -> u64 {
    created_at_ms / UNIX_MINUTE_MS
}

/// Deterministic leaf coordinate (`event_id_in_minute`) for a message.
///
/// Both sender and receiver re-derive this 32-byte coordinate from the
/// message's canonical identifying fields (workspace, author, frontier,
/// timestamp) before decryption, so two peers authoring the same logical
/// message at the same `created_at_ms` land on the same leaf and the
/// admission path collapses the duplicate. Plaintext is intentionally not in
/// the hash — peers must be able to recompute the leaf coord from canonical
/// bytes alone, before AEAD opening.
pub fn message_event_id_in_minute(
    workspace_id: &EventId,
    author_user_id: &EventId,
    removal_frontier_id: &EventId,
    created_at_ms: u64,
) -> EventId {
    let mut info = Writer::with_capacity(32 + 32 + 32 + 8);
    info.id(workspace_id);
    info.id(author_user_id);
    info.id(removal_frontier_id);
    info.u64(created_at_ms);
    let info_bytes = info.finish();
    crypto::blake3_keyed_hash(workspace_id, MESSAGE_LEAF_COORD_DOMAIN, &info_bytes)
}

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

impl MessageEvent {
    /// Re-derive the leaf coordinate from this message's canonical fields.
    pub fn event_id_in_minute_derived(&self) -> EventId {
        message_event_id_in_minute(
            &self.workspace_id,
            &self.author_user_id,
            &self.removal_frontier_id,
            self.created_at_ms,
        )
    }
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

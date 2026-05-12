//! Reaction event types.
//!
//! A reaction is a workspace-scoped emoji attached to a target message. The
//! emoji is fixed-width zero-padded UTF-8 before encryption. Shared canonical
//! bytes carry only ciphertext; the visible emoji row is local projection state.
//!
//! Per-message FS treats the reaction emoji like the message text: each
//! reaction has its own leaf coordinate. The coord is **deterministic** from
//! the reaction's identifying canonical fields, so two peers that
//! independently author "alice :+1: msg42 at t" land on the same leaf and the
//! admission path collapses the duplicate.

use crate::core::crypto::{
    self, Ed25519PublicKey, Ed25519Signature, XChaCha20Poly1305Nonce, XCHACHA20_POLY1305_TAG_BYTES,
};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::Writer;

pub const REACTION_EMOJI_BYTES: usize = 64;
pub const REACTION_CIPHERTEXT_BYTES: usize = REACTION_EMOJI_BYTES + XCHACHA20_POLY1305_TAG_BYTES;
pub type ReactionCiphertext = [u8; REACTION_CIPHERTEXT_BYTES];

/// Domain-separation tag for the reaction leaf-coord derivation.
pub const REACTION_LEAF_COORD_DOMAIN: &[u8] = b"topo reaction leaf coord v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactionEvent {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub target_message_id: EventId,
    pub author_user_id: EventId,
    pub removal_frontier_id: EventId,
    pub local_history_node_secret_id: EventId,
    pub nonce: XChaCha20Poly1305Nonce,
    pub ciphertext: ReactionCiphertext,
}

impl ReactionEvent {
    /// Re-derive the reaction's leaf coordinate from canonical fields.
    ///
    /// Note: emoji plaintext is intentionally not in the hash so peers can
    /// recompute the leaf coord before AEAD decryption. Two reactions from
    /// the same author against the same target message at the same
    /// `created_at_ms` therefore collapse — that is the idempotency
    /// property we want.
    pub fn event_id_in_minute_derived(&self) -> EventId {
        reaction_event_id_in_minute(
            &self.workspace_id,
            &self.author_user_id,
            &self.target_message_id,
            &self.removal_frontier_id,
            self.created_at_ms,
        )
    }
}

/// Deterministic leaf coordinate for a reaction.
///
/// Same author + same target + same frontier + same `created_at_ms` =>
/// same leaf, regardless of which peer authored.
pub fn reaction_event_id_in_minute(
    workspace_id: &EventId,
    author_user_id: &EventId,
    target_message_id: &EventId,
    removal_frontier_id: &EventId,
    created_at_ms: u64,
) -> EventId {
    let mut info = Writer::with_capacity(32 + 32 + 32 + 32 + 8);
    info.id(workspace_id);
    info.id(author_user_id);
    info.id(target_message_id);
    info.id(removal_frontier_id);
    info.u64(created_at_ms);
    let info_bytes = info.finish();
    crypto::blake3_keyed_hash(workspace_id, REACTION_LEAF_COORD_DOMAIN, &info_bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactionPlaintext {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub target_message_id: EventId,
    pub author_user_id: EventId,
    pub removal_frontier_id: EventId,
    pub local_history_node_secret_id: EventId,
    pub emoji: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedReactionEnvelope {
    pub signer_endpoint_shared_id: EventId,
    pub signer_public_key: Ed25519PublicKey,
    pub payload: Vec<u8>,
    pub signature: Ed25519Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactionRow {
    pub workspace_id: EventId,
    pub reaction_id: EventId,
    pub target_message_id: EventId,
    pub author_user_id: EventId,
    pub signer_endpoint_shared_id: EventId,
    pub created_at_ms: u64,
    pub emoji: String,
}

//! Reaction event types.
//!
//! A reaction is a workspace-scoped emoji attached to a target message. The
//! emoji is fixed-width zero-padded UTF-8 before encryption. Shared canonical
//! bytes carry only ciphertext; the visible emoji row is local projection state.

use crate::core::crypto::{
    Ed25519PublicKey, Ed25519Signature, XChaCha20Poly1305Nonce, XCHACHA20_POLY1305_TAG_BYTES,
};
use crate::protocol::event_modules::types::EventId;

pub const REACTION_EMOJI_BYTES: usize = 64;
pub const REACTION_CIPHERTEXT_BYTES: usize = REACTION_EMOJI_BYTES + XCHACHA20_POLY1305_TAG_BYTES;
pub type ReactionCiphertext = [u8; REACTION_CIPHERTEXT_BYTES];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactionEvent {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub target_message_id: EventId,
    pub author_user_id: EventId,
    pub removal_frontier_id: EventId,
    pub local_key_secret_id: EventId,
    pub nonce: XChaCha20Poly1305Nonce,
    pub ciphertext: ReactionCiphertext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactionPlaintext {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub target_message_id: EventId,
    pub author_user_id: EventId,
    pub removal_frontier_id: EventId,
    pub local_key_secret_id: EventId,
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

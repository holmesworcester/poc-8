//! Reaction event types.
//!
//! A reaction is a workspace-scoped emoji attached to a target message. The
//! emoji is fixed-width zero-padded UTF-8 so canonical bytes stay deterministic
//! per event type. Removing a reaction is not a separate event in the port; the
//! poc-7 grouping by `(author_user_id, emoji)` survives at read time.

use crate::core::crypto::{Ed25519PublicKey, Ed25519Signature};
use crate::protocol::event_modules::types::EventId;

pub const REACTION_EMOJI_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactionEvent {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub target_message_id: EventId,
    pub author_user_id: EventId,
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

//! Recipient key tombstone event types.
//!
//! A tombstone is a shared workspace fact for one endpoint membership. It
//! retires a previous recipient public key and names the replacement key event.

use crate::core::crypto::{Ed25519PublicKey, Ed25519Signature};
use crate::protocol::event_modules::types::EventId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientKeyTombstoneEvent {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub endpoint_shared_id: EventId,
    pub old_recipient_key_id: EventId,
    pub new_recipient_key_id: EventId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRecipientKeyTombstoneEnvelope {
    pub signer_endpoint_shared_id: EventId,
    pub signer_public_key: Ed25519PublicKey,
    pub payload: Vec<u8>,
    pub signature: Ed25519Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientKeyTombstoneRow {
    pub workspace_id: EventId,
    pub old_recipient_key_id: EventId,
    pub tombstone_id: EventId,
    pub created_at_ms: u64,
    pub endpoint_shared_id: EventId,
    pub new_recipient_key_id: EventId,
}

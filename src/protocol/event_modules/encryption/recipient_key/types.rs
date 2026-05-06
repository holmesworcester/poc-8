//! Recipient key event types.
//!
//! A recipient key is a shared workspace fact that publishes the public X25519
//! key for one endpoint membership. The matching private material remains in a
//! local recipient key event.

use crate::core::crypto::{Ed25519PublicKey, Ed25519Signature, X25519PublicKey};
use crate::protocol::event_modules::types::EventId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientKeyEvent {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub endpoint_shared_id: EventId,
    pub recipient_key: X25519PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRecipientKeyEnvelope {
    pub signer_endpoint_shared_id: EventId,
    pub signer_public_key: Ed25519PublicKey,
    pub payload: Vec<u8>,
    pub signature: Ed25519Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientKeyRow {
    pub workspace_id: EventId,
    pub recipient_key_id: EventId,
    pub created_at_ms: u64,
    pub endpoint_shared_id: EventId,
    pub recipient_key: X25519PublicKey,
}

//! Message event types.
//!
//! A message is a workspace-scoped chat post written by an authenticated user.
//! The semantic field is fixed-width text so canonical bytes stay deterministic
//! per event type. Encrypted payload, ratchets, and group keys are deliberately
//! out of scope; authenticity comes from a signed envelope whose signer is a
//! workspace endpoint membership.

use crate::core::crypto::{Ed25519PublicKey, Ed25519Signature};
use crate::protocol::event_modules::types::EventId;

pub const MESSAGE_TEXT_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEvent {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub author_user_id: EventId,
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

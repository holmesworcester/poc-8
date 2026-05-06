//! Local recipient key event types.
//!
//! The local recipient key is node-local private material paired with a public
//! X25519 recipient key. A future shared `recipient_key` event can publish the
//! public half; this local event keeps the private half out of sync history.

use crate::core::crypto::{X25519PrivateKey, X25519PublicKey};
use crate::protocol::event_modules::types::EventId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRecipientKey {
    pub workspace_id: EventId,
    pub recipient_key: X25519PublicKey,
    pub recipient_secret: X25519PrivateKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRecipientKeyRow {
    pub workspace_id: EventId,
    pub local_recipient_key_id: EventId,
    pub recipient_key: X25519PublicKey,
    pub recipient_secret: X25519PrivateKey,
}

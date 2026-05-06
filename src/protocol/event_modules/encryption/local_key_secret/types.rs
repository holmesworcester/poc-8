//! Local key-secret event types.
//!
//! The event id of this local-only event is the key-secret commitment named by
//! key wraps and later content events. One local secret is valid for exactly one
//! `removal_frontier_id`.

use crate::core::crypto::XChaCha20Poly1305Key;
use crate::protocol::event_modules::types::EventId;

pub type KeySecret = XChaCha20Poly1305Key;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalKeySecret {
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    pub key_secret: KeySecret,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalKeySecretRow {
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    pub local_key_secret_id: EventId,
    pub key_secret: KeySecret,
}

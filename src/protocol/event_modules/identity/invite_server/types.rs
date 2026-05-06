//! Invite-server event types.
//!
//! An invite-server event publishes an invite public key for one workspace and
//! records the authority event that endorsed it. The private invite secret is
//! intentionally absent from these types; it travels only through local/out-of-
//! band invite flows.

use crate::core::crypto::Ed25519PublicKey;
use crate::protocol::event_modules::types::EventId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteServerEvent {
    pub created_at_ms: u64,
    pub public_key: Ed25519PublicKey,
    pub workspace_id: EventId,
    pub authority_event_id: EventId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteServerRow {
    pub workspace_id: EventId,
    pub invite_server_id: EventId,
    pub created_at_ms: u64,
    pub public_key: Ed25519PublicKey,
    pub authority_event_id: EventId,
}

//! Removal frontier event types.
//!
//! A removal frontier is the workspace-scoped authorization point for one
//! content key. The frontier id is the event id; key secrets and key wraps name
//! `removal_frontier_id` directly instead of inventing a separate key-period
//! term.
//!
//! `removal_event_ids` is a frontier set, not a full history list. When removal
//! facts land, these ids should be the compact set whose dependency closure
//! represents all removals incorporated by this frontier. Phase one keeps the
//! field empty and rejects non-empty frontiers at projection time.

use crate::core::crypto::{Ed25519PublicKey, Ed25519Signature};
use crate::protocol::event_modules::types::EventId;

pub const MAX_REMOVAL_FRONTIER_REFS: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalFrontierEvent {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub authority_admin_id: EventId,
    pub removal_event_ids: Vec<EventId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRemovalFrontierEnvelope {
    pub signer_endpoint_shared_id: EventId,
    pub signer_public_key: Ed25519PublicKey,
    pub payload: Vec<u8>,
    pub signature: Ed25519Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalFrontierRow {
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    pub created_at_ms: u64,
    pub authority_admin_id: EventId,
    pub removal_event_ids: Vec<EventId>,
}

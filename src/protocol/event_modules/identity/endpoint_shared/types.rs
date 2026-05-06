//! Endpoint-shared event types.
//!
//! The endpoint-shared payload is the inner event signed by a device invite.
//! The signed envelope event id is the durable endpoint-shared id projected into
//! membership rows.

use crate::core::crypto::Ed25519PublicKey;
use crate::protocol::event_modules::identity::endpoint::types::{EndpointId, EndpointRole};
use crate::protocol::event_modules::types::EventId;

pub const ENDPOINT_DEVICE_NAME_BYTES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointSharedEvent {
    pub created_at_ms: u64,
    pub workspace_id: EventId,
    pub user_authority_event_id: EventId,
    pub endpoint_id: EndpointId,
    pub signing_public_key: Ed25519PublicKey,
    pub endpoint_role: EndpointRole,
    pub device_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointSharedRow {
    pub workspace_id: EventId,
    pub endpoint_shared_id: EventId,
    pub created_at_ms: u64,
    pub endpoint_id: EndpointId,
    pub signing_public_key: Ed25519PublicKey,
    pub endpoint_role: EndpointRole,
    pub user_authority_event_id: EventId,
    pub device_invite_id: EventId,
    pub device_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointMembershipRow {
    pub endpoint_id: EndpointId,
    pub workspace_id: EventId,
    pub endpoint_shared_id: EventId,
    pub user_authority_event_id: EventId,
    pub device_invite_id: EventId,
    pub signing_public_key: Ed25519PublicKey,
    pub endpoint_role: EndpointRole,
    pub created_at_ms: u64,
}

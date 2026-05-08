//! Transit envelope data types.
//!
//! These values describe encrypted transport envelopes, not stored events.
//! Endpoint bootstrap envelopes carry only connection requests. Invite
//! bootstrap envelopes carry shared identity-bootstrap batches authorized by an
//! invite-derived secret for one workspace. Connection envelopes add the
//! established connection id so the worker can route the recovered inner bytes
//! without consulting the payload.

use crate::protocol::event_modules::connection::types::ConnectionId;
use crate::protocol::event_modules::identity::endpoint::types::EndpointId;
use crate::protocol::event_modules::types::EventId;

pub type TransitNonce = [u8; 24];

pub(super) const BOOTSTRAP_PURPOSE: &[u8] = b"topo-bootstrap-transit-v1";
pub(super) const INVITE_BOOTSTRAP_PURPOSE: &[u8] = b"topo-invite-bootstrap-transit-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitEnvelope {
    Bootstrap {
        sender_endpoint: EndpointId,
        recipient_endpoint: EndpointId,
        nonce: TransitNonce,
        ciphertext: Vec<u8>,
    },
    InviteBootstrap {
        sender_endpoint: EndpointId,
        recipient_endpoint: EndpointId,
        bootstrap_hash: EventId,
        workspace_id: EventId,
        invite_event_id: EventId,
        nonce: TransitNonce,
        ciphertext: Vec<u8>,
    },
    Connection {
        connection_id: ConnectionId,
        sender_endpoint: EndpointId,
        recipient_endpoint: EndpointId,
        nonce: TransitNonce,
        ciphertext: Vec<u8>,
    },
}

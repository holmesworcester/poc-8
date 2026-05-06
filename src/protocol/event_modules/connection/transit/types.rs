//! Transit envelope data types.
//!
//! These values describe encrypted transport envelopes, not stored events.
//! Bootstrap envelopes are endpoint-addressed. Connection envelopes add the
//! established connection id so the worker can route the recovered inner bytes
//! without consulting the payload.

use crate::protocol::event_modules::connection::types::ConnectionId;
use crate::protocol::event_modules::identity::endpoint::types::EndpointId;

pub type TransitNonce = [u8; 24];

pub(super) const BOOTSTRAP_PURPOSE: &[u8] = b"topo-bootstrap-transit-v1";
pub(super) const CONNECTION_PURPOSE: &[u8] = b"topo-connection-transit-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitEnvelope {
    Bootstrap {
        sender_endpoint: EndpointId,
        recipient_endpoint: EndpointId,
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

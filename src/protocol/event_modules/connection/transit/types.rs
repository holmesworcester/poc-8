//! Transit envelope data types.
//!
//! These values describe encrypted transport envelopes, not stored events.
//! Endpoint bootstrap envelopes carry only connection requests. Handshake
//! response envelopes carry the connection response back to the requester.
//! Connection envelopes add the established connection id so the worker can
//! route the recovered inner bytes without consulting the payload.

use crate::protocol::event_modules::connection::types::ConnectionId;
use crate::protocol::event_modules::identity::endpoint::types::EndpointId;
use crate::protocol::event_modules::types::EventId;

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
    ConnectionHandshakeResponse {
        request_id: EventId,
        sender_endpoint: EndpointId,
        recipient_endpoint: EndpointId,
        responder_ephemeral_public_key: EndpointId,
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

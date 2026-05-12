//! Connection request event fields.
//!
//! The request names both endpoints, carries a nonce to keep ids unique, and
//! shares a transcript-bound signature from the invite private key that
//! authorizes bootstrap. It also names the initiator's local ephemeral secret
//! event and carries the matching public key. On the authoring endpoint that
//! secret is a normal dependency; on the receiving endpoint the bootstrap
//! receive proof stands in for the private dependency the receiver cannot have.
//!
//! `from_listen_addr` is the requester's advertised steady-state listener
//! address, when known. The accepting peer uses it as a transport target so the
//! daemons can reach each other after the bootstrap stream closes. The field is
//! optional because not every requester runs a listener; bootstrap still works
//! when only one side advertises.

use std::net::SocketAddr;

use crate::core::crypto::Ed25519Signature;
use crate::protocol::event_modules::identity::endpoint::types::EndpointId;
use crate::protocol::event_modules::types::EventId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestEvent {
    pub from_endpoint: EndpointId,
    pub to_endpoint: EndpointId,
    pub nonce: [u8; 32],
    pub invite_event_id: EventId,
    pub bootstrap_hash: [u8; 32],
    pub invite_signature: Ed25519Signature,
    pub invite_secret_event_id: EventId,
    pub initiator_ephemeral_secret_event_id: EventId,
    pub initiator_ephemeral_public_key: EndpointId,
    pub from_listen_addr: Option<SocketAddr>,
}

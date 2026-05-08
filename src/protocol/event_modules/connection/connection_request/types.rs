//! Connection request event fields.
//!
//! The request names both endpoints, carries a nonce to keep ids unique, and
//! declares the local invite-secret event that authorizes bootstrap. The secret
//! event is a normal local dependency: transit does not reconstruct it from
//! projected rows.
//!
//! `from_listen_addr` is retained as optional request metadata, but invite
//! bootstrap does not treat it as route authority. Route rows are local state:
//! the requester records the invite address it dialed, and receive paths only
//! record routes from explicit receive metadata.

use std::net::SocketAddr;

use crate::protocol::event_modules::identity::endpoint::types::EndpointId;
use crate::protocol::event_modules::types::EventId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestEvent {
    pub from_endpoint: EndpointId,
    pub to_endpoint: EndpointId,
    pub nonce: [u8; 32],
    pub bootstrap_hash: [u8; 32],
    pub invite_secret_event_id: EventId,
    pub from_listen_addr: Option<SocketAddr>,
}

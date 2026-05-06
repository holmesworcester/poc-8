//! Shared connection-domain types.
//!
//! The connection id is derived from the request id and accepting endpoint so
//! both sides can agree on it without another round trip.

use std::net::SocketAddr;

use crate::protocol::event_modules::identity::endpoint::types::EndpointId;
use crate::protocol::event_modules::types::EventId;

pub type ConnectionId = [u8; 32];

pub(super) const EVENT_MAGIC: &[u8; 10] = b"TOPOCONN1\0";

pub(crate) fn connection_id(request_id: &EventId, from_endpoint: &EndpointId) -> ConnectionId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"topo-connection-v1");
    hasher.update(request_id);
    hasher.update(from_endpoint);
    *hasher.finalize().as_bytes()
}

pub(crate) fn event_id(bytes: &[u8]) -> EventId {
    *blake3::hash(bytes).as_bytes()
}

pub(crate) fn connection_id_from_bytes(bytes: &[u8]) -> Result<ConnectionId, String> {
    bytes
        .try_into()
        .map_err(|_| "connection id must be 32 bytes".to_string())
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteExchangeReport {
    pub routes_synced: usize,
    pub failed_routes: usize,
    pub sent_events: usize,
    pub received_events: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectReport {
    pub addr: SocketAddr,
    pub sent_events: usize,
    pub received_events: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeReport {
    pub local_addr: SocketAddr,
    pub accepted_connections: usize,
    pub sent_events: usize,
    pub received_events: usize,
}

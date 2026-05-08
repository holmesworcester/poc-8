//! Shared connection-domain types.
//!
//! The connection id is the event id of the local-only connection response
//! event. That event carries the traffic secret used by transit frames.

use std::net::SocketAddr;

use crate::protocol::event_modules::types::EventId;

pub type ConnectionId = [u8; 32];

pub(super) const EVENT_MAGIC: &[u8; 10] = b"TOPOCONN1\0";

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

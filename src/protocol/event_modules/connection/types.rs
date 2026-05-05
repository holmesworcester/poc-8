//! Shared connection-domain types.
//!
//! The connection id is derived from the request id and accepting endpoint so
//! both sides can agree on it without another round trip.

use std::net::SocketAddr;
use std::time::Duration;

use crate::protocol::event_modules::identity::endpoint::types::EndpointId;
use crate::protocol::event_modules::types::EventId;

pub type ConnectionId = [u8; 32];

pub(super) const EVENT_MAGIC: &[u8; 10] = b"TOPOCONN1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InboundConnection {
    pub outgoing: Vec<Vec<u8>>,
    pub connection_id: Option<ConnectionId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OutboxKey {
    pub(crate) connection_id: ConnectionId,
    pub(crate) event_id: EventId,
}

impl OutboxKey {
    pub(crate) fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&self.connection_id);
        bytes.extend_from_slice(&self.event_id);
        bytes
    }
}

pub(super) fn connection_id(request_id: &EventId, from_endpoint: &EndpointId) -> ConnectionId {
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

pub(crate) fn is_connection_event(bytes: &[u8]) -> bool {
    bytes.starts_with(EVENT_MAGIC)
}

/// Options for the long-lived connection daemon loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DaemonOptions {
    pub listen: SocketAddr,
    pub duration: Option<Duration>,
    pub idle: Duration,
    pub ready_batch: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectReport {
    pub addr: SocketAddr,
    pub established_routes: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServeReport {
    pub local_addr: Option<SocketAddr>,
    pub accepted_connections: usize,
    pub received_events: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteExchangeReport {
    pub routes_synced: usize,
    pub failed_routes: usize,
    pub sent_events: usize,
    pub received_events: usize,
}

impl RouteExchangeReport {
    pub(crate) fn merge(&mut self, other: Self) {
        self.routes_synced += other.routes_synced;
        self.failed_routes += other.failed_routes;
        self.sent_events += other.sent_events;
        self.received_events += other.received_events;
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DaemonReport {
    pub local_addr: Option<SocketAddr>,
    pub accepted_connections: usize,
    pub sync_rounds: usize,
    pub routes_synced: usize,
    pub failed_routes: usize,
    pub sent_events: usize,
    pub received_events: usize,
    pub ready_events: usize,
    pub unblocked_events: usize,
}

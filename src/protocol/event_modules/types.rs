//! Protocol-wide event metadata.
//!
//! Concrete event bodies live in leaf module `types.rs` files. This file holds
//! only the common envelope facts the admission worker needs for every decoded
//! event: deterministic id, timestamp, body length, dependencies, scope, and
//! durable status. Scope and receive metadata are projection context, not part
//! of the canonical bytes; keeping that distinction sharp is what lets
//! projectors stay pure and modules stay independently understandable.

use std::net::SocketAddr;

pub type EventId = [u8; 32];

/// Decoded canonical event plus the metadata needed by the common worker.
///
/// `canonical_bytes` is stored because event ids, network transfer, and replay
/// all operate on the exact encoded bytes. Semantic fields should not be added
/// here unless every event type truly shares them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRecord {
    pub timestamp: u64,
    pub body_len: usize,
    pub canonical_bytes: Vec<u8>,
    pub dependencies: Vec<EventId>,
    pub workspace_id: Option<EventId>,
    pub scope: EventScope,
}

impl EventRecord {
    pub(crate) fn from_stored_parts(
        timestamp: u64,
        body_len: usize,
        canonical_bytes: Vec<u8>,
        dependencies: Vec<EventId>,
        workspace_id: Option<EventId>,
        scope: EventScope,
    ) -> Self {
        Self {
            timestamp,
            body_len,
            canonical_bytes,
            dependencies,
            workspace_id,
            scope,
        }
    }
}

/// Subjective metadata attached by a receive boundary.
///
/// This is not part of the globally canonical event id. It is local projection
/// context for events whose meaning is inherently subjective to this endpoint,
/// such as "we received this connection handshake from this socket address."
/// Durable events currently cannot persist this field, so the common worker
/// only allows it on events that can be projected immediately. If such an event
/// would block, admission fails instead of silently dropping context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiveMetadata {
    origin: SocketAddr,
    local_endpoint: EventId,
    remote_endpoint: EventId,
    remember_route: bool,
    authorization: ReceiveAuthorization,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveAuthorization {
    BootstrapInvite { invite_secret_event_id: EventId },
    EndpointReceive,
}

impl ReceiveMetadata {
    pub(crate) fn bootstrap_invite(
        origin: SocketAddr,
        local_endpoint: EventId,
        remote_endpoint: EventId,
        remember_route: bool,
        invite_secret_event_id: EventId,
    ) -> Self {
        Self {
            origin,
            local_endpoint,
            remote_endpoint,
            remember_route,
            authorization: ReceiveAuthorization::BootstrapInvite {
                invite_secret_event_id,
            },
        }
    }

    pub(crate) fn endpoint_receive(
        origin: SocketAddr,
        local_endpoint: EventId,
        remote_endpoint: EventId,
        remember_route: bool,
    ) -> Self {
        Self {
            origin,
            local_endpoint,
            remote_endpoint,
            remember_route,
            authorization: ReceiveAuthorization::EndpointReceive,
        }
    }

    pub fn origin(self) -> SocketAddr {
        self.origin
    }

    pub fn local_endpoint(self) -> EventId {
        self.local_endpoint
    }

    pub fn remote_endpoint(self) -> EventId {
        self.remote_endpoint
    }

    pub fn remember_route(self) -> bool {
        self.remember_route
    }

    pub fn authorization(self) -> ReceiveAuthorization {
        self.authorization
    }
}

/// Storage and sharing policy for an event.
///
/// `Shared` participates in sync. `Local` is durable but node-local.
/// `Transient` is a real event for projection purposes but is not stored in the
/// durable event history. `Connection` is also transient; it carries the
/// connection context needed by projectors for protocol messages whose canonical
/// bytes are scoped to one established connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventScope {
    Shared,
    Local,
    Transient,
    Connection(ConnectionScope),
}

impl EventScope {
    pub fn is_shared(self) -> bool {
        matches!(self, Self::Shared)
    }

    pub fn is_durable(self) -> bool {
        matches!(self, Self::Shared | Self::Local)
    }

    pub fn durable_tag(self) -> Result<u8, String> {
        match self {
            Self::Shared => Ok(0),
            Self::Local => Ok(1),
            Self::Transient | Self::Connection(_) => {
                Err("non-durable event scope cannot be stored".to_string())
            }
        }
    }

    pub fn from_durable_tag(value: u8) -> Result<Self, String> {
        match value {
            0 => Ok(Self::Shared),
            1 => Ok(Self::Local),
            _ => Err(format!("unknown durable event scope {value}")),
        }
    }
}

/// Projection context for a connection-scoped transient event.
///
/// This is deliberately metadata, not event-body data. The same canonical sync
/// event bytes can be locally proposed for a connection or received from that
/// connection; projectors use this scope to decide which module-owned rows to
/// write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionScope {
    Outgoing { connection_id: EventId },
    Incoming { connection_id: EventId },
}

impl ConnectionScope {
    pub fn connection_id(self) -> EventId {
        match self {
            Self::Outgoing { connection_id } | Self::Incoming { connection_id } => connection_id,
        }
    }
}

/// Durable admission status for shared/local events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventStatus {
    Ready,
    Blocked,
    Applied,
    Rejected,
}

impl EventStatus {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Ready => 0,
            Self::Blocked => 1,
            Self::Applied => 2,
            Self::Rejected => 3,
        }
    }

    pub fn from_u8(value: u8) -> Result<Self, String> {
        match value {
            0 => Ok(Self::Ready),
            1 => Ok(Self::Blocked),
            2 => Ok(Self::Applied),
            3 => Ok(Self::Rejected),
            _ => Err(format!("unknown event status {value}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventIndexEntry {
    pub event_id: EventId,
    pub timestamp: u64,
    pub workspace_id: Option<EventId>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EventStatusCounts {
    pub ready: usize,
    pub blocked: usize,
    pub applied: usize,
    pub rejected: usize,
    pub blocked_edges: usize,
}

pub fn event_id(bytes: &[u8]) -> EventId {
    *blake3::hash(bytes).as_bytes()
}

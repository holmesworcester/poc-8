//! Connection-owned row tables.
//!
//! `CONNECTION_EVENTS` stores canonical request/connection bytes that are needed
//! to validate later connection facts and decrypt connection transit until TTL
//! purge removes them. `REQUEST_CONNECTIONS` maps an accepted request to the
//! connection event id that completed it. `CONNECTIONS` maps established
//! connection ids to remote endpoints. `CONNECTION_INVITE_WORKSPACES` records the one
//! workspace an invite-scoped request authorizes before mutual endpoint
//! membership has projected. `CONNECTION_SCOPED_EVENTS` is a durable local byte
//! cache for connection-scoped events such as sync compare/have/need; it is not
//! shared history and is eligible for TTL purge.
//! `PENDING_CONNECTION_ATTEMPTS` is a projected local retry queue keyed by a
//! local request id. It stores the invite address until the connection worker
//! obtains a response and replaces it with a normal `TRANSPORT_TARGETS` route.
//! `PENDING_CONNECTION_RESPONSES` is the responder-side queue keyed by received
//! request id. It stores the requester's advertised daemon address until the
//! connection worker creates and sends a response.
//! `TRANSPORT_TARGETS` is local route state: invite accept/connect paths write
//! the invite address for the resulting connection, but the address is not a
//! separate semantic event. Worker-owned send queues live in `src/protocol/workers/schema.rs`.

use std::net::SocketAddr;

use crate::core::store::{Schema, TableName, TableRow};
use crate::protocol::event_modules::identity::endpoint::types::EndpointId;
use crate::protocol::event_modules::types::EventId;

use super::types::ConnectionId;

pub(crate) const CONNECTION_EVENTS: TableName = TableName::new("connection.connection_events");
pub(crate) const REQUEST_CONNECTIONS: TableName = TableName::new("connection.request_connections");
pub(crate) const CONNECTIONS: TableName = TableName::new("connection.connections");
pub(crate) const CONNECTION_INVITE_WORKSPACES: TableName =
    TableName::new("connection.invite_workspaces");
pub(crate) const CONNECTION_SCOPED_EVENTS: TableName =
    TableName::new("connection.connection_scoped_events");
pub(crate) const PENDING_CONNECTION_ATTEMPTS: TableName =
    TableName::new("connection.pending_connection_attempts");
pub(crate) const PENDING_CONNECTION_RESPONSES: TableName =
    TableName::new("connection.pending_connection_responses");
pub(crate) const TRANSPORT_TARGETS: TableName = TableName::new("connection.transport_targets");

pub const SCHEMAS: &[Schema] = &[
    Schema::durable_row_table("connection.connection_events.v1", CONNECTION_EVENTS),
    Schema::durable_row_table("connection.request_connections.v1", REQUEST_CONNECTIONS),
    Schema::durable_row_table("connection.connections.v1", CONNECTIONS),
    Schema::durable_row_table(
        "connection.invite_workspaces.v1",
        CONNECTION_INVITE_WORKSPACES,
    ),
    Schema::durable_row_table("connection.transport_targets.v1", TRANSPORT_TARGETS),
    Schema::durable_row_table(
        "connection.connection_scoped_events.v1",
        CONNECTION_SCOPED_EVENTS,
    ),
    Schema::durable_row_table(
        "connection.pending_connection_attempts.v1",
        PENDING_CONNECTION_ATTEMPTS,
    ),
    Schema::durable_row_table(
        "connection.pending_connection_responses.v1",
        PENDING_CONNECTION_RESPONSES,
    ),
];

pub(crate) fn connection_event_row(event_id: EventId, bytes: Vec<u8>) -> TableRow {
    TableRow {
        table: CONNECTION_EVENTS,
        key: event_id.to_vec(),
        value: bytes,
    }
}

pub(crate) fn request_connection_row(request_id: EventId, connection_id: ConnectionId) -> TableRow {
    TableRow {
        table: REQUEST_CONNECTIONS,
        key: request_id.to_vec(),
        value: connection_id.to_vec(),
    }
}

pub(crate) fn connection_row(connection_id: ConnectionId, remote_endpoint: EndpointId) -> TableRow {
    TableRow {
        table: CONNECTIONS,
        key: connection_id.to_vec(),
        value: remote_endpoint.to_vec(),
    }
}

pub(crate) fn connection_invite_workspace_row(
    connection_id: ConnectionId,
    workspace_id: EventId,
) -> TableRow {
    TableRow {
        table: CONNECTION_INVITE_WORKSPACES,
        key: connection_id.to_vec(),
        value: workspace_id.to_vec(),
    }
}

pub(crate) fn transport_target_row(connection_id: ConnectionId, addr: SocketAddr) -> TableRow {
    TableRow {
        table: TRANSPORT_TARGETS,
        key: connection_id.to_vec(),
        value: addr.to_string().into_bytes(),
    }
}

pub(crate) fn pending_connection_attempt_row(request_id: EventId, addr: SocketAddr) -> TableRow {
    TableRow {
        table: PENDING_CONNECTION_ATTEMPTS,
        key: request_id.to_vec(),
        value: addr.to_string().into_bytes(),
    }
}

pub(crate) fn pending_connection_response_row(request_id: EventId, addr: SocketAddr) -> TableRow {
    TableRow {
        table: PENDING_CONNECTION_RESPONSES,
        key: request_id.to_vec(),
        value: addr.to_string().into_bytes(),
    }
}

pub(crate) fn connection_scoped_event_row(event_id: EventId, canonical_bytes: Vec<u8>) -> TableRow {
    TableRow {
        table: CONNECTION_SCOPED_EVENTS,
        key: event_id.to_vec(),
        value: canonical_bytes,
    }
}

//! Connection-owned row tables.
//!
//! `CONNECTIONS` maps established connection ids to remote endpoints.
//! `TRANSPORT_TARGETS` is receive-derived local state: connection projection
//! writes the latest socket address observed for a connection, but the address
//! is not a separate semantic event. Canonical request/response and
//! connection-scoped sync bytes live in the common local event store.
//! Worker-owned send queues live in `src/workers/schema.rs`.

use std::net::SocketAddr;

use crate::core::store::Store;
use crate::core::store::{Schema, TableName, TableRow};
use crate::protocol::event_modules::identity::endpoint::types::EndpointId;
use crate::protocol::event_modules::types::EventId;

use super::types::ConnectionId;

pub(crate) const CONNECTIONS: TableName = TableName::new("connection.connections");
pub(crate) const TRANSPORT_TARGETS: TableName = TableName::new("connection.transport_targets");

pub const SCHEMAS: &[Schema] = &[
    Schema::durable_row_table("connection.connections.v1", CONNECTIONS),
    Schema::durable_row_table("connection.transport_targets.v1", TRANSPORT_TARGETS),
];

pub(crate) fn connection_row(connection_id: ConnectionId, remote_endpoint: EndpointId) -> TableRow {
    TableRow {
        table: CONNECTIONS,
        key: connection_id.to_vec(),
        value: remote_endpoint.to_vec(),
    }
}

pub(crate) fn transport_target_row(connection_id: ConnectionId, addr: SocketAddr) -> TableRow {
    TableRow {
        table: TRANSPORT_TARGETS,
        key: connection_id.to_vec(),
        value: addr.to_string().into_bytes(),
    }
}

pub(crate) fn remote_endpoint(
    store: &Store,
    connection_id: ConnectionId,
) -> Result<EndpointId, String> {
    let bytes = store
        .table_row(CONNECTIONS, &connection_id)
        .map_err(|err| format!("load connection: {err}"))?
        .ok_or_else(|| "unknown connection".to_string())?;
    endpoint_id_from_bytes(&bytes)
}

fn endpoint_id_from_bytes(bytes: &[u8]) -> Result<EndpointId, String> {
    id_from_bytes(bytes).map_err(|_| "stored endpoint id is malformed".to_string())
}

fn id_from_bytes(bytes: &[u8]) -> Result<EventId, String> {
    if bytes.len() != 32 {
        return Err("stored id is malformed".to_string());
    }
    let mut out = [0; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

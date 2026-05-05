//! Connection-owned row tables.
//!
//! `CONNECTION_EVENTS` stores canonical request/ack bytes that are needed to
//! validate later connection facts. `CONNECTIONS` maps established connection
//! ids to remote endpoints. `CONNECTION_SCOPED_EVENTS` is an in-memory byte
//! cache for non-durable connection-scoped events such as sync compare/have/need.
//! `OUTBOX` is id-only in-memory send work: the connection worker resolves each
//! id to durable or in-memory canonical bytes before wrapping, and lost rows are
//! recreated by later sync. Core network queues only see the wrapped bytes
//! produced later by the worker. `TRANSPORT_TARGETS` is
//! receive-derived local state: connection projection writes the latest socket
//! address observed for a connection, but the address is not a separate semantic
//! event. `BOOTSTRAP_WORKSPACES` records the workspace scope proved by an invite
//! during first contact, so the inviter can receive the joiner's initial
//! identity facts before steady-state mutual membership exists.

use std::net::SocketAddr;

use crate::core::store::Store;
use crate::core::store::{Schema, TableName, TableRow};
use crate::protocol::event_modules::identity::endpoint::types::EndpointId;
use crate::protocol::event_modules::types::EventId;

use super::types::{ConnectionId, OutboxKey};

pub(in crate::protocol::event_modules) const CONNECTION_EVENTS: TableName =
    TableName::new("connection.connection_events");
pub(in crate::protocol::event_modules) const CONNECTIONS: TableName =
    TableName::new("connection.connections");
pub(in crate::protocol::event_modules) const CONNECTION_SCOPED_EVENTS: TableName =
    TableName::new("connection.connection_scoped_events");
pub(in crate::protocol::event_modules) const OUTBOX: TableName =
    TableName::new("connection.outbox");
pub(in crate::protocol::event_modules) const TRANSPORT_TARGETS: TableName =
    TableName::new("connection.transport_targets");
pub(in crate::protocol::event_modules) const BOOTSTRAP_WORKSPACES: TableName =
    TableName::new("connection.bootstrap_workspaces");

pub const SCHEMAS: &[Schema] = &[
    Schema::durable_row_table("connection.connection_events.v1", CONNECTION_EVENTS),
    Schema::durable_row_table("connection.connections.v1", CONNECTIONS),
    Schema::durable_row_table("connection.transport_targets.v1", TRANSPORT_TARGETS),
    Schema::durable_row_table("connection.bootstrap_workspaces.v1", BOOTSTRAP_WORKSPACES),
    Schema::memory_row_table(
        "connection.connection_scoped_events.v1",
        CONNECTION_SCOPED_EVENTS,
    ),
    Schema::memory_row_table("connection.outbox.v1", OUTBOX),
];

pub(crate) fn connection_event_row(event_id: EventId, bytes: Vec<u8>) -> TableRow {
    TableRow {
        table: CONNECTION_EVENTS,
        key: event_id.to_vec(),
        value: bytes,
    }
}

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

pub(crate) fn bootstrap_workspace_row(
    connection_id: ConnectionId,
    workspace_id: EventId,
) -> TableRow {
    TableRow {
        table: BOOTSTRAP_WORKSPACES,
        key: connection_id.to_vec(),
        value: workspace_id.to_vec(),
    }
}

pub(in crate::protocol::event_modules) fn connection_scoped_event_row(
    event_id: EventId,
    canonical_bytes: Vec<u8>,
) -> TableRow {
    TableRow {
        table: CONNECTION_SCOPED_EVENTS,
        key: event_id.to_vec(),
        value: canonical_bytes,
    }
}

pub(in crate::protocol::event_modules) fn outbox_row(
    connection_id: ConnectionId,
    event_id: EventId,
) -> TableRow {
    let key = OutboxKey {
        connection_id,
        event_id,
    }
    .to_bytes();
    TableRow {
        table: OUTBOX,
        key,
        value: Vec::new(),
    }
}

pub(in crate::protocol::event_modules) fn remote_endpoint(
    store: &Store,
    connection_id: ConnectionId,
) -> Result<EndpointId, String> {
    let bytes = store
        .table_row(CONNECTIONS, &connection_id)
        .map_err(|err| format!("load connection: {err}"))?
        .ok_or_else(|| "unknown connection".to_string())?;
    endpoint_id_from_bytes(&bytes)
}

pub(in crate::protocol::event_modules) fn bootstrap_workspace_id(
    store: &Store,
    connection_id: ConnectionId,
) -> Result<Option<EventId>, String> {
    store
        .table_row(BOOTSTRAP_WORKSPACES, &connection_id)
        .map_err(|err| format!("load bootstrap workspace: {err}"))?
        .map(|bytes| id_from_bytes(&bytes))
        .transpose()
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

#[cfg(test)]
mod tests {
    use crate::protocol::Protocol;

    use super::*;

    #[test]
    fn outbox_rows_are_memory_restart_work() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let path = tmp.path().join("connection-outbox.db");
        {
            let store = Protocol::open_store(&path).expect("open first store");
            store
                .insert_table_rows(vec![outbox_row([1; 32], [2; 32])])
                .expect("insert temp outbox row");
            assert_eq!(store.table_row_count(OUTBOX).expect("count temp outbox"), 1);
        }

        let store = Protocol::open_store(&path).expect("reopen store");
        assert_eq!(
            store
                .table_row_count(OUTBOX)
                .expect("count temp outbox after reopen"),
            0
        );
    }
}

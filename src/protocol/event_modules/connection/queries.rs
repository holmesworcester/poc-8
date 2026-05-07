//! Read-only connection CLI views.
//!
//! Workers keep operational reads close to the work they perform. This file is
//! intentionally just the reporting surface used by CLI count/status commands.

use crate::core::store::Store;

use super::schema;
use super::types::ConnectionId;
use crate::protocol::event_modules::identity::endpoint::types::EndpointId;

pub fn connection_count(store: &Store) -> Result<usize, String> {
    store
        .table_row_count(schema::CONNECTIONS)
        .map_err(|err| format!("count connections: {err}"))
}

pub fn connection_event_count(store: &Store) -> Result<usize, String> {
    store
        .table_row_count(schema::CONNECTION_EVENTS)
        .map_err(|err| format!("count connection events: {err}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionListing {
    pub connection_id: ConnectionId,
    pub remote_endpoint: EndpointId,
    pub addr: Option<String>,
}

pub fn list_connections(store: &Store) -> Result<Vec<ConnectionListing>, String> {
    let connections = store
        .table_rows(schema::CONNECTIONS)
        .map_err(|err| format!("load connections: {err}"))?;
    let mut out = Vec::with_capacity(connections.len());
    for (key, value) in connections {
        let connection_id = decode_id(&key, "connection id")?;
        let remote_endpoint = decode_id(&value, "remote endpoint id")?;
        // Prefer a stable dial-back route if the worker remembered one;
        // otherwise fall back to the most recent observed peer source addr so
        // the listener side can still report 127.0.0.1:port for debugging.
        let addr = match load_addr(store, schema::TRANSPORT_TARGETS, &key)? {
            Some(addr) => Some(addr),
            None => load_addr(store, schema::RECENT_PEER_ADDRS, &key)?,
        };
        out.push(ConnectionListing {
            connection_id,
            remote_endpoint,
            addr,
        });
    }
    out.sort_by(|left, right| left.connection_id.cmp(&right.connection_id));
    Ok(out)
}

fn load_addr(
    store: &Store,
    table: crate::core::store::TableName,
    key: &[u8],
) -> Result<Option<String>, String> {
    store
        .table_row(table, key)
        .map_err(|err| format!("load addr from {}: {err}", table.as_str()))?
        .map(|bytes| {
            String::from_utf8(bytes)
                .map_err(|_| format!("{} address is not utf-8", table.as_str()))
        })
        .transpose()
}

fn decode_id(bytes: &[u8], label: &str) -> Result<[u8; 32], String> {
    if bytes.len() != 32 {
        return Err(format!("{label} has invalid length"));
    }
    let mut out = [0; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

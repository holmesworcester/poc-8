//! Read-only connection views.
//!
//! This file exposes bounded reads over connection-owned tables. CLI commands
//! use the counters for status output.

use crate::core::store::Store;

use super::{connection_request, connection_response, schema};
use crate::protocol::event_modules::schema as event_schema;

pub fn connection_count(store: &Store) -> Result<usize, String> {
    store
        .table_row_count(schema::CONNECTIONS)
        .map_err(|err| format!("count connections: {err}"))
}

pub fn connection_event_count(store: &Store) -> Result<usize, String> {
    event_schema::all_applied_event_bytes(store)
        .map_err(|err| format!("count connection events: {err}"))
        .map(|events| {
            events
                .into_iter()
                .filter(|bytes| {
                    connection_request::codec::is_request(bytes)
                        || connection_response::codec::is_response(bytes)
                })
                .count()
        })
}

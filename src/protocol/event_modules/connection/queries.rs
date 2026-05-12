//! Read-only connection CLI views.
//!
//! Active workers and projectors keep their connection-state reads local to the
//! operation they are performing. This file stays intentionally small: it only
//! exposes reporting/counting queries for user-facing status commands.

use crate::core::store::Store;

use super::schema;

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

//! Read-only connection CLI views.
//!
//! Workers keep operational reads close to the work they perform. This file is
//! intentionally just the reporting surface used by CLI count/status commands.

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

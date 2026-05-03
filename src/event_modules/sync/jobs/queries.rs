use crate::store::{EventId, Store, TableRow, TableRowDeletion};

use super::tables;

pub fn initiator_session_exists(store: &Store, connection_id: EventId) -> Result<bool, String> {
    store
        .table_row(tables::INITIATOR_SESSION, &connection_id)
        .map(|row| row.is_some())
        .map_err(|err| format!("load sync initiator session: {err}"))
}

pub fn initiator_session_row(connection_id: EventId) -> TableRow {
    TableRow {
        table: tables::INITIATOR_SESSION,
        key: connection_id.to_vec(),
        value: Vec::new(),
    }
}

pub fn initiator_session_delete(connection_id: EventId) -> TableRowDeletion {
    TableRowDeletion {
        table: tables::INITIATOR_SESSION,
        key: connection_id.to_vec(),
    }
}

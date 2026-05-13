//! Message deletion projection-owned tables.
//!
//! The deletion projector emits a row into `content.purge_pending` whenever it
//! admits a deletion fact. The row is a generic operational marker: a worker-level
//! post-admission hook scans this table to decide whether the content purge
//! worker should run before returning to the caller. This keeps the deletion
//! semantic in the projector while letting any synchronous admission path drain
//! the resulting purge work without waiting for the daemon's tick.
//!
//! The table is memory-only: durable forward-secrecy is provided by the deletion
//! event itself plus the message tombstone summary written by the purge worker.
//! After a clean process exit the queue is empty by construction, and the
//! daemon's belt-and-suspenders content_purge worker still runs a full scan to
//! handle any deletion admitted before this binary was deployed.

use crate::core::store::{Schema, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;

pub const CONTENT_PURGE_PENDING: TableName = TableName::new("content.purge_pending");

pub const SCHEMAS: &[Schema] = &[Schema::memory_row_table(
    "content.purge_pending.v1",
    CONTENT_PURGE_PENDING,
)];

/// Row written by the deletion projector to mark that the content purge worker
/// has bounded work waiting after admission completes.
pub fn purge_pending_row(target_message_id: EventId) -> TableRow {
    TableRow {
        table: CONTENT_PURGE_PENDING,
        key: target_message_id.to_vec(),
        value: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::Protocol;

    use super::super::queries::has_purge_pending;
    use super::*;

    #[test]
    fn purge_pending_row_targets_message_id_with_empty_value() {
        let row = purge_pending_row([7; 32]);
        assert_eq!(row.table, CONTENT_PURGE_PENDING);
        assert_eq!(row.key, [7; 32].to_vec());
        assert!(row.value.is_empty());
    }

    #[test]
    fn purge_pending_round_trips_through_has_query() {
        let store = Protocol::open_memory_store().expect("store");
        assert!(!has_purge_pending(&store).expect("empty"));
        store
            .insert_table_rows(vec![purge_pending_row([3; 32])])
            .expect("insert pending row");
        assert!(has_purge_pending(&store).expect("populated"));
    }

    #[test]
    fn purge_pending_table_is_memory_only_and_resets_across_reopens() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("purge-pending.db");
        {
            let store = Protocol::open_store(&path).expect("open first");
            store
                .insert_table_rows(vec![purge_pending_row([9; 32])])
                .expect("insert pending row");
            assert!(has_purge_pending(&store).expect("populated"));
        }
        let store = Protocol::open_store(&path).expect("reopen");
        assert!(!has_purge_pending(&store).expect("memory table reset"));
    }
}

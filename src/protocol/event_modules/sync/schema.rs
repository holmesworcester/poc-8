//! Sync-domain shared schema.
//!
//! This file holds row-table declarations that belong to the sync domain
//! as a whole (not to one of its child event modules). At the moment the
//! only such table is the negentropy purge queue described below; if
//! future work needs another sync-wide local table, declare it here next
//! to `NEGENTROPY_PENDING_PURGES` and append its row-table schema to
//! `SCHEMAS`.
//!
//! # Negentropy purge queue
//!
//! When the worker-owned local-retention purge helper drops the canonical
//! bytes of an admitted shared event from `EVENTS`, the in-memory negentropy
//! `SyncIndex` still references the event id by timestamp + workspace. Two
//! peers that purge the same set of ids must reach byte-identical sync
//! summaries; if the index keeps stale ids around, two peers can disagree
//! on the root summary and re-request canonical bytes that they
//! intentionally dropped.
//!
//! This file owns the durable per-event row that records "negentropy still
//! has not been told that this event id was purged." The purging helper
//! enqueues one row per purged event in the same transaction as the
//! canonical-bytes delete; the negentropy purge drainer worker drains the
//! rows on the next daemon tick and removes the matching ids from the
//! in-memory index.
//!
//! The table is local-only state. It is never propagated; each peer
//! independently bookkeeps its own pending purges. It lives here, at the
//! sync-domain root, because it is shared bookkeeping for the sync index
//! and is not itself a canonical event with codec/projector behavior.
//!
//! Schema:
//!   * key = `workspace_id (32) || event_id (32)` (64 bytes total)
//!   * value = a single sentinel byte (`0`); the row's existence is the
//!     only fact carried, but a non-empty value keeps ad-hoc dumps
//!     legible.

use crate::core::store::{Schema, Store, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;

/// Table name for the per-peer negentropy pending-purge queue.
pub const NEGENTROPY_PENDING_PURGES: TableName =
    TableName::new("encryption.negentropy_pending_purges");

/// Schema declarations contributed by this file. Aggregated in
/// `protocol::event_modules::schemas` next to other module schema lists.
pub const SCHEMAS: &[Schema] = &[Schema::durable_row_table(
    "encryption.negentropy_pending_purges.v1",
    NEGENTROPY_PENDING_PURGES,
)];

/// Length of the row key, in bytes (workspace_id || event_id).
pub const KEY_BYTES: usize = 32 + 32;

/// Build a table row that records "negentropy still owes a purge of
/// `event_id` in `workspace_id`."
pub fn pending_purge_row(workspace_id: EventId, event_id: EventId) -> TableRow {
    TableRow {
        table: NEGENTROPY_PENDING_PURGES,
        key: pending_purge_key(workspace_id, event_id),
        value: vec![0],
    }
}

/// Build the row key for a pending-purge entry without constructing the
/// full row. Used by callers that only need to delete the row (drainer
/// path).
pub fn pending_purge_key(workspace_id: EventId, event_id: EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(KEY_BYTES);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&event_id);
    key
}

/// Decode a row key back into its `(workspace_id, event_id)` components.
pub fn decode_pending_purge_key(key: &[u8]) -> Result<(EventId, EventId), String> {
    if key.len() != KEY_BYTES {
        return Err(format!(
            "negentropy pending purge key should be {} bytes, got {}",
            KEY_BYTES,
            key.len()
        ));
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut event_id = [0; 32];
    event_id.copy_from_slice(&key[32..]);
    Ok((workspace_id, event_id))
}

/// Enqueue a single pending purge row inside an open write transaction.
///
/// Callers MUST be inside `Store::write_transaction(...)` when they call
/// this so the queue row becomes visible atomically with the canonical
/// bytes deletion. Workspace-less purges (events that lack an admitted
/// workspace scope) are a no-op: such events were never admissible to a
/// workspace-scoped negentropy summary and so cannot be in the in-memory
/// index.
pub fn enqueue_purge_in_tx(
    store: &Store,
    workspace_id: Option<EventId>,
    event_id: &EventId,
) -> rusqlite::Result<bool> {
    let Some(workspace_id) = workspace_id else {
        return Ok(false);
    };
    let inserted = store
        .insert_table_rows_in_tx(vec![pending_purge_row(workspace_id, *event_id)])?;
    Ok(inserted > 0)
}

/// Drain up to `limit` queued pending-purge rows.
///
/// Returns the decoded `(workspace_id, event_id)` pairs along with the raw
/// row keys so the drainer can hand those keys to `clear_pending_purges`
/// after it has removed each id from the in-memory negentropy index. The
/// scan is ordered by key, so two peers that have queued the same set of
/// purges drain them in the same order — the in-memory index is mutated
/// deterministically.
pub fn drain_pending_purges(
    store: &Store,
    limit: usize,
) -> Result<Vec<PendingPurge>, String> {
    let limit = limit.max(1);
    let rows = store
        .table_rows_with_key_prefix(NEGENTROPY_PENDING_PURGES, &[], limit)
        .map_err(|err| format!("load negentropy pending purges: {err}"))?;
    rows.into_iter()
        .map(|(key, _)| {
            let (workspace_id, event_id) = decode_pending_purge_key(&key)?;
            Ok(PendingPurge {
                key,
                workspace_id,
                event_id,
            })
        })
        .collect()
}

/// Delete a batch of drained pending-purge rows.
///
/// This is called by the negentropy purge drainer after it has applied
/// each row to the in-memory `SyncIndex`. The delete runs outside any
/// transaction here because the row is local-only restart bookkeeping: a
/// drainer crash between "remove from in-memory index" and "delete row"
/// is recovered by simply re-removing the id on the next tick (the index
/// remove is idempotent — see `SyncIndex::remove_event`).
pub fn clear_pending_purges(store: &Store, keys: Vec<Vec<u8>>) -> Result<usize, String> {
    if keys.is_empty() {
        return Ok(0);
    }
    store
        .delete_table_rows(NEGENTROPY_PENDING_PURGES, keys)
        .map_err(|err| format!("delete negentropy pending purges: {err}"))
}

/// Convenience wrapper for tests and ad-hoc CLI commands: clear a single
/// queued purge row by its `(workspace_id, event_id)` pair.
pub fn clear_pending_purge(
    store: &Store,
    workspace_id: EventId,
    event_id: EventId,
) -> Result<bool, String> {
    let key = pending_purge_key(workspace_id, event_id);
    let deleted = store
        .delete_table_rows(NEGENTROPY_PENDING_PURGES, vec![key])
        .map_err(|err| format!("delete single negentropy pending purge: {err}"))?;
    Ok(deleted > 0)
}

/// Total number of rows currently queued. Tests assert this drops to 0
/// after a daemon tick to prove the drainer ran.
pub fn pending_purge_count(store: &Store) -> rusqlite::Result<usize> {
    store.table_row_count(NEGENTROPY_PENDING_PURGES)
}

/// One drained pending-purge row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPurge {
    /// Raw key, used to delete the row after the in-memory index update
    /// commits.
    pub key: Vec<u8>,
    pub workspace_id: EventId,
    pub event_id: EventId,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Protocol;

    #[test]
    fn enqueue_then_drain_returns_inserted_pair() {
        let store = Protocol::open_memory_store().expect("open store");
        let workspace_id = [1u8; 32];
        let event_id = [2u8; 32];

        let inserted = store
            .write_transaction(|store| {
                Ok(enqueue_purge_in_tx(store, Some(workspace_id), &event_id)
                    .map_err(|err| {
                        rusqlite::Error::InvalidParameterName(err.to_string())
                    })
                    .unwrap_or(false))
            })
            .expect("enqueue purge");
        assert!(inserted);

        let drained = drain_pending_purges(&store, 16).expect("drain");
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].workspace_id, workspace_id);
        assert_eq!(drained[0].event_id, event_id);
        assert_eq!(pending_purge_count(&store).expect("count"), 1);

        let cleared = clear_pending_purges(&store, vec![drained[0].key.clone()])
            .expect("clear");
        assert_eq!(cleared, 1);
        assert_eq!(pending_purge_count(&store).expect("count"), 0);
    }

    #[test]
    fn enqueue_without_workspace_is_noop() {
        let store = Protocol::open_memory_store().expect("open store");
        let event_id = [3u8; 32];

        let inserted = store
            .write_transaction(|store| {
                enqueue_purge_in_tx(store, None, &event_id).map_err(|err| {
                    rusqlite::Error::InvalidParameterName(err.to_string())
                })
            })
            .expect("enqueue purge without workspace");
        assert!(!inserted);
        assert_eq!(pending_purge_count(&store).expect("count"), 0);
    }

    #[test]
    fn drain_returns_rows_in_deterministic_key_order() {
        let store = Protocol::open_memory_store().expect("open store");
        let workspace_id = [9u8; 32];
        // Insert in non-sorted order; the table scan should sort by key.
        let ids: Vec<EventId> = vec![[5u8; 32], [1u8; 32], [3u8; 32], [4u8; 32], [2u8; 32]];
        store
            .write_transaction(|store| {
                for id in &ids {
                    let _ = enqueue_purge_in_tx(store, Some(workspace_id), id)
                        .map_err(|err| rusqlite::Error::InvalidParameterName(err.to_string()))?;
                }
                Ok(())
            })
            .expect("enqueue many");

        let drained = drain_pending_purges(&store, 16).expect("drain");
        let drained_event_ids: Vec<EventId> = drained.iter().map(|p| p.event_id).collect();
        let mut expected: Vec<EventId> = ids.clone();
        expected.sort();
        assert_eq!(drained_event_ids, expected);
    }

    #[test]
    fn clear_pending_purge_helper_removes_named_row() {
        let store = Protocol::open_memory_store().expect("open store");
        let workspace_id = [7u8; 32];
        let event_id = [8u8; 32];
        store
            .write_transaction(|store| {
                enqueue_purge_in_tx(store, Some(workspace_id), &event_id).map_err(|err| {
                    rusqlite::Error::InvalidParameterName(err.to_string())
                })
            })
            .expect("enqueue purge");
        assert_eq!(pending_purge_count(&store).expect("count"), 1);

        let cleared = clear_pending_purge(&store, workspace_id, event_id).expect("clear");
        assert!(cleared);
        assert_eq!(pending_purge_count(&store).expect("count"), 0);

        // Idempotent — the second clear is a no-op.
        let cleared_again = clear_pending_purge(&store, workspace_id, event_id).expect("clear 2");
        assert!(!cleared_again);
    }
}

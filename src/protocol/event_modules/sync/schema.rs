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

use crate::core::store::{Schema, TableName, TableRow};
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

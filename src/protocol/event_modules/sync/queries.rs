//! Read-only views over the negentropy pending-purge queue.
//!
//! Scope: a single count CLI/test helpers use to observe queue depth.
//! Enqueue/drain/clear live in the workers that own the bookkeeping
//! (`workers::sync` drains the queue each tick; `workers::pipeline_helpers::purging`
//! enqueues when canonical bytes are dropped from `EVENTS`).

use crate::core::store::Store;

use super::schema::NEGENTROPY_PENDING_PURGES;

/// Total number of rows currently queued. Tests assert this drops to 0
/// after a daemon tick to prove the drainer ran.
pub fn pending_purge_count(store: &Store) -> rusqlite::Result<usize> {
    store.table_row_count(NEGENTROPY_PENDING_PURGES)
}

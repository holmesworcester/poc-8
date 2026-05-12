//! Negentropy purge drainer worker.
//!
//! Inputs:
//!   * `encryption.negentropy_pending_purges.v1` rows enqueued by
//!     `purge_event_storage_in_tx` whenever a workspace-scoped shared
//!     event's canonical bytes are dropped from `EVENTS`.
//!
//! Step: read up to `work_limit` queued rows in deterministic key order,
//! call `SyncIndex::remove_event` for each id, then delete the queued rows.
//! The in-memory index update and the row delete are not run in the same
//! transaction because the index is process-local memory; a daemon crash
//! between the two simply re-applies the (idempotent) `remove_event` on
//! the next tick.
//!
//! Outputs: the in-memory `SyncIndex` no longer references any of the
//! purged ids, so the next `compare`/`have_id` round produces a summary
//! consistent with the on-disk EVENTS state. Two peers that have purged
//! the same set of ids reach byte-identical root summaries (proven by
//! the cross-peer test in `tests/negentropy_purge_sync_test.rs`).
//!
//! Sequencing: the daemon list runs `disappearing_minute_expiry` and
//! then `disappearing_floor_dispatcher` first. Both can call into the
//! purging helper, which writes to `negentropy_pending_purges`. Running
//! this drainer immediately after them — and *before* `sync_tick` —
//! guarantees the response-producing sync work in the same daemon tick
//! reads a clean index.
//!
//! Local-only state: the queue table is durable but never propagated.
//! The in-memory `SyncIndex` is restart-local; on restart it is rebuilt
//! by `prepare_index_for_response` (which scans `TIMESTAMP_EVENTS`),
//! and that scan necessarily skips purged ids because their rows were
//! deleted by the same transaction that enqueued the pending purge. So
//! the queue is also harmless to leave behind across a restart: the
//! drainer just drains rows whose ids were never put into the index,
//! and the `remove_event` calls return false for each.
//!
//! Fairness: the drainer claims `ctx.options.work_limit` rows per tick.
//! A peer that wakes from a long sleep with thousands of pending purges
//! drains them in batches across subsequent ticks; sync work in the
//! current tick is bounded by other workers, so a long drain cannot
//! block the loop.

use crate::core::daemon::{StepContext, Worker};
use crate::core::store::Store;
use crate::protocol::event_modules::sync::schema as negentropy_purges;
use crate::protocol::event_modules::sync::SyncIndex;
use crate::workers::DaemonWorkerContext;

/// Default upper bound when a caller does not pass an explicit limit.
/// Kept large enough that one tick's drain absorbs the bursty per-leaf
/// retire / chop output of a typical disappearing-minute expiry, but
/// finite so a single tick cannot stall.
pub const DEFAULT_DRAIN_LIMIT: usize = 4096;

/// Summary of one drain pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DrainReport {
    /// Total queued rows pulled from `negentropy_pending_purges` this tick.
    pub drained_rows: usize,
    /// Rows whose ids were still in the in-memory index when removed.
    /// `drained_rows - removed_from_index` rows were already absent
    /// (e.g. a daemon restart drained them after a previous tick had
    /// already updated the index).
    pub removed_from_index: usize,
}

/// Caller-facing work shape — the drainer has only one mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    Drain { limit: usize },
}

/// Run one drain pass.
///
/// This entrypoint exists so unit tests, the daemon worker step, and any
/// future ad-hoc CLI command go through the same code path. Callers
/// supply the in-memory `SyncIndex` they want updated; production wiring
/// passes the `Modules`-owned shared one.
pub fn run(store: &Store, index: &SyncIndex, work: Work) -> Result<DrainReport, String> {
    match work {
        Work::Drain { limit } => drain(store, index, limit),
    }
}

/// Daemon worker descriptor used by the worker catalog. The worker name
/// is surfaced by `daemon_workers` and asserted on by the catalog test.
pub(crate) fn daemon_worker<C>() -> Worker<C>
where
    C: DaemonWorkerContext,
{
    Worker {
        name: "negentropy_purge_drainer",
        run: daemon_step::<C>,
    }
}

fn daemon_step<C>(ctx: &mut StepContext<'_, C>) -> Result<(), String>
where
    C: DaemonWorkerContext,
{
    let app = &*ctx.app;
    let report = run(
        app.store(),
        app.sync_index(),
        Work::Drain {
            limit: ctx.options.work_limit.max(1),
        },
    )?;
    ctx.report
        .add("negentropy_purges_drained", report.drained_rows);
    ctx.report
        .add("negentropy_purges_applied", report.removed_from_index);
    Ok(())
}

fn drain(store: &Store, index: &SyncIndex, limit: usize) -> Result<DrainReport, String> {
    let mut report = DrainReport::default();
    let pending = negentropy_purges::drain_pending_purges(store, limit)?;
    if pending.is_empty() {
        return Ok(report);
    }

    let mut keys_to_clear = Vec::with_capacity(pending.len());
    for entry in &pending {
        report.drained_rows += 1;
        // Index removal runs first; if it fails we keep the queue row so
        // the next tick retries. SyncIndex::remove_event is intentionally
        // idempotent — a false return means the id was already absent.
        if index.remove_event(&entry.event_id)? {
            report.removed_from_index += 1;
        }
        keys_to_clear.push(entry.key.clone());
    }
    let _ = negentropy_purges::clear_pending_purges(store, keys_to_clear)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::event_modules::types::{EventId, EventIndexEntry};
    use crate::protocol::Protocol;

    fn enqueue(store: &Store, workspace_id: EventId, event_id: EventId) {
        store
            .write_transaction(|store| {
                negentropy_purges::enqueue_purge_in_tx(store, Some(workspace_id), &event_id)
                    .map_err(|err| rusqlite::Error::InvalidParameterName(err.to_string()))
            })
            .expect("enqueue purge");
    }

    fn entry(timestamp: u64, event_id: EventId, workspace_id: EventId) -> EventIndexEntry {
        EventIndexEntry {
            event_id,
            timestamp,
            workspace_id: Some(workspace_id),
        }
    }

    #[test]
    fn drain_removes_queued_ids_from_in_memory_index() {
        let store = Protocol::open_memory_store().expect("open store");
        let index = SyncIndex::default();
        let workspace_id = [1u8; 32];
        let id_a = [2u8; 32];
        let id_b = [3u8; 32];
        let id_c = [4u8; 32];

        for (ts, id) in [(10, id_a), (20, id_b), (30, id_c)] {
            index.insert_entry(entry(ts, id, workspace_id)).expect("insert");
        }
        let pre_summary = index.root_summary().expect("pre summary");
        let pre_count = index.indexed_event_count().expect("count");
        assert_eq!(pre_count, 3);

        // Purge ids a and c. Index summary should change after drain.
        enqueue(&store, workspace_id, id_a);
        enqueue(&store, workspace_id, id_c);
        let report = run(&store, &index, Work::Drain { limit: 16 }).expect("drain");
        assert_eq!(report.drained_rows, 2);
        assert_eq!(report.removed_from_index, 2);

        let post_summary = index.root_summary().expect("post summary");
        assert_ne!(pre_summary, post_summary, "summary must change after purge");
        assert_eq!(index.indexed_event_count().expect("count"), 1);
        assert!(!index.contains_event(&id_a).expect("contains a"));
        assert!(!index.contains_event(&id_c).expect("contains c"));
        assert!(index.contains_event(&id_b).expect("contains b"));
        assert_eq!(
            negentropy_purges::pending_purge_count(&store).expect("count"),
            0,
            "queue must be empty after drain"
        );
    }

    #[test]
    fn drain_is_deterministic_under_two_drain_orderings() {
        let workspace_id = [9u8; 32];
        let ids: Vec<EventId> = (0..16u8).map(|i| [i; 32]).collect();

        let build_indexed = || {
            let index = SyncIndex::default();
            for (idx, id) in ids.iter().enumerate() {
                index
                    .insert_entry(entry(1000 + idx as u64, *id, workspace_id))
                    .expect("insert");
            }
            index
        };

        // Ordering A: enqueue forward.
        let store_a = Protocol::open_memory_store().expect("open store a");
        let index_a = build_indexed();
        for id in ids.iter() {
            enqueue(&store_a, workspace_id, *id);
        }
        run(&store_a, &index_a, Work::Drain { limit: 64 }).expect("drain a");

        // Ordering B: enqueue reverse.
        let store_b = Protocol::open_memory_store().expect("open store b");
        let index_b = build_indexed();
        for id in ids.iter().rev() {
            enqueue(&store_b, workspace_id, *id);
        }
        run(&store_b, &index_b, Work::Drain { limit: 64 }).expect("drain b");

        // Both indices reach an empty admitted set; root summary is the
        // identity (count=0, fingerprint=zeros) regardless of insertion or
        // drain order. This is the load-bearing determinism property.
        let summary_a = index_a.root_summary().expect("summary a");
        let summary_b = index_b.root_summary().expect("summary b");
        assert_eq!(summary_a, summary_b);
        assert_eq!(summary_a.count, 0);
        assert_eq!(summary_a.fingerprint, [0u8; 32]);
    }

    #[test]
    fn partial_drain_under_purge_subset_yields_same_summary_for_two_orderings() {
        // Stronger property: two peers that purge the same SUBSET (not
        // all) of admitted ids reach byte-identical summaries regardless
        // of the drain ordering.
        let workspace_id = [11u8; 32];
        let live_ids: Vec<EventId> = (0..6u8).map(|i| [i; 32]).collect();
        let purged_ids: Vec<EventId> = (10..16u8).map(|i| [i; 32]).collect();

        let build_indexed = || {
            let index = SyncIndex::default();
            for (idx, id) in live_ids.iter().chain(purged_ids.iter()).enumerate() {
                index
                    .insert_entry(entry(1000 + idx as u64, *id, workspace_id))
                    .expect("insert");
            }
            index
        };

        let store_a = Protocol::open_memory_store().expect("open store a");
        let index_a = build_indexed();
        for id in purged_ids.iter() {
            enqueue(&store_a, workspace_id, *id);
        }
        run(&store_a, &index_a, Work::Drain { limit: 64 }).expect("drain a");

        let store_b = Protocol::open_memory_store().expect("open store b");
        let index_b = build_indexed();
        for id in purged_ids.iter().rev() {
            enqueue(&store_b, workspace_id, *id);
        }
        run(&store_b, &index_b, Work::Drain { limit: 64 }).expect("drain b");

        let summary_a = index_a.root_summary().expect("summary a");
        let summary_b = index_b.root_summary().expect("summary b");
        assert_eq!(summary_a, summary_b);
        assert_eq!(summary_a.count, live_ids.len() as u64);
    }

    #[test]
    fn drain_on_empty_queue_is_noop() {
        let store = Protocol::open_memory_store().expect("open store");
        let index = SyncIndex::default();
        let report = run(&store, &index, Work::Drain { limit: 16 }).expect("drain");
        assert_eq!(report.drained_rows, 0);
        assert_eq!(report.removed_from_index, 0);
    }

    #[test]
    fn drain_after_index_already_updated_clears_queue_row_idempotently() {
        // Mimics the daemon-restart case: the in-memory index is empty
        // (just rebuilt) and the queue still has rows for ids whose
        // EVENTS rows were already gone. The drain should still wipe
        // the queue so it does not grow without bound.
        let store = Protocol::open_memory_store().expect("open store");
        let index = SyncIndex::default();
        let workspace_id = [3u8; 32];
        let event_id = [7u8; 32];
        enqueue(&store, workspace_id, event_id);
        let report = run(&store, &index, Work::Drain { limit: 16 }).expect("drain");
        assert_eq!(report.drained_rows, 1);
        assert_eq!(report.removed_from_index, 0);
        assert_eq!(
            negentropy_purges::pending_purge_count(&store).expect("count"),
            0
        );
    }
}

//! Topo worker catalog.
//!
//! Workers are fundamental runtime boundaries. Each worker exposes one
//! synchronous `run` function over a small `Work` enum. Callers provide the
//! schedule by choosing which worker receives the next bounded work item.
//!
//! Implementations live in this directory so reviewers can see every active
//! queue/status/index drain in one place. `common_event_pipeline` is shared
//! machinery, not a scheduled worker. Event modules own event syntax, semantic
//! schemas, commands, and projectors; workers own bounded movement between
//! explicit inputs and outputs.
//!
//! See `src/workers/README.md` for the universal worker contract, queue list,
//! and caller-owned scheduling rules.

use crate::core::daemon::Worker;
use crate::core::store::Store;

pub mod bootstrap_exchange;
pub mod common_event_pipeline;
pub mod dependency_unblock;
pub mod encryption;
pub mod event_admission;
pub mod event_projection;
pub mod schema;
pub mod sync;
pub mod transit_in;
pub mod transit_out;

/// Protocol context required by daemon worker descriptors.
pub trait DaemonWorkerContext: common_event_pipeline::EventRegistry {
    fn store(&self) -> &Store;
    fn sync_index(&self) -> &crate::protocol::event_modules::sync::SyncIndex;
}

pub fn daemon_workers<C>() -> Vec<Worker<C>>
where
    C: DaemonWorkerContext,
{
    vec![
        transit_in::daemon_worker(),
        event_admission::daemon_worker(),
        event_projection::daemon_worker(),
        dependency_unblock::daemon_worker(),
        sync::daemon_worker(),
        transit_out::daemon_worker(),
    ]
}

//! Topo worker catalog.
//!
//! Workers are fundamental runtime boundaries. Each worker exposes one
//! synchronous `run` function over a small `Work` enum. Callers provide the
//! schedule by choosing which worker receives the next bounded work item.
//!
//! Implementations live in this directory so reviewers can see every active
//! queue/status/index drain in one place. `pipeline_helpers::event_pipeline` is shared
//! machinery, not a scheduled worker. Event modules own event syntax, semantic
//! schemas, commands, and projectors; workers own bounded movement between
//! explicit inputs and outputs.
//!
//! See `src/workers/README.md` for the universal worker contract, queue list,
//! and caller-owned scheduling rules.

use crate::core::daemon::Worker;
use crate::core::store::Store;
use crate::protocol::event_modules::content::message_deletion;

pub mod connection;
pub mod content_purge;
pub mod dependency_unblock;
pub mod encryption;
pub mod event_admission;
pub mod event_projection;
pub(crate) mod pipeline_helpers;
pub mod schema;
pub mod sync;
pub mod transit_in;
pub mod transit_out;

/// Drain pending content-purge work triggered during admission.
///
/// The deletion projector writes a `content.purge_pending` row whenever a
/// signed message-deletion fact is admitted. This helper observes that row
/// and runs `content_purge::Drain` once so any in-process admission path —
/// the inline `delete-message` call, a one-shot sync invocation, a scripted
/// batch, or the daemon's `event_admission` step — reaches the same
/// forward-secrecy end state without depending on a separately scheduled
/// daemon tick. The daemon's belt-and-suspenders worker remains in
/// `daemon_workers()` for any path this hook misses.
pub fn drain_post_admission_purge_pending<R>(store: &Store, registry: &R) -> Result<(), String>
where
    R: pipeline_helpers::event_pipeline::EventRegistry,
{
    if !message_deletion::schema::has_purge_pending(store)? {
        return Ok(());
    }
    content_purge::run(
        store,
        registry,
        content_purge::Work::Drain {
            limit: pipeline_helpers::event_pipeline::DEFAULT_READY_BATCH,
        },
    )?;
    Ok(())
}

/// Protocol context required by daemon worker descriptors.
pub trait DaemonWorkerContext: pipeline_helpers::event_pipeline::EventRegistry {
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
        encryption::daemon_worker(),
        content_purge::daemon_worker(),
        connection::daemon_worker(),
        sync::daemon_worker(),
        transit_out::daemon_worker(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_worker_catalog_lists_named_workers() {
        let names: Vec<&'static str> = daemon_workers::<TestContext>()
            .iter()
            .map(|w| w.name)
            .collect();
        assert!(names.contains(&"transit_in"));
        assert!(names.contains(&"connection"));
        assert!(names.contains(&"encryption"));
        assert!(names.contains(&"sync_tick"));
        assert!(names.contains(&"transit_out"));
        assert!(!names.contains(&"peer_supervisor"));
    }

    /// Test-only DaemonWorkerContext. Workers are never actually invoked here;
    /// the list is built only to surface their `name` field.
    struct TestContext;

    impl crate::workers::pipeline_helpers::event_pipeline::EventRegistry for TestContext {
        fn record_from_bytes(
            &self,
            _bytes: Vec<u8>,
        ) -> Result<crate::protocol::event_modules::types::EventRecord, String> {
            Err("not implemented".to_string())
        }

        fn project_network_in(
            &self,
            _store: &Store,
            _inbound: &crate::core::network_queues::InboundNetworkRow,
        ) -> Result<crate::workers::pipeline_helpers::event_pipeline::ProjectionOutput, String>
        {
            Err("not implemented".to_string())
        }

        fn record_from_canonical_in(
            &self,
            _store: &Store,
            _bytes: Vec<u8>,
            _receive: Option<crate::protocol::event_modules::types::ReceiveMetadata>,
            _provenance: Option<crate::workers::schema::TransitProvenance>,
        ) -> Result<crate::workers::pipeline_helpers::event_pipeline::ReceivedRecord, String>
        {
            Err("not implemented".to_string())
        }

        fn project_record(
            &self,
            _store: &Store,
            _event: &crate::workers::pipeline_helpers::event_pipeline::EventWithContext<'_>,
        ) -> Result<crate::workers::pipeline_helpers::event_pipeline::ProjectionOutput, String>
        {
            Err("not implemented".to_string())
        }
    }

    impl DaemonWorkerContext for TestContext {
        fn store(&self) -> &Store {
            unimplemented!("test context does not provide a store")
        }

        fn sync_index(&self) -> &crate::protocol::event_modules::sync::SyncIndex {
            unimplemented!()
        }
    }
}

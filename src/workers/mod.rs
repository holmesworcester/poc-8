//! Topo worker catalog.
//!
//! Workers are fundamental runtime boundaries. Each worker exposes one
//! synchronous `run` function over a small `Work` enum. Callers provide the
//! schedule by choosing which worker receives the next bounded work item.
//!
//! Implementations live in this directory so reviewers can see every active
//! queue/status/index drain in one place. `common::event_pipeline` is shared
//! machinery, not a scheduled worker. Event modules own event syntax, semantic
//! schemas, commands, and projectors; workers own bounded movement between
//! explicit inputs and outputs.
//!
//! See `src/workers/README.md` for the universal worker contract, queue list,
//! and caller-owned scheduling rules.

use crate::core::daemon::Worker;
use crate::core::store::Store;

pub mod bootstrap_exchange;
pub(crate) mod common;
pub mod content_purge;
pub mod dependency_unblock;
pub mod encryption;
pub mod event_admission;
pub mod event_projection;
pub mod peer_supervisor;
pub mod schema;
pub mod sync;
pub mod transit_in;
pub mod transit_out;

/// Protocol context required by daemon worker descriptors.
pub trait DaemonWorkerContext: common::event_pipeline::EventRegistry {
    fn store(&self) -> &Store;
    fn sync_index(&self) -> &crate::protocol::event_modules::sync::SyncIndex;
    fn peer_supervisor_cursor(&self) -> &peer_supervisor::PeerCursor;
}

pub fn daemon_workers<C>() -> Vec<Worker<C>>
where
    C: DaemonWorkerContext,
{
    vec![
        // Accept any available inbound stream first so bootstrap responses
        // (workspace identity events) ride out on the same TCP connection the
        // requester opened. The same accept handler also writes a transport
        // target row from the requester's advertised steady-state listener so
        // the daemon can dial that peer back after the bootstrap stream
        // closes.
        bootstrap_exchange::daemon_worker(),
        transit_in::daemon_worker(),
        event_admission::daemon_worker(),
        event_projection::daemon_worker(),
        dependency_unblock::daemon_worker(),
        content_purge::daemon_worker(),
        sync::daemon_worker(),
        // Periodic per-peer rotation. The base sync worker's leader rule keeps
        // a higher-endpoint daemon quiet for new rounds, so the supervisor
        // claims one of its higher-endpoint peers per tick and starts a sync
        // round against that peer in fair rotation. Slow peers fail their own
        // turn without starving the rest of the rotation.
        peer_supervisor::daemon_worker(),
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
        assert!(names.contains(&"bootstrap_serve"));
        assert!(names.contains(&"transit_in"));
        assert!(names.contains(&"sync_tick"));
        assert!(names.contains(&"transit_out"));
        assert!(names.contains(&"peer_supervisor"));
    }

    /// Test-only DaemonWorkerContext. Workers are never actually invoked here;
    /// the list is built only to surface their `name` field.
    struct TestContext;

    impl crate::workers::common::event_pipeline::EventRegistry for TestContext {
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
        ) -> Result<crate::workers::common::event_pipeline::ProjectionOutput, String> {
            Err("not implemented".to_string())
        }

        fn record_from_canonical_in(
            &self,
            _store: &Store,
            _bytes: Vec<u8>,
            _receive: Option<crate::protocol::event_modules::types::ReceiveMetadata>,
            _provenance: Option<crate::workers::schema::TransitProvenance>,
        ) -> Result<crate::workers::common::event_pipeline::ReceivedRecord, String> {
            Err("not implemented".to_string())
        }

        fn project_record(
            &self,
            _store: &Store,
            _event: &crate::workers::common::event_pipeline::EventWithContext<'_>,
        ) -> Result<crate::workers::common::event_pipeline::ProjectionOutput, String> {
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

        fn peer_supervisor_cursor(&self) -> &peer_supervisor::PeerCursor {
            unimplemented!()
        }
    }
}

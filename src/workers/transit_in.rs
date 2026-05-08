//! Transit in worker.
//!
//! Inputs: accepted TCP frames staged as `core.network.inbound`.
//! State: local endpoint secret material and connection route facts read by the
//! protocol transit projector.
//! Step: claim up to `limit` inbound network rows, ask the protocol registry to
//! unwrap each row, and write the recovered inner bytes to `canonical.in` with
//! transit provenance. Socket accept belongs to `transport_accept`; this worker
//! handles both ordinary connection frames and invite-bootstrap frames.
//! Outputs: `canonical.in` rows for the event admission worker.
//! Consume: accepted network rows are deleted after their projection rows are
//! written; rejected rows are deleted so malformed transport bytes do not poison
//! future worker turns.
//! Failure: unwrap/authentication/projection errors stop the turn after the bad
//! network row is consumed. The resulting `canonical.in` rows are not decoded
//! or semantically admitted here.
//! Fairness: `Work::Drain { limit }` bounds queue drains.

use crate::core::daemon::{StepContext, Worker};
use crate::core::store::Store;
use crate::workers::pipeline_helpers::event_pipeline::{
    self as pipeline, EventRegistry, TransitInReport,
};
use crate::workers::DaemonWorkerContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    Drain { limit: usize },
}

pub fn run<R>(store: &Store, registry: &R, work: Work) -> Result<TransitInReport, String>
where
    R: EventRegistry,
{
    match work {
        Work::Drain { limit } => pipeline::drain_transit_in(store, registry, limit),
    }
}

pub(crate) fn daemon_worker<C>() -> Worker<C>
where
    C: DaemonWorkerContext,
{
    Worker {
        name: "transit_in",
        run: daemon_step::<C>,
    }
}

fn daemon_step<C>(ctx: &mut StepContext<'_, C>) -> Result<(), String>
where
    C: DaemonWorkerContext,
{
    let app = &*ctx.app;
    // The accept worker owns sockets. transit_in is the drain step that consumes
    // already-staged inbound network rows and applies transit authentication.
    let report = run(
        app.store(),
        app,
        Work::Drain {
            limit: ctx.options.work_limit,
        },
    )
    .map_err(|err| format!("drain transit in: {err}"))?;
    ctx.report.add("transit_frames", report.network_frames);
    ctx.report.add("canonical_in", report.canonical_rows);
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::core::network_queues::{self, InboundNetworkRow, NetworkSource};
    use crate::protocol::event_modules::connection::{schema, transit, types};
    use crate::protocol::event_modules::identity::{endpoint, invite};
    use crate::protocol::Protocol;
    use crate::workers::schema as worker_schema;

    use super::*;

    fn keypair() -> endpoint::types::EndpointKeypair {
        endpoint::commands::create_local_keypair().value
    }

    #[test]
    fn drains_network_frames_into_canonical_in_without_admitting_inner_event() {
        let local = keypair();
        let remote = keypair();
        let connection_id: types::ConnectionId = [3; 32];
        let store = Protocol::open_memory_store().expect("open store");
        let mut rows = endpoint::projector::local_endpoint(local);
        rows.push(schema::connection_row(connection_id, remote.endpoint));
        store
            .insert_table_rows(rows)
            .expect("insert connection rows");
        let inner = b"inner canonical bytes".to_vec();
        let frame = transit::commands::create_connection_batch(
            &remote,
            local.endpoint,
            connection_id,
            vec![inner.clone()],
        )
        .expect("create transit frame");
        let inbound = InboundNetworkRow::new(
            NetworkSource::new("127.0.0.1:41001".parse().expect("source addr")),
            frame,
        );
        network_queues::enqueue_inbound(&store, &[inbound]).expect("enqueue inbound frame");

        let report =
            run(&store, &Protocol::new(), Work::Drain { limit: 1 }).expect("drain transit in");

        assert_eq!(report.network_frames, 1);
        assert_eq!(report.canonical_rows, 1);
        assert_eq!(
            store
                .table_row_count(network_queues::INBOUND_TABLE)
                .expect("count inbound"),
            0,
            "transit_in consumes accepted network rows"
        );
        let queued = worker_schema::claim_canonical_in(&store, 1).expect("claim canonical in");
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].canonical_bytes, inner);
        assert!(
            queued[0].provenance.is_some(),
            "canonical admission receives transit provenance as queue metadata"
        );
    }

    #[test]
    fn drains_invite_bootstrap_frames_through_the_same_inbound_queue() {
        let local = keypair();
        let remote = keypair();
        let bootstrap_secret = [7; 32];
        let bootstrap_hash = invite::types::bootstrap_secret_hash(&bootstrap_secret);
        let workspace_id = [8; 32];
        let invite_event_id = [9; 32];
        let store = Protocol::open_memory_store().expect("open store");
        let mut rows = endpoint::projector::local_endpoint(local);
        rows.extend(invite::projector::invite_secret(
            bootstrap_hash,
            bootstrap_secret,
            Some(workspace_id),
            Some(invite_event_id),
        ));
        store.insert_table_rows(rows).expect("insert local rows");
        let first = b"first identity bytes".to_vec();
        let second = b"second identity bytes".to_vec();
        let frame = transit::commands::create_invite_bootstrap_batch(
            &remote,
            local.endpoint,
            &bootstrap_secret,
            workspace_id,
            invite_event_id,
            vec![first.clone(), second.clone()],
        )
        .expect("create invite bootstrap frame");
        let inbound = InboundNetworkRow::new(
            NetworkSource::new("127.0.0.1:41002".parse().expect("source addr")),
            frame,
        );
        network_queues::enqueue_inbound(&store, &[inbound]).expect("enqueue inbound frame");

        let report =
            run(&store, &Protocol::new(), Work::Drain { limit: 1 }).expect("drain transit in");

        assert_eq!(report.network_frames, 1);
        assert_eq!(report.canonical_rows, 2);
        assert_eq!(
            store
                .table_row_count(network_queues::INBOUND_TABLE)
                .expect("count inbound"),
            0,
            "invite bootstrap frames are consumed by the normal transit_in drain"
        );
        let mut queued = worker_schema::claim_canonical_in(&store, 2).expect("claim canonical in");
        queued.sort_by(|left, right| left.canonical_bytes.cmp(&right.canonical_bytes));
        assert_eq!(queued[0].canonical_bytes, first);
        assert_eq!(queued[1].canonical_bytes, second);
        for row in queued {
            let provenance = row.provenance.expect("invite bootstrap provenance");
            assert_eq!(provenance.local_endpoint, local.endpoint);
            assert_eq!(provenance.sender_endpoint, remote.endpoint);
            assert_eq!(
                provenance.unwrapped_with,
                worker_schema::TransitUnwrap::InviteBootstrap {
                    bootstrap_hash,
                    workspace_id,
                    invite_event_id,
                }
            );
        }
    }
}

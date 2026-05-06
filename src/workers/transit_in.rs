//! Transit in worker.
//!
//! Inputs: accepted TCP frames staged as `core.network.inbound`.
//! State: local endpoint secret material and connection route facts read by the
//! protocol transit projector.
//! Step: accept at most one available TCP stream, claim up to `limit` inbound
//! network rows, ask the protocol registry to unwrap each row, and write the
//! recovered inner bytes to `canonical.in` with transit provenance.
//! Outputs: `canonical.in` rows for the event admission worker.
//! Consume: accepted network rows are deleted after their projection rows are
//! written; rejected rows are deleted so malformed transport bytes do not poison
//! future worker turns.
//! Failure: unwrap/authentication/projection errors stop the turn after the bad
//! network row is consumed. The resulting `canonical.in` rows are not decoded
//! or semantically admitted here.
//! Fairness: `Work::Drain { limit }` bounds queue drains; TCP accept handles at
//! most one available stream per daemon call.

use crate::core::daemon::{StepContext, Worker};
use crate::core::store::Store;
use crate::workers::common_event_pipeline::{self as pipeline, EventRegistry, TransitInReport};
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
    let accept = ctx.listener.accept_available(app.store())?;
    ctx.report
        .add("accepted_connections", accept.accepted_connections);
    ctx.report
        .add("received_frames", accept.value.received_frames);
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
    use crate::protocol::event_modules::identity::endpoint;
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
}

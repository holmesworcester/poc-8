//! Transit in worker.
//!
//! Inputs: accepted TCP streams and queued `core.network.inbound` frames.
//! State: local endpoint secret material and connection route facts read by the
//! protocol transit projector.
//! Step: accept at most one available stream, or claim up to `limit` queued
//! inbound rows, ask the protocol registry to unwrap each row, and write the
//! recovered inner bytes to `canonical.in` with transit provenance.
//! Outputs: `canonical.in` rows for the event admission worker. Normal sync is
//! scheduled by the sync/transit-out workers on later daemon turns. Connection
//! bootstrap responses are scheduled by the connection worker, not by transit
//! receive.
//! Consume: accepted or queued network rows are deleted after their projection
//! rows are written; rejected rows are deleted so malformed transport bytes do
//! not poison future worker turns.
//! Failure: unwrap/authentication/projection errors stop the turn after the bad
//! network row is consumed. The resulting `canonical.in` rows are not decoded
//! or semantically admitted here.
//! Fairness: `Work::Drain { limit }` bounds queue drains; stream accept handles
//! at most one TCP stream per daemon turn.

use std::net::SocketAddr;

use crate::core::daemon::{StepContext, Worker};
use crate::core::store::Store;
use crate::core::tcp;
use crate::protocol::event_modules::sync::SyncIndex;
use crate::workers::pipeline_helpers::event_pipeline::{
    self as pipeline, EventRegistry, TransitInReport,
};
use crate::workers::DaemonWorkerContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    Drain {
        limit: usize,
    },
    Serve {
        listen: SocketAddr,
        accept_count: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    Drained(TransitInReport),
    Served(ServeReport),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeReport {
    pub local_addr: SocketAddr,
    pub accepted_connections: usize,
    pub received_events: usize,
}

pub fn run<R>(
    store: &Store,
    registry: &R,
    _sync_index: Option<&SyncIndex>,
    work: Work,
) -> Result<Output, String>
where
    R: EventRegistry,
{
    match work {
        Work::Drain { limit } => {
            pipeline::drain_transit_in(store, registry, limit).map(Output::Drained)
        }
        Work::Serve {
            listen,
            accept_count,
        } => serve(store, registry, _sync_index, listen, accept_count).map(Output::Served),
    }
}

fn serve<R>(
    store: &Store,
    registry: &R,
    _sync_index: Option<&SyncIndex>,
    listen: SocketAddr,
    accept_count: usize,
) -> Result<ServeReport, String>
where
    R: EventRegistry,
{
    let report = tcp::serve_inbound(store, listen, accept_count)?;
    let _ = pipeline::drain_transit_in(store, registry, accept_count.max(1))?;
    Ok(ServeReport {
        local_addr: report.local_addr,
        accepted_connections: report.accepted_connections,
        received_events: report.value.received_frames,
    })
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
        .add("received_events", accept.value.received_frames);

    let report = match run(
        app.store(),
        app,
        None,
        Work::Drain {
            limit: ctx.options.work_limit,
        },
    )
    .map_err(|err| format!("drain transit in: {err}"))?
    {
        Output::Drained(report) => report,
        Output::Served(_) => return Err("transit_in worker returned non-drain output".to_string()),
    };
    ctx.report.add("transit_frames", report.network_frames);
    ctx.report.add("canonical_in", report.canonical_rows);
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::core::network_queues::{self, InboundNetworkRow, NetworkSource};
    use crate::protocol::event_modules::connection::{
        connection_request, connection_response, schema, transit, types,
    };
    use crate::protocol::event_modules::identity::{endpoint, invite};
    use crate::protocol::Protocol;
    use crate::workers::pipeline_helpers::event_pipeline as pipeline;
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
        let connection = connection_response::types::ResponseEvent {
            from_endpoint: remote.endpoint,
            to_endpoint: local.endpoint,
            request_id: [9; 32],
            invite_secret_event_id: [8; 32],
            initiator_ephemeral_secret_event_id: [7; 32],
            responder_ephemeral_secret_event_id: [6; 32],
            responder_ephemeral_public_key: [5; 32],
            handshake_hash: [4; 32],
            connection_secret: [5; 32],
        };
        let mut rows = endpoint::projector::local_endpoint(local);
        rows.push(schema::connection_row(connection_id, remote.endpoint));
        rows.push(schema::connection_event_row(
            connection_id,
            connection_response::codec::encode(&connection),
        ));
        store
            .insert_table_rows(rows)
            .expect("insert connection rows");
        let inner = b"inner canonical bytes".to_vec();
        let frame = transit::commands::create_connection_batch(
            remote.endpoint,
            local.endpoint,
            connection_id,
            &connection.connection_secret,
            vec![inner.clone()],
        )
        .expect("create transit frame");
        let inbound = InboundNetworkRow::new(
            NetworkSource::new("127.0.0.1:41001".parse().expect("source addr")),
            frame,
        );
        network_queues::enqueue_inbound(&store, &[inbound]).expect("enqueue inbound frame");

        let report = match run(&store, &Protocol::new(), None, Work::Drain { limit: 1 })
            .expect("drain transit in")
        {
            Output::Drained(report) => report,
            Output::Served(_) => panic!("expected drain output"),
        };

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
    fn bootstrap_request_drain_uses_canonical_queue_boundary() {
        let alice = keypair();
        let bob = keypair();
        let store = Protocol::open_memory_store().expect("open store");
        let protocol = Protocol::new();
        store
            .insert_table_rows(endpoint::projector::local_endpoint(alice))
            .expect("insert alice endpoint");
        let invite_output =
            invite::commands::create(alice, "127.0.0.1:41000".parse().expect("invite addr"));
        let invite_link = invite_output.value.clone();
        pipeline::run(&store, &protocol, invite_output).expect("admit invite secret");
        let stale = invite::codec::record_from_bytes(invite::codec::encode(
            &invite::types::InviteSecretEvent::new([99; 32]),
        ))
        .expect("stale canonical record");
        store
            .insert_table_rows(vec![worker_schema::canonical_in_row(stale, None)])
            .expect("insert stale canonical row");
        let request = connection_request::commands::create(
            bob,
            &invite_link,
            Some("127.0.0.1:41001".parse().expect("bob listen")),
        )
        .expect("create request");
        let request_id = request.value.request_id;
        let request_bytes = request.events[2].record().canonical_bytes.clone();
        let frame =
            crate::protocol::event_modules::connection::transit::commands::create_bootstrap(
                &bob,
                alice.endpoint,
                &request_bytes,
            )
            .expect("bootstrap frame");
        let inbound = InboundNetworkRow::new(
            NetworkSource::new("127.0.0.1:41001".parse().expect("source addr")),
            frame,
        );
        network_queues::enqueue_inbound(&store, &[inbound]).expect("enqueue inbound frame");

        let report = match run(&store, &protocol, None, Work::Drain { limit: 1 })
            .expect("drain transit frame")
        {
            Output::Drained(report) => report,
            Output::Served(_) => panic!("expected drain output"),
        };

        assert_eq!(report.network_frames, 1);
        assert_eq!(report.canonical_rows, 1);
        assert_eq!(
            store
                .table_row_count(worker_schema::CANONICAL_IN)
                .expect("count canonical queue"),
            2,
            "transit_in adds recovered bytes to canonical.in without directly admitting them"
        );

        let admitted = pipeline::drain_canonical_in(&store, &protocol, 2)
            .expect("admit queued canonical events");
        assert_eq!(admitted.inserted_events, 2);
        assert_eq!(
            store
                .table_row(schema::PENDING_CONNECTION_RESPONSES, &request_id)
                .expect("pending response row"),
            Some("127.0.0.1:41001".as_bytes().to_vec())
        );
        assert_eq!(
            store
                .table_row_count(worker_schema::CANONICAL_IN)
                .expect("count canonical queue"),
            0,
            "admission, not transit_in, consumes canonical queue rows"
        );
    }
}

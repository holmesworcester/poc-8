//! Transit in worker.
//!
//! Inputs: accepted TCP streams and any already-staged `core.network.inbound`
//! rows.
//! State: local endpoint secret material and connection route facts read by the
//! protocol transit projector.
//! Step: accept at most one available daemon stream, stage each frame as a core
//! inbound row, unwrap/admit it, and write same-stream invite-bootstrap or
//! connection sync responses when needed. It can also claim up to `limit`
//! already-staged inbound rows for tests and retry paths.
//! Outputs: `canonical.in` rows, admitted events, and optional same-stream
//! response frames.
//! Consume: accepted network rows are deleted after their projection rows are
//! written; rejected rows are deleted so malformed transport bytes do not poison
//! future worker turns.
//! Failure: unwrap/authentication/projection/admission errors stop the turn
//! after the bad network row is consumed. Accepted rows have already passed
//! through the same admission path as queued inbound transit.
//! Fairness: `Work::Drain { limit }` bounds queue drains.

use std::{cell::RefCell, collections::HashMap, collections::HashSet, net::SocketAddr};

use crate::core::daemon::{StepContext, Worker};
use crate::core::network_queues::{self, InboundNetworkRow, NetworkTarget, OutboundNetworkRow};
use crate::core::store::Store;
use crate::core::tcp;
use crate::protocol::event_modules::connection::types::ConnectionId;
use crate::protocol::event_modules::connection::{
    connection_request, connection_response, transit,
};
use crate::protocol::event_modules::identity::{endpoint, invite};
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::types::EventId;
use crate::workers::pipeline_helpers::event_pipeline::{
    self as pipeline, CanonicalInProjection, DrainUntilIdle, EventRegistry, TransitInReport,
};
use crate::workers::{
    event_admission, schema as worker_schema, sync, transit_out, DaemonWorkerContext,
};

const READY_BATCH: usize = pipeline::DEFAULT_READY_BATCH;

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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct InboundExchangeOutput {
    pub canonical_rows: usize,
    pub received_events: usize,
    pub connection_ids: Vec<ConnectionId>,
    pub outbound_rows: Vec<OutboundNetworkRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InviteListenReport {
    pub local_addr: SocketAddr,
    pub accepted_connections: usize,
    pub canonical_rows: usize,
    pub received_events: usize,
    pub sent_frames: usize,
}

#[derive(Debug, Clone)]
struct InviteBootstrapReply {
    sender_endpoint: endpoint::types::EndpointId,
    bootstrap_hash: EventId,
    workspace_id: EventId,
    invite_event_id: EventId,
}

pub(crate) fn process_inbound_exchange<R>(
    store: &Store,
    registry: &R,
    inbound: InboundNetworkRow,
) -> Result<InboundExchangeOutput, String>
where
    R: EventRegistry,
{
    let target = NetworkTarget::new(inbound.source.addr());
    let admission = event_admission::transit_admission_registry(registry);
    let admitted = pipeline::project_network_in_and_admit(store, &admission, inbound, READY_BATCH)?;
    let decoded = admitted.canonical_rows;
    let reply = invite_bootstrap_reply(store, &decoded)?;
    let mut connection_ids = decoded_connection_ids(&decoded);
    connection_ids.extend(admitted_connection_response_ids(
        store,
        &decoded,
        &admitted.admitted.event_ids,
    )?);
    let connection_responses =
        connection_response_frames(store, registry, &decoded, &admitted.admitted.event_ids)?;
    connection_ids.extend(connection_responses.connection_ids);
    let frames = match reply {
        Some(reply) => {
            invite_bootstrap_response_frames(store, reply, &admitted.admitted.event_ids)?
        }
        None => Vec::new(),
    };
    let mut frames = frames;
    frames.extend(connection_responses.frames);
    Ok(InboundExchangeOutput {
        canonical_rows: decoded.len(),
        received_events: admitted.admitted.event_ids.len(),
        connection_ids,
        outbound_rows: network_queues::outbound_rows(target, frames),
    })
}

pub(crate) fn process_inbound_exchange_with_same_stream_sync<R>(
    store: &Store,
    registry: &R,
    index: &crate::protocol::event_modules::sync::SyncIndex,
    inbound: InboundNetworkRow,
    sent_transit_out: &RefCell<HashMap<Vec<u8>, Vec<Vec<u8>>>>,
) -> Result<InboundExchangeOutput, String>
where
    R: EventRegistry,
{
    let target = NetworkTarget::new(inbound.source.addr());
    let mut output = process_inbound_exchange(store, registry, inbound)?;
    let sync_out = drain_same_stream_sync(store, registry, index, target, &output.connection_ids)?;
    if !sync_out.outbound_rows.is_empty() {
        transit_out::remember_sent_rows(
            sent_transit_out,
            &sync_out.outbound_rows,
            &sync_out.sent_transit_out,
        )?;
        output.outbound_rows.extend(sync_out.outbound_rows);
    }
    Ok(output)
}

pub(crate) fn serve_invite_listener<R>(
    store: &Store,
    registry: &R,
    index: &crate::protocol::event_modules::sync::SyncIndex,
    listen: SocketAddr,
    accept_count: usize,
) -> Result<InviteListenReport, String>
where
    R: EventRegistry,
{
    let report = tcp::serve(
        store,
        listen,
        accept_count,
        InviteListenState::default(),
        |inbound, state| {
            let output = process_inbound_exchange_with_same_stream_sync(
                store,
                registry,
                index,
                inbound,
                &state.sent_transit_out,
            )?;
            state.canonical_rows += output.canonical_rows;
            state.received_events += output.received_events;
            Ok(output.outbound_rows)
        },
        |rows, state| {
            state.sent_frames += rows.len();
            transit_out::mark_sent_network_rows(store, rows, &state.sent_transit_out)
        },
    )?;
    Ok(InviteListenReport {
        local_addr: report.local_addr,
        accepted_connections: report.accepted_connections,
        canonical_rows: report.value.canonical_rows,
        received_events: report.value.received_events,
        sent_frames: report.value.sent_frames,
    })
}

#[derive(Debug, Default)]
struct InviteListenState {
    canonical_rows: usize,
    received_events: usize,
    sent_frames: usize,
    sent_transit_out: RefCell<HashMap<Vec<u8>, Vec<Vec<u8>>>>,
}

fn decoded_connection_ids(decoded: &[CanonicalInProjection]) -> Vec<ConnectionId> {
    let mut out = Vec::new();
    for row in decoded {
        let Some(provenance) = row.provenance else {
            continue;
        };
        let worker_schema::TransitUnwrap::Connection { connection_id } = provenance.unwrapped_with
        else {
            continue;
        };
        if !out.iter().any(|known| known == &connection_id) {
            out.push(connection_id);
        }
    }
    out
}

fn admitted_connection_response_ids(
    store: &Store,
    decoded: &[CanonicalInProjection],
    admitted_event_ids: &[EventId],
) -> Result<Vec<ConnectionId>, String> {
    let admitted = admitted_event_ids.iter().copied().collect::<HashSet<_>>();
    let mut out = Vec::new();
    for row in decoded {
        if !connection_response::codec::is_response(&row.canonical_bytes) {
            continue;
        }
        let connection_id = crate::protocol::event_modules::types::event_id(&row.canonical_bytes);
        if !admitted.contains(&connection_id) || out.iter().any(|known| known == &connection_id) {
            continue;
        }
        if event_schema::applied_event_bytes(store, &connection_id)
            .map_err(|err| format!("load connection event: {err}"))?
            .is_some()
        {
            out.push(connection_id);
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ConnectionResponseFrames {
    frames: Vec<Vec<u8>>,
    connection_ids: Vec<ConnectionId>,
}

fn connection_response_frames<R>(
    store: &Store,
    registry: &R,
    decoded: &[CanonicalInProjection],
    admitted_event_ids: &[EventId],
) -> Result<ConnectionResponseFrames, String>
where
    R: EventRegistry,
{
    let admitted = admitted_event_ids.iter().copied().collect::<HashSet<_>>();
    let local = local_endpoint(store)?;
    let mut out = ConnectionResponseFrames::default();
    for row in decoded {
        let Some(provenance) = row.provenance else {
            continue;
        };
        if provenance.unwrapped_with != worker_schema::TransitUnwrap::Bootstrap {
            continue;
        }
        if !connection_request::codec::is_request(&row.canonical_bytes) {
            continue;
        }
        let request_id = crate::protocol::event_modules::types::event_id(&row.canonical_bytes);
        if !admitted.contains(&request_id) {
            continue;
        }
        if event_schema::applied_event_bytes(store, &request_id)
            .map_err(|err| format!("load connection request event: {err}"))?
            .is_none()
        {
            continue;
        }
        let request = connection_request::codec::decode(&row.canonical_bytes)?;
        let response = connection_response::commands::create(local, request_id, request)?;
        let (response, _) = pipeline::run(store, registry, response)
            .map_err(|err| format!("record connection response: {err}"))?;
        pipeline::run(
            store,
            registry,
            DrainUntilIdle {
                batch_size: READY_BATCH,
            },
        )?;
        out.connection_ids.push(response.connection_id);
        out.frames.push(response.bytes);
    }
    Ok(out)
}

fn invite_bootstrap_reply(
    store: &Store,
    decoded: &[CanonicalInProjection],
) -> Result<Option<InviteBootstrapReply>, String> {
    for row in decoded {
        let Some(provenance) = row.provenance else {
            continue;
        };
        let worker_schema::TransitUnwrap::InviteBootstrap {
            bootstrap_hash,
            workspace_id,
            invite_event_id,
        } = provenance.unwrapped_with
        else {
            continue;
        };
        if event_schema::has_event(store, &invite_event_id)
            .map_err(|err| format!("check local invite event: {err}"))?
        {
            return Ok(Some(InviteBootstrapReply {
                sender_endpoint: provenance.sender_endpoint,
                bootstrap_hash,
                workspace_id,
                invite_event_id,
            }));
        }
    }
    Ok(None)
}

fn invite_bootstrap_response_frames(
    store: &Store,
    reply: InviteBootstrapReply,
    exclude_event_ids: &[EventId],
) -> Result<Vec<Vec<u8>>, String> {
    let local = local_endpoint(store)?;
    let invite_secret = invite::schema::invite_secret_by_hash(store, &reply.bootstrap_hash)?;
    if invite_secret.workspace_id != Some(reply.workspace_id)
        || invite_secret.invite_event_id != Some(reply.invite_event_id)
    {
        return Err("invite bootstrap reply key is not scoped to envelope invite".to_string());
    }
    let exclude_event_ids = exclude_event_ids.iter().copied().collect::<HashSet<_>>();
    let inners =
        workspace_identity_bootstrap_event_bytes(store, reply.workspace_id, &exclude_event_ids)?;
    if inners.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![transit::commands::create_invite_bootstrap_batch(
        &local,
        reply.sender_endpoint,
        &invite_secret.bootstrap_secret,
        reply.workspace_id,
        reply.invite_event_id,
        inners,
    )?])
}

fn workspace_identity_bootstrap_event_bytes(
    store: &Store,
    workspace_id: EventId,
    exclude_event_ids: &HashSet<EventId>,
) -> Result<Vec<Vec<u8>>, String> {
    let entries = event_schema::event_index_entries_in_timestamp_range(store, 0, u64::MAX)
        .map_err(|err| format!("load workspace identity events: {err}"))?;
    let mut out = Vec::new();
    for entry in entries {
        if exclude_event_ids.contains(&entry.event_id) {
            continue;
        }
        if entry.workspace_id != Some(workspace_id) {
            continue;
        }
        let Some(bytes) = event_schema::event_bytes(store, &entry.event_id)
            .map_err(|err| format!("load workspace identity event bytes: {err}"))?
        else {
            continue;
        };
        if event_admission::is_identity_bootstrap_event(&bytes)? {
            out.push(bytes);
        }
    }
    Ok(out)
}

fn local_endpoint(store: &Store) -> Result<endpoint::types::EndpointKeypair, String> {
    endpoint::commands::local_keypair(store)?.ok_or_else(|| "local endpoint is missing".to_string())
}

fn drain_same_stream_sync<R>(
    store: &Store,
    registry: &R,
    index: &crate::protocol::event_modules::sync::SyncIndex,
    target: NetworkTarget,
    connection_ids: &[ConnectionId],
) -> Result<SameStreamSyncOut, String>
where
    R: EventRegistry,
{
    let mut out = SameStreamSyncOut::default();
    for connection_id in connection_ids {
        let output = sync::run(
            store,
            index,
            sync::Work::DrainConnectionIn {
                connection_id: *connection_id,
                limit: READY_BATCH,
            },
        )?;
        let sync::Output::DrainedIn(report) = output else {
            return Err("sync worker returned non-drain output".to_string());
        };
        if !report.events.is_empty() {
            pipeline::run(
                store,
                registry,
                pipeline::CommandOutput::with_events((), report.events),
            )?;
            pipeline::run(
                store,
                registry,
                DrainUntilIdle {
                    batch_size: READY_BATCH,
                },
            )?;
        }
        let drained = transit_out::drain_and_wrap_connection_out(store, *connection_id)?;
        if drained.outgoing.is_empty() {
            continue;
        }
        out.sent_transit_out.extend(drained.sent_transit_out);
        out.outbound_rows
            .extend(network_queues::outbound_rows(target, drained.outgoing));
    }
    Ok(out)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SameStreamSyncOut {
    outbound_rows: Vec<OutboundNetworkRow>,
    sent_transit_out: Vec<Vec<Vec<u8>>>,
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
    let store = app.store();
    let accepted = ctx
        .listener
        .accept_exchange_available(
            store,
            TransitAcceptState::default(),
            |inbound, state| {
                state.stream.received_frames += 1;
                let output = process_inbound_exchange_with_same_stream_sync(
                    store,
                    app,
                    app.sync_index(),
                    inbound,
                    &state.sent_transit_out,
                )?;
                state.canonical_rows += output.canonical_rows;
                state.received_events += output.received_events;
                Ok(output.outbound_rows)
            },
            |rows, state| {
                state.stream.sent_frames += rows.len();
                transit_out::mark_sent_network_rows(store, rows, &state.sent_transit_out)
            },
        )
        .map_err(|err| format!("accept transit stream: {err}"))?;
    ctx.report
        .add("accepted_connections", accepted.accepted_connections);
    ctx.report
        .add("received_frames", accepted.value.stream.received_frames);
    ctx.report
        .add("sent_frames", accepted.value.stream.sent_frames);
    ctx.report
        .add("canonical_in", accepted.value.canonical_rows);
    ctx.report
        .add("admitted_events", accepted.value.received_events);

    let drained = run(
        app.store(),
        app,
        Work::Drain {
            limit: ctx.options.work_limit,
        },
    )
    .map_err(|err| format!("drain transit in: {err}"))?;
    ctx.report.add("transit_frames", drained.network_frames);
    ctx.report.add("canonical_in", drained.canonical_rows);
    Ok(())
}

#[derive(Debug, Default)]
struct TransitAcceptState {
    stream: crate::core::tcp::StreamReport,
    canonical_rows: usize,
    received_events: usize,
    sent_transit_out: RefCell<HashMap<Vec<u8>, Vec<Vec<u8>>>>,
}

#[cfg(test)]
mod tests {
    use crate::core::network_queues::{self, InboundNetworkRow, NetworkSource};
    use crate::protocol::event_modules::connection::{connection_response, schema, transit, types};
    use crate::protocol::event_modules::identity::{endpoint, endpoint_shared, invite, workspace};
    use crate::protocol::event_modules::schema as event_schema;
    use crate::protocol::event_modules::sync::{compare, have_id};
    use crate::protocol::event_modules::types::{EventId, EventStatus};
    use crate::protocol::event_modules::worker as event_worker;
    use crate::protocol::Protocol;
    use crate::workers::schema as worker_schema;

    use super::*;

    fn keypair() -> endpoint::types::EndpointKeypair {
        endpoint::commands::create_local_keypair().value
    }

    fn endpoint_membership_row(
        workspace_id: EventId,
        endpoint_id: EventId,
        signing_public_key: EventId,
    ) -> crate::core::store::TableRow {
        endpoint_shared::schema::endpoint_membership_row(
            [7; 32],
            [8; 32],
            &endpoint_shared::types::EndpointSharedEvent {
                created_at_ms: 1,
                workspace_id,
                user_authority_event_id: [9; 32],
                endpoint_id,
                signing_public_key,
                endpoint_role: endpoint::types::EndpointRole::Device,
                device_name: "device".to_string(),
            },
        )
    }

    #[test]
    fn drains_network_frames_into_canonical_in_without_admitting_inner_event() {
        let local = keypair();
        let remote = keypair();
        let connection = connection_response::types::ResponseEvent {
            from_endpoint: local.endpoint,
            to_endpoint: remote.endpoint,
            request_id: [2; 32],
            traffic_secret: [4; 32],
        };
        let connection_bytes = connection_response::codec::encode(&connection);
        let connection_id: types::ConnectionId = types::event_id(&connection_bytes);
        let connection_record =
            connection_response::codec::record_from_bytes(connection_bytes.clone())
                .expect("connection record");
        let store = Protocol::open_memory_store().expect("open store");
        let mut rows = endpoint::projector::local_endpoint(local);
        rows.extend([
            event_schema::event_row(&connection_id, &connection_record, EventStatus::Applied)
                .expect("connection event row"),
            schema::connection_row(connection_id, remote.endpoint),
        ]);
        store
            .insert_table_rows(rows)
            .expect("insert connection rows");
        let inner = b"inner canonical bytes".to_vec();
        let frame = transit::commands::create_connection_batch(
            remote.endpoint,
            &connection,
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

    #[test]
    fn same_stream_connection_compare_produces_sync_response_frames() {
        let local = keypair();
        let remote = keypair();
        let connection = connection_response::types::ResponseEvent {
            from_endpoint: local.endpoint,
            to_endpoint: remote.endpoint,
            request_id: [2; 32],
            traffic_secret: [4; 32],
        };
        let connection_bytes = connection_response::codec::encode(&connection);
        let connection_id: types::ConnectionId = types::event_id(&connection_bytes);
        let connection_record =
            connection_response::codec::record_from_bytes(connection_bytes.clone())
                .expect("connection record");
        let store = Protocol::open_memory_store().expect("open store");
        let protocol = Protocol::new();
        let workspace = workspace::commands::create(workspace::commands::CreateWorkspace {
            created_at_ms: 1,
            public_key: [10; 32],
            name: "same-stream-sync".to_string(),
        })
        .expect("create workspace");
        let workspace_id = workspace.value.workspace_id;
        event_worker::run(&store, &protocol, workspace).expect("admit workspace");
        let mut rows = endpoint::projector::local_endpoint(local);
        rows.extend([
            event_schema::event_row(&connection_id, &connection_record, EventStatus::Applied)
                .expect("connection event row"),
            schema::connection_row(connection_id, remote.endpoint),
            endpoint_membership_row(workspace_id, local.endpoint, local.signing_public_key),
            endpoint_membership_row(workspace_id, remote.endpoint, remote.signing_public_key),
        ]);
        store
            .insert_table_rows(rows)
            .expect("insert same-stream sync context");
        assert_eq!(
            endpoint_shared::schema::mutual_workspace_ids(&store, local.endpoint, remote.endpoint)
                .expect("mutual workspaces"),
            vec![workspace_id]
        );
        let index_entries =
            event_schema::event_index_entries_in_timestamp_range(&store, 0, u64::MAX)
                .expect("index entries");
        assert_eq!(index_entries.len(), 1);
        assert_eq!(index_entries[0].workspace_id, Some(workspace_id));
        let compare = compare::types::CompareEvent {
            connection_id,
            range: compare::types::TimestampRange::ROOT,
            summary: compare::types::RangeSummary {
                count: 2,
                fingerprint: [5; 32],
            },
            response_requested: true,
        };
        let frame = transit::commands::create_connection_batch(
            remote.endpoint,
            &connection,
            connection_id,
            vec![compare::codec::encode(&compare)],
        )
        .expect("create compare transit frame");
        let inbound = InboundNetworkRow::new(
            NetworkSource::new("127.0.0.1:41003".parse().expect("source addr")),
            frame,
        );

        let output = process_inbound_exchange_with_same_stream_sync(
            &store,
            &protocol,
            protocol.sync_index(),
            inbound,
            &RefCell::new(HashMap::new()),
        )
        .expect("process inbound compare");

        assert_eq!(output.canonical_rows, 1);
        assert_eq!(output.connection_ids, vec![connection_id]);
        assert!(
            !output.outbound_rows.is_empty(),
            "incoming compare over a real connection should receive same-stream sync responses"
        );
        let outgoing = event_schema::all_applied_event_bytes(&store).expect("load events");
        let event_types = store
            .table_rows(event_schema::EVENTS)
            .expect("event rows")
            .into_iter()
            .map(|(_, value)| {
                (
                    value.get(17).copied().unwrap_or_default(),
                    value.get(52).copied().unwrap_or_default(),
                )
            })
            .collect::<Vec<_>>();
        assert!(
            outgoing.iter().any(|bytes| have_id::codec::is_event(bytes)),
            "same-stream response should admit outgoing have-id events before wrapping them; outbound_rows: {}; event types: {event_types:?}",
            output.outbound_rows.len()
        );
    }
}

//! Socket exchange for invite bootstrap and direct connection requests.
//!
//! This worker owns the small amount of active TCP behavior needed before a
//! steady-state connection route exists. It does not own event meaning. Every
//! inbound frame is first unwrapped by the transit projector, then the recovered
//! canonical bytes are admitted through the common event pipeline.
//!
//! Realm of responsibility:
//!
//! - send unscoped invite connection requests for the `connect` CLI path
//! - send one invite-key batch for identity invite acceptance
//! - accept daemon or finite-listener streams and admit their frames
//! - reply to an invite-key batch only when this store already owns the invite
//!   event named by the envelope, using one batch for the current workspace
//!   identity bootstrap set excluding the acceptor's just-submitted events
//!
//! Non-responsibility:
//!
//! - it does not authorize workspace events by connection id
//! - it does not project identity rows directly
//! - it does not send content or sync history during bootstrap
//! - it does not decide that a normal connection exists
//!
//! The key invariant is per-event bootstrap authorization:
//!
//! ```text
//! workspace <=> invite-derived transit key used <=> canonical event bytes
//! ```
//!
//! The envelope proves the invite key and workspace. The event pipeline still
//! proves the event's own dependencies and projector invariants.

use std::collections::HashSet;
use std::net::SocketAddr;

use crate::core::daemon::{StepContext, Worker};
use crate::core::network_queues::{self, InboundNetworkRow, NetworkTarget, OutboundNetworkRow};
use crate::core::store::Store;
use crate::core::tcp;
use crate::protocol::event_modules::connection::{connection_request, schema, transit, types};
use crate::protocol::event_modules::identity::{endpoint, invite, invite_accepted};
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::types::{event_id, EventId, EventRecord};
use crate::workers::pipeline_helpers::event_pipeline::{
    self as pipeline, DrainUntilIdle, EventRegistry, ProjectionOutput,
};
use crate::workers::{event_admission, schema as worker_schema, DaemonWorkerContext};

const READY_BATCH: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Work {
    ConnectInvite {
        invite: String,
        /// Caller-provided steady-state listen address to advertise inside
        /// the request body. CLI dispatch reads `core::daemon::current_listen_addr`
        /// from the lock file to populate this; daemons start no `Work` with a
        /// `Some` here because they would dial peers from their own worker,
        /// and one-shot CLI accepts on a host without a daemon pass `None`.
        from_listen_addr: Option<SocketAddr>,
    },
    ConnectInviteWithInitialEvents {
        invite: String,
        records: Vec<EventRecord>,
        from_listen_addr: Option<SocketAddr>,
    },
    Serve {
        listen: SocketAddr,
        accept_count: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    Connected(types::ConnectReport),
    Served(types::ServeReport),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ExchangeState {
    sent_events: usize,
    received_events: usize,
}

#[derive(Debug, Clone)]
struct DecodedCanonical {
    provenance: Option<worker_schema::TransitProvenance>,
    canonical_bytes: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InviteBootstrapReply {
    sender_endpoint: endpoint::types::EndpointId,
    bootstrap_hash: EventId,
    workspace_id: EventId,
    invite_event_id: EventId,
}

pub fn run<R>(store: &Store, registry: &R, work: Work) -> Result<Output, String>
where
    R: EventRegistry,
{
    match work {
        Work::ConnectInvite {
            invite,
            from_listen_addr,
        } => connect_transport_invite(store, registry, invite, from_listen_addr),
        Work::ConnectInviteWithInitialEvents {
            invite,
            records,
            from_listen_addr,
        } => connect_identity_invite(store, registry, invite, records, from_listen_addr),
        Work::Serve {
            listen,
            accept_count,
        } => serve(store, registry, listen, accept_count),
    }
}

fn connect_transport_invite<R>(
    store: &Store,
    registry: &R,
    invite_link: String,
    from_listen_addr: Option<SocketAddr>,
) -> Result<Output, String>
where
    R: EventRegistry,
{
    let output =
        connection_request::commands::create_with_local(store, &invite_link, from_listen_addr)
            .map_err(|err| format!("create connection request: {err}"))?;
    let (request, _) = pipeline::run(store, registry, output)
        .map_err(|err| format!("record connection request: {err}"))?;
    store
        .insert_table_rows(vec![schema::transport_target_row(
            request.connection_id,
            request.addr,
        )])
        .map_err(|err| format!("remember connection route: {err}"))?;

    let target = NetworkTarget::new(request.addr);
    let state = tcp::connect_exchange(
        store,
        target,
        network_queues::outbound_rows(target, vec![request.bytes]),
        ExchangeState::default(),
        |inbound, state| process_inbound(store, registry, inbound, state),
        |rows, state| {
            state.sent_events += rows.len();
            Ok(())
        },
    )?;
    Ok(Output::Connected(types::ConnectReport {
        addr: request.addr,
        sent_events: state.sent_events,
        received_events: state.received_events,
    }))
}

fn connect_identity_invite<R>(
    store: &Store,
    registry: &R,
    invite_link: String,
    initial_records: Vec<EventRecord>,
    from_listen_addr: Option<SocketAddr>,
) -> Result<Output, String>
where
    R: EventRegistry,
{
    let parsed_invite = invite::commands::parse(&invite_link)?;
    if !parsed_invite.identity_scope {
        return Err("initial invite events require an identity-scoped invite".to_string());
    }
    let local = ensure_local_invite_acceptance(store, registry, &parsed_invite)?;

    // Author a connection_request and send it after the invite-bootstrap batch
    // on the same stream. The accept-side records the advertised listener via
    // `remember_advertised_listener`, which is what lets her periodic outbound
    // sync dial the acceptor back after this stream closes. A local
    // transport_target row is also written when the caller supplies a
    // listener (i.e., a daemon is running) so the acceptor's daemon can dial
    // the host directly.
    let request_output =
        connection_request::commands::create_with_local(store, &invite_link, from_listen_addr)
            .map_err(|err| format!("create connection request: {err}"))?;
    let (request, _) = pipeline::run(store, registry, request_output)
        .map_err(|err| format!("record connection request: {err}"))?;
    if from_listen_addr.is_some() {
        // Skip when no daemon is running locally — a one-shot CLI accept
        // can't reuse the route, and persisting one risks pointing at a
        // finite invite listener that exits immediately after acceptance.
        store
            .insert_table_rows(vec![schema::transport_target_row(
                request.connection_id,
                request.addr,
            )])
            .map_err(|err| format!("remember connection route: {err}"))?;
    }

    let inners = initial_bootstrap_inner_bytes(&parsed_invite, initial_records)?;
    let frame = transit::commands::create_invite_bootstrap_batch(
        &local,
        parsed_invite.endpoint,
        &parsed_invite.bootstrap_secret,
        parsed_invite.workspace_id,
        parsed_invite.invite_event_id,
        inners,
    )?;

    let target = NetworkTarget::new(parsed_invite.addr);
    let state = tcp::connect_exchange(
        store,
        target,
        network_queues::outbound_rows(target, vec![frame, request.bytes]),
        ExchangeState::default(),
        |inbound, state| process_inbound(store, registry, inbound, state),
        |rows, state| {
            state.sent_events += rows.len();
            Ok(())
        },
    )?;
    Ok(Output::Connected(types::ConnectReport {
        addr: parsed_invite.addr,
        sent_events: state.sent_events,
        received_events: state.received_events,
    }))
}

fn serve<R>(
    store: &Store,
    registry: &R,
    listen: SocketAddr,
    accept_count: usize,
) -> Result<Output, String>
where
    R: EventRegistry,
{
    let report = tcp::serve(
        store,
        listen,
        accept_count,
        ExchangeState::default(),
        |inbound, state| process_inbound(store, registry, inbound, state),
        |rows, state| {
            state.sent_events += rows.len();
            Ok(())
        },
    )?;
    Ok(Output::Served(types::ServeReport {
        local_addr: report.local_addr,
        accepted_connections: report.accepted_connections,
        sent_events: report.value.sent_events,
        received_events: report.value.received_events,
    }))
}

fn process_inbound<R>(
    store: &Store,
    registry: &R,
    inbound: InboundNetworkRow,
    state: &mut ExchangeState,
) -> Result<Vec<OutboundNetworkRow>, String>
where
    R: EventRegistry,
{
    let target = NetworkTarget::new(inbound.source.addr());
    let output = registry.project_network_in(store, &inbound)?;
    let decoded = canonical_rows(&output)?;
    let reply = invite_bootstrap_reply(store, &decoded)?;
    store
        .insert_table_rows(output.rows)
        .map_err(|err| format!("stage canonical input: {err}"))?;
    let admitted = event_admission::run(
        store,
        registry,
        event_admission::Work::Drain {
            limit: decoded.len().max(1),
        },
    )?;
    pipeline::run(
        store,
        registry,
        DrainUntilIdle {
            batch_size: READY_BATCH,
        },
    )?;
    state.received_events += admitted.event_ids.len();

    // After admission, walk decoded canonical bytes and record any
    // requester-advertised listener for outbound dial-back. This is what lets
    // the daemon's periodic sync find peers it has accepted from.
    for canonical in &decoded {
        if let Some(bytes) = canonical.canonical_bytes.as_ref() {
            if connection_request::codec::is_request(bytes) {
                remember_advertised_listener(store, bytes)?;
            }
        }
    }
    let frames = match reply {
        Some(reply) => invite_bootstrap_response_frames(store, reply, &admitted.event_ids)?,
        None => Vec::new(),
    };
    Ok(network_queues::outbound_rows(target, frames))
}

/// Persist a transport target for the requester's advertised listener.
///
/// Called per-frame after admission of a received connection_request. The
/// helper:
///
/// - Decodes the request to read its `from_listen_addr`. The field is
///   optional: a one-shot CLI requester sets it to `None`, so this helper
///   leaves routes alone in that case.
/// - Skips when this endpoint already has a routed connection to the same
///   remote endpoint. The receive side runs without knowing which connection
///   the local side already initiated; piling on a second route per peer turns
///   one sync round into N redundant rounds for the same workspace and shows
///   up in tests as broken convergence even though the messages cross the
///   wire. The "first route wins" rule keeps fan-out per peer at one TT.
/// - Otherwise writes a transport target keyed by the connection id derived
///   from the request id and this local endpoint, with the remote-advertised
///   socket address as the routed destination.
fn remember_advertised_listener(store: &Store, request_bytes: &[u8]) -> Result<(), String> {
    let request = connection_request::codec::decode(request_bytes)?;
    let Some(addr) = request.from_listen_addr else {
        return Ok(());
    };
    let local = local_endpoint(store)?;
    let request_id = event_id(request_bytes);
    let connection_id = types::connection_id(&request_id, &local.endpoint);
    // Drop quietly when the request did not project. Admission can mark a
    // request `Blocked` if its invite-secret dependency has not yet arrived,
    // in which case no `connection.connections` row exists and writing a
    // transport target here would orphan that route — the next `sync_tick`
    // would then iterate transport targets, fail to resolve the connection,
    // and stop the daemon. Connection requests are local protocol state, not
    // shared facts; the requester will keep retrying until both sides have
    // every dependency, so the safe behavior is to skip route persistence
    // for un-admitted requests and let a future delivery write the row.
    if schema::remote_endpoint(store, connection_id).is_err() {
        return Ok(());
    }
    if endpoint_has_routed_connection(store, &request.from_endpoint)? {
        return Ok(());
    }
    let row = schema::transport_target_row(connection_id, addr);
    store
        .insert_table_rows(vec![row])
        .map(|_| ())
        .map_err(|err| format!("remember received connection route: {err}"))
}

/// Check whether any existing routed connection's remote is `endpoint`.
///
/// `connection.transport_targets` rows are keyed by `connection_id`, so the
/// only way to ask "do we have a routed connection to this endpoint?" is to
/// scan the table and resolve each connection's remote endpoint. Routed peer
/// counts are bounded by the local daemon's known peer set, so the scan is
/// cheap in practice.
fn endpoint_has_routed_connection(
    store: &Store,
    endpoint: &endpoint::types::EndpointId,
) -> Result<bool, String> {
    for (key, _) in store
        .table_rows(schema::TRANSPORT_TARGETS)
        .map_err(|err| format!("load transport targets: {err}"))?
    {
        let connection_id = types::connection_id_from_bytes(&key)?;
        match schema::remote_endpoint(store, connection_id) {
            Ok(remote) => {
                if remote == *endpoint {
                    return Ok(true);
                }
            }
            Err(_) => continue,
        }
    }
    Ok(false)
}

fn canonical_rows(output: &ProjectionOutput) -> Result<Vec<DecodedCanonical>, String> {
    output
        .rows
        .iter()
        .filter(|row| row.table == worker_schema::CANONICAL_IN)
        .map(|row| {
            let (canonical_bytes, _, provenance) =
                worker_schema::decode_canonical_in(&row.value)?;
            Ok(DecodedCanonical {
                provenance,
                canonical_bytes: Some(canonical_bytes),
            })
        })
        .collect()
}

fn invite_bootstrap_reply(
    store: &Store,
    decoded: &[DecodedCanonical],
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

fn ensure_local_invite_acceptance<R>(
    store: &Store,
    registry: &R,
    parsed_invite: &invite::types::Invite,
) -> Result<endpoint::types::EndpointKeypair, String>
where
    R: EventRegistry,
{
    let local = endpoint::commands::local_or_create(store)?;
    let local_endpoint = local.value;
    if !local.events.is_empty() {
        pipeline::run(
            store,
            registry,
            pipeline::CommandOutput::with_proposed_events((), local.events),
        )
        .map_err(|err| format!("record local endpoint: {err}"))?;
    }

    let accepted = invite_accepted::commands::accept(invite_accepted::commands::AcceptInvite {
        accepted_endpoint_id: local_endpoint.endpoint,
        bootstrap_secret: parsed_invite.bootstrap_secret,
        workspace_id: parsed_invite.workspace_id,
        invite_event_id: parsed_invite.invite_event_id,
    })?;
    pipeline::run(
        store,
        registry,
        pipeline::CommandOutput::with_proposed_events((), accepted.events),
    )
    .map_err(|err| format!("record invite bootstrap acceptance: {err}"))?;
    Ok(local_endpoint)
}

fn initial_bootstrap_inner_bytes(
    parsed_invite: &invite::types::Invite,
    records: Vec<EventRecord>,
) -> Result<Vec<Vec<u8>>, String> {
    let mut inners = Vec::with_capacity(records.len());
    for record in records {
        if !record.scope.is_shared() {
            return Err("initial invite events must be shared events".to_string());
        }
        if record.workspace_id != Some(parsed_invite.workspace_id) {
            return Err("initial invite event is outside invite workspace".to_string());
        }
        if !crate::protocol::event_modules::is_identity_bootstrap_event(&record.canonical_bytes)? {
            return Err("initial invite event must be an identity bootstrap event".to_string());
        }
        inners.push(record.canonical_bytes);
    }
    Ok(inners)
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
        if crate::protocol::event_modules::is_identity_bootstrap_event(&bytes)? {
            out.push(bytes);
        }
    }
    Ok(out)
}

/// Daemon worker that serves bootstrap and inbound transit on the long-lived
/// listener. Each tick accepts at most one available stream; the inbound
/// callback runs the same `process_inbound` pipeline used by the one-shot
/// `Serve` variant so bootstrap responses go out on the same stream the
/// requester opened. Steady-state inbound frames return an empty reply, the
/// stream's write side shuts, and reads continue until the peer closes.
pub(crate) fn daemon_worker<C>() -> Worker<C>
where
    C: DaemonWorkerContext,
{
    Worker {
        name: "bootstrap_serve",
        run: daemon_step::<C>,
    }
}

fn daemon_step<C>(ctx: &mut StepContext<'_, C>) -> Result<(), String>
where
    C: DaemonWorkerContext,
{
    let app = &*ctx.app;
    let accept = ctx.listener.accept_exchange_available(
        app.store(),
        ExchangeState::default(),
        |inbound, state| process_inbound(app.store(), app, inbound, state),
        |rows, state| {
            state.sent_events += rows.len();
            Ok(())
        },
    )?;
    ctx.report
        .add("accepted_connections", accept.accepted_connections);
    ctx.report.add("received_events", accept.value.received_events);
    ctx.report
        .add("sent_bootstrap_events", accept.value.sent_events);
    Ok(())
}

fn local_endpoint(store: &Store) -> Result<endpoint::types::EndpointKeypair, String> {
    endpoint::commands::local_keypair(store)?.ok_or_else(|| "local endpoint is missing".to_string())
}

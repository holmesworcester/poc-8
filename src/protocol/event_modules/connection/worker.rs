//! Connection worker.
//!
//! The connection domain is the protocol boundary between transport routes and
//! Topo events. Core TCP can move length-prefixed byte frames, but it cannot say
//! whether those bytes are a bootstrap request, a connection-scoped transit
//! blob, or junk. This worker owns that interpretation for the connection event
//! family.
//!
//! The worker has two jobs:
//!
//! ```text
//! inbound bytes  -> unwrap transit -> connection event or connection-scoped inner bytes
//! outbox rows    -> wrap transit   -> opaque bytes for a concrete transport target
//! ```
//!
//! It deliberately does not implement generic event projection, sync comparison,
//! TCP sockets, or length-prefix framing. Accepted connection events and
//! received durable bytes are admitted through the common event-module worker.
//! When connection-scoped inner bytes arrive, this worker admits them as
//! transient inbound protocol events, wakes the owning domain worker over the
//! rows those events projected, then drains only the outbox needed to answer on
//! the same transport target. The CLI-facing operations may drive the generic
//! core TCP pump, but framing and socket mechanics remain in core.
//!
//! The most important caution is to keep "connection" and "transport target"
//! separate. A connection id is semantic state established by signed events and
//! transit secrets. A transport target is just where bytes can be sent right
//! now. This worker may resolve one to the other, but core must never need to
//! know that mapping.

use std::{
    cell::RefCell, collections::HashMap, net::SocketAddr, str::FromStr, thread, time::Instant,
};

use crate::core::network_queues::{self, InboundNetworkRow, NetworkTarget, OutboundNetworkRow};
use crate::core::store::Store;
use crate::core::tcp;
use crate::protocol::event_modules::identity::{
    admin, device_invite, endpoint, endpoint_shared, invite, signed, user, user_invite, workspace,
};
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::sync;
use crate::protocol::event_modules::types::{EventId, EventRecord, ReceiveMetadata};
use crate::protocol::event_modules::worker::{
    self, AdmitReceivedRecords, AdmitRecords, CommandOutput, EventRegistry, ProposedEvent,
    ReceivedRecord,
};

use super::{connection_ack, connection_request, schema, transit, types};

pub trait ConnectionRegistry: EventRegistry {
    fn sync_index(&self) -> &sync::worker::SyncIndex;
}

/// Transport metadata attached to one inbound frame.
///
/// `origin` is a concrete route observed by core TCP. `remember_origin` tells
/// the worker whether a connection handshake record should project with that
/// route. Tests and replay paths can ingest bytes without mutating route state
/// by setting it to false.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FrameMetadata {
    pub origin: SocketAddr,
    pub remember_origin: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UnwrappedFrameMetadata {
    pub frame: FrameMetadata,
    pub sender_endpoint: endpoint::types::EndpointId,
}

pub const DEFAULT_DAEMON_READY_BATCH: usize = worker::DEFAULT_READY_BATCH;

/// Work accepted by the connection worker.
///
/// Each variant is an active connection-domain operation. The variants are
/// intentionally report-oriented so callers do not reach into helper functions
/// for frame ingestion, route draining, or send confirmation bookkeeping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Work {
    ConnectInvite {
        invite: String,
    },
    ConnectInviteWithInitialEvents {
        invite: String,
        records: Vec<EventRecord>,
    },
    Serve {
        listen: SocketAddr,
        accept_count: usize,
    },
    ExchangeOutboundRoutes,
    StartSyncRoutes {
        selection: sync::worker::SyncSelection,
    },
    RunDaemon {
        options: types::DaemonOptions,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BootstrapScope {
    workspace_id: [u8; 32],
    authorized_endpoint: endpoint::types::EndpointId,
}

/// Result of a connection worker action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    Connected(types::ConnectReport),
    Served(types::ServeReport),
    RoutesExchanged(types::RouteExchangeReport),
    SyncRoutesStarted(types::RouteExchangeReport),
    DaemonRan(types::DaemonReport),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct StreamExchangeReport {
    bootstrap_scope: Option<BootstrapScope>,
    pending_bootstrap_outgoing: Vec<Vec<u8>>,
    established_routes: usize,
    sent_events: usize,
    received_events: usize,
}

/// Opaque bytes prepared for one route after draining protocol outbox rows.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OutboundSync {
    target: NetworkTarget,
    outgoing: Vec<OutboundNetworkRow>,
    sent_outbox: Vec<Vec<Vec<u8>>>,
}

/// Summary of a complete inbound network-row exchange.
///
/// This is the active network boundary for the connection domain. It includes
/// opaque rows ready for core TCP, protocol outbox keys represented by those
/// rows, and small counters used by black-box CLI tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct NetworkIngestResult {
    outgoing: Vec<OutboundNetworkRow>,
    sent_outbox: Vec<Vec<Vec<u8>>>,
    bootstrap_scope: Option<BootstrapScope>,
    established_routes: usize,
    sent_events: usize,
    received_events: usize,
}

/// Interpretation of one inbound frame after transit unwrapping.
///
/// Connection events can be admitted directly. Connection-scoped inner bytes
/// must be handed to the event family that owns the inner wire format while
/// preserving the connection id recovered from transit. Durable events carry
/// only the sender endpoint recovered by transit; they are not considered safe
/// for the common pipeline until `ingest_durable_event` proves the sender and
/// receiver have mutual membership in the event workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
enum InboundFrame {
    Connection(ConnectionFrameReport),
    SyncEvent {
        connection_id: types::ConnectionId,
        inner: Vec<u8>,
    },
    DurableEvent {
        connection_id: types::ConnectionId,
        sender_endpoint: endpoint::types::EndpointId,
        inner: Vec<u8>,
    },
    BootstrapDurableEvent {
        workspace_id: [u8; 32],
        sender_endpoint: endpoint::types::EndpointId,
        inner: Vec<u8>,
    },
}

/// Records and response bytes produced while accepting a connection frame.
///
/// The events are canonical connection-domain facts. `outgoing` is bootstrap or
/// connection response traffic that should go back to the frame origin. Route
/// establishment is reported separately for CLI output and tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ConnectionFrameReport {
    pub records: Vec<ReceivedRecord>,
    pub outgoing: Vec<Vec<u8>>,
    pub bootstrap_scope: Option<BootstrapScope>,
    pub established_routes: usize,
}

/// Opaque transit bytes ready for one concrete transport target.
///
/// `sent_outbox` carries the protocol outbox keys represented by `outgoing`.
/// The caller deletes those rows only after it has committed the corresponding
/// core outbound network rows.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OutboundTransit {
    target: SocketAddr,
    outgoing: Vec<Vec<u8>>,
    sent_outbox: Vec<Vec<Vec<u8>>>,
}

/// Result of draining one connection's protocol outbox.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct DrainedOutbox {
    outgoing: Vec<Vec<u8>>,
    sent_outbox: Vec<Vec<Vec<u8>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TransportRoute {
    connection_id: types::ConnectionId,
    addr: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OutboxItem {
    key: types::OutboxKey,
    event_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct OutboxDrain {
    items: Vec<OutboxItem>,
    stale_keys: Vec<Vec<u8>>,
}

const TRANSIT_TARGET_PLAINTEXT_BYTES: usize = 32 * 1024 * 1024;

/// Run one connection worker action.
///
/// This is the only public entrypoint by design. Keeping helpers private makes
/// it clear which effects the connection domain can perform and gives boundary
/// tests one stable surface to check.
pub fn run<R>(store: &Store, registry: &R, work: Work) -> Result<Output, String>
where
    R: ConnectionRegistry,
{
    match work {
        Work::ConnectInvite { invite } => {
            run_connect(store, registry, invite, Vec::new()).map(Output::Connected)
        }
        Work::ConnectInviteWithInitialEvents { invite, records } => {
            run_connect(store, registry, invite, records).map(Output::Connected)
        }
        Work::Serve {
            listen,
            accept_count,
        } => run_serve(store, registry, listen, accept_count).map(Output::Served),
        Work::ExchangeOutboundRoutes => {
            exchange_outbound_routes(store, registry, true).map(Output::RoutesExchanged)
        }
        Work::StartSyncRoutes { selection } => {
            start_sync_routes(store, registry, selection, true).map(Output::SyncRoutesStarted)
        }
        Work::RunDaemon { options } => run_daemon(store, registry, options).map(Output::DaemonRan),
    }
}

fn run_connect<R>(
    store: &Store,
    registry: &R,
    invite: String,
    initial_records: Vec<EventRecord>,
) -> Result<types::ConnectReport, String>
where
    R: ConnectionRegistry,
{
    let parsed_invite = invite::commands::parse(&invite)?;
    if !parsed_invite.identity_scope && !initial_records.is_empty() {
        return Err("initial invite events require an identity-scoped invite".to_string());
    }
    let invite_scope = parsed_invite.identity_scope.then_some(BootstrapScope {
        workspace_id: parsed_invite.workspace_id,
        authorized_endpoint: parsed_invite.endpoint,
    });
    let output = connection_request::commands::create_with_local(store, &invite)
        .map_err(|err| format!("create connection request: {err}"))?;
    let addr = output.value.addr;
    let request = worker::run(store, registry, output)
        .map_err(|err| format!("record connection request: {err}"))?
        .0;

    let target = NetworkTarget::new(addr);
    let initial_outbound = vec![OutboundNetworkRow::new(target, request.bytes)];
    let initial_event_bytes =
        initial_invite_event_bytes(parsed_invite.workspace_id, initial_records)?;
    let mut pending_bootstrap_outgoing = Vec::with_capacity(initial_event_bytes.len());
    if !initial_event_bytes.is_empty() {
        let local = local_endpoint(store)?;
        for bytes in initial_event_bytes {
            pending_bootstrap_outgoing.push(transit::commands::create_bootstrap(
                &local,
                parsed_invite.endpoint,
                &bytes,
            )?);
        }
    }
    let sent_outbox = RefCell::new(HashMap::new());
    let summary = tcp::connect_exchange(
        store,
        target,
        initial_outbound,
        StreamExchangeReport {
            pending_bootstrap_outgoing,
            ..StreamExchangeReport::default()
        },
        |inbound, summary| {
            handle_inbound(
                store,
                registry,
                inbound,
                summary,
                InboundHandling {
                    remember_origin: true,
                    bootstrap_scope: invite_scope,
                    sent_outbox: &sent_outbox,
                    stream_scopes: None,
                },
            )
        },
        |rows, _| mark_sent_network_rows(store, rows, &sent_outbox),
    )?;
    if summary.established_routes == 0 {
        return Err("connection was not established".to_string());
    }
    Ok(types::ConnectReport {
        addr,
        established_routes: summary.established_routes,
    })
}

fn initial_invite_event_bytes(
    workspace_id: EventId,
    records: Vec<EventRecord>,
) -> Result<Vec<Vec<u8>>, String> {
    let mut out = Vec::with_capacity(records.len());
    for record in records {
        if !record.scope.is_shared() {
            return Err("initial invite events must be shared events".to_string());
        }
        if record.workspace_id != Some(workspace_id) {
            return Err("initial invite event is outside invite workspace".to_string());
        }
        out.push(record.canonical_bytes);
    }
    Ok(out)
}

fn run_serve<R>(
    store: &Store,
    registry: &R,
    listen: SocketAddr,
    accept_count: usize,
) -> Result<types::ServeReport, String>
where
    R: ConnectionRegistry,
{
    let sent_outbox = RefCell::new(HashMap::new());
    let bootstrap_scopes = RefCell::new(HashMap::new());
    let report = tcp::serve(
        store,
        listen,
        accept_count,
        types::ServeReport::default(),
        |inbound, summary| {
            let mut one_stream = StreamExchangeReport::default();
            let outgoing = handle_inbound(
                store,
                registry,
                inbound,
                &mut one_stream,
                InboundHandling {
                    remember_origin: false,
                    bootstrap_scope: None,
                    sent_outbox: &sent_outbox,
                    stream_scopes: Some(&bootstrap_scopes),
                },
            )?;
            summary.received_events += one_stream.received_events;
            Ok(outgoing)
        },
        |rows, _| mark_sent_network_rows(store, rows, &sent_outbox),
    )?;
    let mut summary = report.value;
    summary.local_addr = Some(report.local_addr);
    summary.accepted_connections = report.accepted_connections;
    Ok(summary)
}

fn run_daemon<R>(
    store: &Store,
    registry: &R,
    options: types::DaemonOptions,
) -> Result<types::DaemonReport, String>
where
    R: ConnectionRegistry,
{
    let listener = tcp::listen(options.listen)?;
    let sent_outbox = RefCell::new(HashMap::new());
    let bootstrap_scopes = RefCell::new(HashMap::new());
    let mut summary = types::DaemonReport {
        local_addr: Some(listener.local_addr()),
        ..types::DaemonReport::default()
    };
    let started = Instant::now();

    loop {
        let accept = listener.accept_available(
            store,
            types::ServeReport::default(),
            |inbound, stream_summary| {
                let mut one_stream = StreamExchangeReport::default();
                let outgoing = handle_inbound(
                    store,
                    registry,
                    inbound,
                    &mut one_stream,
                    InboundHandling {
                        remember_origin: false,
                        bootstrap_scope: None,
                        sent_outbox: &sent_outbox,
                        stream_scopes: Some(&bootstrap_scopes),
                    },
                )?;
                stream_summary.received_events += one_stream.received_events;
                Ok(outgoing)
            },
            |rows, _| mark_sent_network_rows(store, rows, &sent_outbox),
        )?;
        summary.accepted_connections += accept.accepted_connections;
        summary.received_events += accept.value.received_events;

        let ready = worker::run(
            store,
            registry,
            worker::DrainReadyBatch {
                batch_size: options.ready_batch,
            },
        )
        .map_err(|err| format!("drain daemon ready batch: {err}"))?;
        summary.ready_events += ready.applied_events;
        summary.unblocked_events += ready.unblocked_events;

        let sync = start_sync_routes(store, registry, sync::worker::SyncSelection::All, false)?;
        summary.sync_rounds += 1;
        summary.routes_synced += sync.routes_synced;
        summary.failed_routes += sync.failed_routes;
        summary.sent_events += sync.sent_events;
        summary.received_events += sync.received_events;

        if options
            .duration
            .is_some_and(|duration| started.elapsed() >= duration)
        {
            return Ok(summary);
        }
        thread::sleep(options.idle);
    }
}

fn start_sync_routes<R>(
    store: &Store,
    registry: &R,
    selection: sync::worker::SyncSelection,
    fail_on_route_error: bool,
) -> Result<types::RouteExchangeReport, String>
where
    R: ConnectionRegistry,
{
    let start = match sync::worker::run(
        store,
        registry.sync_index(),
        sync::worker::Work::Start { selection },
    )
    .map_err(|err| format!("start sync: {err}"))?
    {
        sync::worker::Output::Started(output) => output,
        sync::worker::Output::DrainedInboundSync(_) => {
            return Err("sync worker returned non-start output".to_string())
        }
    };
    let (started, _) = worker::run(store, registry, start)
        .map_err(|err| format!("record daemon sync events: {err}"))?;

    let mut summary = types::RouteExchangeReport {
        sent_events: started.sent_events,
        ..types::RouteExchangeReport::default()
    };
    summary.merge(exchange_outbound_routes(
        store,
        registry,
        fail_on_route_error,
    )?);
    Ok(summary)
}

fn exchange_outbound_routes<R>(
    store: &Store,
    registry: &R,
    fail_on_route_error: bool,
) -> Result<types::RouteExchangeReport, String>
where
    R: ConnectionRegistry,
{
    let mut summary = types::RouteExchangeReport::default();
    for outbound in drain_outbox_routes(store).map_err(|err| format!("drain outbox: {err}"))? {
        let outbound = outbound_sync(outbound);
        let target = outbound.target;
        match exchange_outbound_route(store, registry, outbound) {
            Ok(stream_summary) => {
                summary.routes_synced += 1;
                summary.sent_events += stream_summary.sent_events;
                summary.received_events += stream_summary.received_events;
            }
            Err(err) if fail_on_route_error => {
                return Err(format!("exchange outbound route {target:?}: {err}"));
            }
            Err(_) => {
                summary.failed_routes += 1;
            }
        }
    }
    Ok(summary)
}

fn exchange_outbound_route<R>(
    store: &Store,
    registry: &R,
    outbound: OutboundSync,
) -> Result<StreamExchangeReport, String>
where
    R: ConnectionRegistry,
{
    let sent_outbox = RefCell::new(HashMap::new());
    remember_sent_outbox(&sent_outbox, &outbound.outgoing, &outbound.sent_outbox)?;
    tcp::connect_exchange(
        store,
        outbound.target,
        outbound.outgoing,
        StreamExchangeReport::default(),
        |inbound, summary| {
            handle_inbound(
                store,
                registry,
                inbound,
                summary,
                InboundHandling {
                    remember_origin: false,
                    bootstrap_scope: None,
                    sent_outbox: &sent_outbox,
                    stream_scopes: None,
                },
            )
        },
        |rows, _| mark_sent_network_rows(store, rows, &sent_outbox),
    )
}

fn outbound_sync(outbound: OutboundTransit) -> OutboundSync {
    let target = NetworkTarget::new(outbound.target);
    OutboundSync {
        target,
        outgoing: network_queues::outbound_rows(target, outbound.outgoing),
        sent_outbox: outbound.sent_outbox,
    }
}

fn ingest_network<R>(
    store: &Store,
    registry: &R,
    inbound: InboundNetworkRow,
    remember_origin: bool,
    bootstrap_scope: Option<BootstrapScope>,
) -> Result<NetworkIngestResult, String>
where
    R: ConnectionRegistry,
{
    let local = local_endpoint(store)?;
    let origin = inbound.source.addr();
    let metadata = FrameMetadata {
        origin,
        remember_origin,
    };
    let frames = unwrap_transit_bytes(store, local, metadata, inbound.bytes, bootstrap_scope)?;
    let mut report = NetworkFrameReport::default();
    for frame in frames {
        // Transit unwrap tells us who sent the bytes and, for established
        // transit, which connection secret decrypted them. That proves origin
        // for the frame, not workspace authority for arbitrary durable events.
        // Connection-scoped sync gets routed by connection id; durable shared
        // history must pass the workspace-membership check below before it can
        // enter the ordinary event pipeline.
        let next = match frame {
            InboundFrame::Connection(report) => NetworkFrameReport {
                received_records: report.records,
                outgoing: report.outgoing,
                bootstrap_scope: report.bootstrap_scope,
                established_routes: report.established_routes,
                ..NetworkFrameReport::default()
            },
            InboundFrame::SyncEvent {
                connection_id,
                inner,
            } => ingest_connection_scoped_sync_event(connection_id, inner)?,
            InboundFrame::DurableEvent {
                connection_id,
                sender_endpoint,
                inner,
            } => ingest_durable_event(
                store,
                registry,
                local.endpoint,
                connection_id,
                sender_endpoint,
                inner,
            )?,
            InboundFrame::BootstrapDurableEvent {
                workspace_id,
                sender_endpoint,
                inner,
            } => ingest_bootstrap_durable_event(
                store,
                registry,
                workspace_id,
                sender_endpoint,
                inner,
            )?,
        };
        report.merge(next);
    }

    admit_records_if_any(
        store,
        registry,
        std::mem::take(&mut report.events),
        std::mem::take(&mut report.received_records),
    )?;

    if let Some(connection_id) = report.drain_sync_for {
        let sync_report = drain_projected_sync_work(store, registry.sync_index(), connection_id)?;
        worker::run(
            store,
            registry,
            AdmitRecords {
                records: sync_report.events,
            },
        )?;
        report.sent_events += sync_report.sent_events;
    }

    let target = network_queues::NetworkTarget::new(origin);
    let mut outgoing = network_queues::outbound_rows(target, report.outgoing);
    let mut sent_outbox = Vec::new();
    if let Some(connection_id) = report.drain_outbox_for {
        let drained = drain_outbox_for_route(store, local, connection_id)?;
        outgoing.extend(network_queues::outbound_rows(target, drained.outgoing));
        sent_outbox.extend(drained.sent_outbox);
    }

    Ok(NetworkIngestResult {
        outgoing,
        sent_outbox,
        bootstrap_scope: report.bootstrap_scope,
        established_routes: report.established_routes,
        sent_events: report.sent_events,
        received_events: report.received_events,
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct NetworkFrameReport {
    events: Vec<EventRecord>,
    received_records: Vec<ReceivedRecord>,
    outgoing: Vec<Vec<u8>>,
    drain_sync_for: Option<types::ConnectionId>,
    drain_outbox_for: Option<types::ConnectionId>,
    bootstrap_scope: Option<BootstrapScope>,
    established_routes: usize,
    sent_events: usize,
    received_events: usize,
}

impl NetworkFrameReport {
    fn merge(&mut self, other: Self) {
        self.events.extend(other.events);
        self.received_records.extend(other.received_records);
        self.outgoing.extend(other.outgoing);
        self.drain_sync_for = self.drain_sync_for.or(other.drain_sync_for);
        self.drain_outbox_for = self.drain_outbox_for.or(other.drain_outbox_for);
        self.bootstrap_scope = self.bootstrap_scope.or(other.bootstrap_scope);
        self.established_routes += other.established_routes;
        self.sent_events += other.sent_events;
        self.received_events += other.received_events;
    }
}

fn ingest_connection_scoped_sync_event(
    connection_id: types::ConnectionId,
    inner: Vec<u8>,
) -> Result<NetworkFrameReport, String> {
    let event = sync::inbound_record_from_connection_bytes(connection_id, inner)?;
    Ok(NetworkFrameReport {
        events: vec![event],
        drain_sync_for: Some(connection_id),
        drain_outbox_for: Some(connection_id),
        ..NetworkFrameReport::default()
    })
}

fn admit_records_if_any(
    store: &Store,
    registry: &impl EventRegistry,
    records: Vec<EventRecord>,
    received_records: Vec<ReceivedRecord>,
) -> Result<(), String> {
    if !received_records.is_empty() {
        worker::run(
            store,
            registry,
            AdmitReceivedRecords {
                records: received_records,
            },
        )?;
    }
    if !records.is_empty() {
        worker::run(store, registry, AdmitRecords { records })?;
    }
    Ok(())
}

fn ingest_durable_event(
    store: &Store,
    registry: &impl EventRegistry,
    local_endpoint: endpoint::types::EndpointId,
    connection_id: types::ConnectionId,
    sender_endpoint: endpoint::types::EndpointId,
    inner: Vec<u8>,
) -> Result<NetworkFrameReport, String> {
    let is_join_bootstrap = is_join_bootstrap_event(&inner)?;
    let record = registry.record_from_bytes(inner)?;
    if !record.scope.is_shared() {
        return Err("connection durable ingress only accepts shared events".to_string());
    }
    let workspace_id = record
        .workspace_id
        .ok_or_else(|| "connection durable ingress requires a workspace".to_string())?;
    // This is the receive-side workspace boundary. Solicitation is deliberately
    // not part of the check: sync often cannot know which dependencies it needs
    // until a peer advertises them. What matters is whether the authenticated
    // sender endpoint and our local endpoint are both joined to the workspace
    // named by the event. If not, admitting the event would let one connection
    // inject or exfiltrate facts for another workspace.
    let allowed_workspaces =
        endpoint_shared::schema::mutual_workspace_ids(store, local_endpoint, sender_endpoint)?;
    if !allowed_workspaces
        .iter()
        .any(|allowed| allowed == &workspace_id)
    {
        let bootstrap_workspace = schema::bootstrap_workspace_id(store, connection_id)?;
        if bootstrap_workspace != Some(workspace_id) || !is_join_bootstrap {
            return Err(
                "connection durable ingress rejected event outside sender workspace".to_string(),
            );
        }
    }
    Ok(NetworkFrameReport {
        events: vec![record],
        received_events: 1,
        ..NetworkFrameReport::default()
    })
}

fn ingest_bootstrap_durable_event(
    _store: &Store,
    registry: &impl EventRegistry,
    workspace_id: [u8; 32],
    _sender_endpoint: endpoint::types::EndpointId,
    inner: Vec<u8>,
) -> Result<NetworkFrameReport, String> {
    let is_identity_bootstrap = is_identity_bootstrap_event(&inner)?;
    let record = registry.record_from_bytes(inner)?;
    if !record.scope.is_shared() {
        return Err("bootstrap durable ingress only accepts shared events".to_string());
    }
    if record.workspace_id != Some(workspace_id) {
        return Err(
            "bootstrap durable ingress rejected event outside invite workspace".to_string(),
        );
    }
    if !is_identity_bootstrap {
        return Err("bootstrap durable ingress only accepts identity bootstrap events".to_string());
    }
    Ok(NetworkFrameReport {
        events: vec![record],
        received_events: 1,
        ..NetworkFrameReport::default()
    })
}

fn drain_projected_sync_work(
    store: &Store,
    index: &sync::worker::SyncIndex,
    connection_id: types::ConnectionId,
) -> Result<sync::worker::SyncWorkReport, String> {
    let mut aggregate = sync::worker::SyncWorkReport::default();
    loop {
        let output = sync::worker::run(
            store,
            index,
            sync::worker::Work::DrainInboundSync {
                connection_id,
                limit: sync::worker::DEFAULT_INBOUND_BATCH,
            },
        )?;
        let sync::worker::Output::DrainedInboundSync(report) = output else {
            return Err("sync worker returned non-drain output".to_string());
        };
        let processed_work = report.processed_work;
        aggregate.processed_work += processed_work;
        aggregate.sent_events += report.sent_events;
        aggregate.events.extend(report.events);
        aggregate.send_event_ids.extend(report.send_event_ids);
        if processed_work < sync::worker::DEFAULT_INBOUND_BATCH {
            return Ok(aggregate);
        }
    }
}

fn unwrap_transit_bytes(
    store: &Store,
    local: endpoint::types::EndpointKeypair,
    metadata: FrameMetadata,
    bytes: Vec<u8>,
    bootstrap_scope: Option<BootstrapScope>,
) -> Result<Vec<InboundFrame>, String> {
    // Transit unwrap is the only place inbound bytes become meaningful. A
    // bootstrap frame has no connection id yet; an ordinary connection transit
    // frame must recover one before any inner bytes are trusted enough to route.
    // The recovered sender endpoint is carried forward into admission checks; we
    // never infer sender identity from a payload field inside the decrypted bytes.
    let transit = transit::commands::unwrap(local, &bytes, |connection_id| {
        remote_endpoint(store, connection_id)
    })?;
    let mut frames = Vec::with_capacity(transit.inners.len());
    for inner in transit.inners {
        if types::is_connection_event(&inner) {
            frames.push(InboundFrame::Connection(ingest_connection_frame(
                store,
                local,
                UnwrappedFrameMetadata {
                    frame: metadata,
                    sender_endpoint: transit.sender_endpoint,
                },
                inner,
            )?));
            continue;
        }
        let Some(connection_id) = transit.connection_id else {
            let Some(scope) = bootstrap_scope else {
                return Err("connection-scoped frame requires connection transit".to_string());
            };
            if transit.sender_endpoint != scope.authorized_endpoint {
                return Err(
                    "bootstrap durable sender does not match authorized endpoint".to_string(),
                );
            }
            frames.push(InboundFrame::BootstrapDurableEvent {
                workspace_id: scope.workspace_id,
                sender_endpoint: transit.sender_endpoint,
                inner,
            });
            continue;
        };
        if sync::is_connection_scoped_event(&inner) {
            frames.push(InboundFrame::SyncEvent {
                connection_id,
                inner,
            });
        } else {
            frames.push(InboundFrame::DurableEvent {
                connection_id,
                sender_endpoint: transit.sender_endpoint,
                inner,
            });
        }
    }
    Ok(frames)
}

fn drain_outbox_routes(store: &Store) -> Result<Vec<OutboundTransit>, String> {
    // Route draining is deliberately route-based, not global "send everything".
    // Slow or absent targets should only starve their own route.
    let routes = routes(store)?;
    if routes.is_empty() {
        return Ok(Vec::new());
    }
    let local = local_endpoint(store)?;
    let mut outbound = Vec::new();
    for route in routes {
        let drained = drain_outbox_for_route(store, local, route.connection_id)?;
        if drained.outgoing.is_empty() {
            continue;
        }
        outbound.push(OutboundTransit {
            target: route.addr,
            outgoing: drained.outgoing,
            sent_outbox: drained.sent_outbox,
        });
    }
    Ok(outbound)
}

fn local_endpoint(store: &Store) -> Result<endpoint::types::EndpointKeypair, String> {
    endpoint::commands::local_keypair(store)?.ok_or_else(|| "local endpoint is missing".to_string())
}

fn drain_outbox_for_route(
    store: &Store,
    local: endpoint::types::EndpointKeypair,
    connection_id: types::ConnectionId,
) -> Result<DrainedOutbox, String> {
    let outbox = outbox_items_for_connection(store, connection_id)?;
    if !outbox.stale_keys.is_empty() {
        store
            .delete_table_rows(schema::OUTBOX, outbox.stale_keys)
            .map_err(|err| format!("delete stale outbox rows: {err}"))?;
    }
    let items = outbox.items;
    if items.is_empty() {
        return Ok(DrainedOutbox::default());
    }
    let remote = remote_endpoint(store, &connection_id)?;
    let batches = batch_outbox_items(items);
    let mut outgoing = Vec::with_capacity(batches.len());
    let mut sent_outbox = Vec::with_capacity(batches.len());
    for batch in batches {
        // The outbox stores canonical inner event bytes. Wrapping happens here,
        // at the connection boundary, so event modules never need socket or
        // encryption context in their projectors.
        let mut inner_events = Vec::with_capacity(batch.len());
        let mut batch_outbox = Vec::with_capacity(batch.len());
        for item in batch {
            inner_events.push(item.event_bytes);
            batch_outbox.push(item.key.to_bytes());
        }
        outgoing.push(transit::commands::create_connection_batch(
            &local,
            remote,
            connection_id,
            inner_events,
        )?);
        sent_outbox.push(batch_outbox);
    }
    Ok(DrainedOutbox {
        outgoing,
        sent_outbox,
    })
}

fn batch_outbox_items(items: Vec<OutboxItem>) -> Vec<Vec<OutboxItem>> {
    let mut batches: Vec<Vec<OutboxItem>> = Vec::new();
    let mut current = Vec::new();
    let mut current_bytes = 0usize;
    for item in items {
        let item_bytes = 4usize.saturating_add(item.event_bytes.len());
        if !current.is_empty()
            && current_bytes.saturating_add(item_bytes) > TRANSIT_TARGET_PLAINTEXT_BYTES
        {
            batches.push(std::mem::take(&mut current));
            current_bytes = 0;
        }
        current_bytes = current_bytes.saturating_add(item_bytes);
        current.push(item);
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
}

struct InboundHandling<'a> {
    remember_origin: bool,
    bootstrap_scope: Option<BootstrapScope>,
    sent_outbox: &'a RefCell<HashMap<Vec<u8>, Vec<Vec<u8>>>>,
    stream_scopes: Option<&'a RefCell<HashMap<SocketAddr, BootstrapScope>>>,
}

fn handle_inbound<R>(
    store: &Store,
    registry: &R,
    inbound: InboundNetworkRow,
    summary: &mut StreamExchangeReport,
    handling: InboundHandling<'_>,
) -> Result<Vec<OutboundNetworkRow>, String>
where
    R: ConnectionRegistry,
{
    let origin = inbound.source.addr();
    let remembered_scope = handling
        .stream_scopes
        .and_then(|scopes| scopes.borrow().get(&origin).copied());
    let active_bootstrap_scope = handling
        .bootstrap_scope
        .or(summary.bootstrap_scope)
        .or(remembered_scope);
    let mut ingest = ingest_network(
        store,
        registry,
        inbound,
        handling.remember_origin,
        active_bootstrap_scope,
    )?;
    summary.bootstrap_scope = summary.bootstrap_scope.or(ingest.bootstrap_scope);
    if let (Some(scopes), Some(scope)) = (handling.stream_scopes, ingest.bootstrap_scope) {
        scopes.borrow_mut().insert(origin, scope);
    }
    summary.established_routes += ingest.established_routes;
    summary.sent_events += ingest.sent_events;
    summary.received_events += ingest.received_events;
    if !summary.pending_bootstrap_outgoing.is_empty()
        && (ingest.established_routes > 0 || active_bootstrap_scope.is_some())
    {
        let target = network_queues::NetworkTarget::new(origin);
        ingest.outgoing.extend(network_queues::outbound_rows(
            target,
            std::mem::take(&mut summary.pending_bootstrap_outgoing),
        ));
    }

    worker::run(
        store,
        registry,
        worker::DrainUntilIdle {
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("drain ready events after inbound network: {err}"))?;

    remember_sent_outbox(handling.sent_outbox, &ingest.outgoing, &ingest.sent_outbox)?;
    Ok(ingest.outgoing)
}

fn remember_sent_outbox(
    sent_outbox: &RefCell<HashMap<Vec<u8>, Vec<Vec<u8>>>>,
    rows: &[OutboundNetworkRow],
    outbox_keys: &[Vec<Vec<u8>>],
) -> Result<(), String> {
    if outbox_keys.is_empty() {
        return Ok(());
    }
    if outbox_keys.len() > rows.len() {
        return Err("more outbox keys than outbound network rows".to_string());
    }
    let first = rows.len() - outbox_keys.len();
    let mut sent_outbox = sent_outbox.borrow_mut();
    for (row, row_outbox_keys) in rows[first..].iter().zip(outbox_keys) {
        sent_outbox
            .entry(row.key.clone())
            .or_default()
            .extend(row_outbox_keys.iter().cloned());
    }
    Ok(())
}

fn mark_sent_network_rows(
    store: &Store,
    rows: &[OutboundNetworkRow],
    sent_outbox: &RefCell<HashMap<Vec<u8>, Vec<Vec<u8>>>>,
) -> Result<(), String> {
    let mut outbox_keys = Vec::new();
    {
        let mut sent_outbox = sent_outbox.borrow_mut();
        for row in rows {
            if let Some(mut row_outbox_keys) = sent_outbox.remove(&row.key) {
                outbox_keys.append(&mut row_outbox_keys);
            }
        }
    }
    mark_outbox_sent(store, outbox_keys)
}

fn mark_outbox_sent(store: &Store, sent_outbox: Vec<Vec<u8>>) -> Result<(), String> {
    if sent_outbox.is_empty() {
        return Ok(());
    }
    // Delete only rows that have been converted into committed core outbound
    // network rows. A crash before this point may resend duplicate protocol
    // events, which is acceptable because event ids and outbox keys dedupe.
    store
        .delete_table_rows(schema::OUTBOX, sent_outbox)
        .map(|_| ())
        .map_err(|err| format!("delete sent outbox rows: {err}"))
}

fn remote_endpoint(
    store: &Store,
    connection_id: &types::ConnectionId,
) -> Result<endpoint::types::EndpointId, String> {
    let bytes = store
        .table_row(schema::CONNECTIONS, connection_id)
        .map_err(|err| format!("load connection: {err}"))?
        .ok_or_else(|| "unknown connection".to_string())?;
    endpoint_id_from_bytes(&bytes)
}

fn routes(store: &Store) -> Result<Vec<TransportRoute>, String> {
    let rows = store
        .table_rows(schema::TRANSPORT_TARGETS)
        .map_err(|err| format!("load transport targets: {err}"))?;
    rows.into_iter()
        .map(|(key, value)| {
            let connection_id = types::connection_id_from_bytes(&key)?;
            let text = String::from_utf8(value)
                .map_err(|err| format!("transport target is not utf8: {err}"))?;
            let addr = SocketAddr::from_str(&text)
                .map_err(|err| format!("transport target is invalid: {err}"))?;
            Ok(TransportRoute {
                connection_id,
                addr,
            })
        })
        .collect()
}

fn outbox_items_for_connection(
    store: &Store,
    connection_id: types::ConnectionId,
) -> Result<OutboxDrain, String> {
    // Outbox rows are id-only. Durable data resolves from the common event
    // store; connection-scoped protocol events resolve from the in-memory
    // connection byte cache populated by their projectors.
    let prefix = connection_id.to_vec();
    let rows = store
        .table_rows_with_key_prefix(schema::OUTBOX, &prefix, 4096)
        .map_err(|err| format!("load outbox: {err}"))?;
    let mut drain = OutboxDrain {
        items: Vec::with_capacity(rows.len()),
        stale_keys: Vec::new(),
    };
    for (key, _) in rows {
        let outbox_key = decode_outbox_key(&key)?;
        let Some(event_bytes) = resolve_outbox_event_bytes(store, &outbox_key.event_id)? else {
            drain.stale_keys.push(key);
            continue;
        };
        drain.items.push(OutboxItem {
            key: outbox_key,
            event_bytes,
        });
    }
    Ok(drain)
}

fn resolve_outbox_event_bytes(
    store: &Store,
    event_id: &[u8; 32],
) -> Result<Option<Vec<u8>>, String> {
    if let Some(bytes) = event_schema::event_bytes(store, event_id)
        .map_err(|err| format!("load durable outbox event: {err}"))?
    {
        return Ok(Some(bytes));
    }
    store
        .table_row(schema::CONNECTION_SCOPED_EVENTS, event_id)
        .map_err(|err| format!("load connection-scoped outbox event: {err}"))
}

fn decode_outbox_key(bytes: &[u8]) -> Result<types::OutboxKey, String> {
    if bytes.len() != 64 {
        return Err("outbox key must be 64 bytes".to_string());
    }
    let connection_id = types::connection_id_from_bytes(&bytes[..32])?;
    let mut event_id = [0; 32];
    event_id.copy_from_slice(&bytes[32..]);
    Ok(types::OutboxKey {
        connection_id,
        event_id,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AuthorizedInvite {
    invite_secret_event_id: [u8; 32],
    workspace_id: Option<[u8; 32]>,
    invite_event_id: Option<[u8; 32]>,
}

fn authorized_invite(
    store: &Store,
    bootstrap_hash: &[u8; 32],
) -> Result<Option<AuthorizedInvite>, String> {
    let Some(value) = store
        .table_row(invite::schema::INVITE_SECRETS, bootstrap_hash)
        .map_err(|err| format!("load invite secret: {err}"))?
    else {
        return Ok(None);
    };
    let row = invite::schema::decode_invite_secret_row(&value)?;
    let bytes = invite::codec::encode(&invite::types::InviteSecretEvent {
        bootstrap_hash: *bootstrap_hash,
        bootstrap_secret: row.bootstrap_secret,
        workspace_id: row.workspace_id,
        invite_event_id: row.invite_event_id,
    });
    Ok(Some(AuthorizedInvite {
        invite_secret_event_id: types::event_id(&bytes),
        workspace_id: row.workspace_id,
        invite_event_id: row.invite_event_id,
    }))
}

fn endpoint_id_from_bytes(bytes: &[u8]) -> Result<endpoint::types::EndpointId, String> {
    if bytes.len() != 32 {
        return Err("stored endpoint id is malformed".to_string());
    }
    let mut out = [0; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn ingest_connection_frame(
    store: &Store,
    local: endpoint::types::EndpointKeypair,
    metadata: UnwrappedFrameMetadata,
    bytes: Vec<u8>,
) -> Result<ConnectionFrameReport, String> {
    let mut result = ConnectionFrameReport::default();
    if connection_request::codec::is_request(&bytes) {
        // Request acceptance proves the invite/bootstrap authorization before
        // producing an ack. The raw request event is also admitted so the
        // connection projector can atomically write the connection row and the
        // route learned from receive metadata.
        let event = connection_request::codec::decode(&bytes)?;
        let authorized = authorized_invite(store, &event.bootstrap_hash)?
            .ok_or_else(|| "invite private key rejected".to_string())?;
        let mut record = connection_request::codec::record_from_bytes(bytes.clone())?;
        record.dependencies.push(authorized.invite_secret_event_id);
        result.records.push(record_with_bootstrap_receive_metadata(
            record,
            metadata,
            local.endpoint,
            authorized.invite_secret_event_id,
            authorized.workspace_id,
        ));
        result.bootstrap_scope = authorized.workspace_id.map(|workspace_id| BootstrapScope {
            workspace_id,
            authorized_endpoint: event.from_endpoint,
        });
        let connection = connection_request::commands::accept(local, true, bytes)?;
        apply_connection_result(connection, &mut result);
        if let Some(workspace_id) = authorized.workspace_id {
            result.outgoing.extend(bootstrap_identity_events(
                store,
                &local,
                event.from_endpoint,
                workspace_id,
            )?);
        }
    } else if connection_ack::codec::is_ack(&bytes) {
        // Ack projection validates the original request through the ack's
        // declared dependency. The worker only checks local endpoint shape
        // before admitting the ack and reporting the derived connection id.
        result.records.push(record_with_endpoint_receive_metadata(
            connection_ack::codec::record_from_bytes(bytes.clone())?,
            metadata,
            local.endpoint,
        ));
        let connection = connection_ack::commands::accept(local, bytes)?;
        apply_connection_result(connection, &mut result);
    } else {
        return Err("unknown connection event".to_string());
    }
    Ok(result)
}

fn bootstrap_identity_events(
    store: &Store,
    local: &endpoint::types::EndpointKeypair,
    recipient_endpoint: endpoint::types::EndpointId,
    workspace_id: [u8; 32],
) -> Result<Vec<Vec<u8>>, String> {
    let max_timestamp =
        event_schema::max_timestamp(store).map_err(|err| format!("load max timestamp: {err}"))?;
    let entries = event_schema::event_index_entries_in_timestamp_range(store, 0, max_timestamp)
        .map_err(|err| format!("load workspace events: {err}"))?;
    let mut out = Vec::new();
    for entry in entries {
        if entry.workspace_id != Some(workspace_id) {
            continue;
        }
        let Some(bytes) = event_schema::event_bytes(store, &entry.event_id)
            .map_err(|err| format!("load event bytes: {err}"))?
        else {
            continue;
        };
        if !is_identity_bootstrap_event(&bytes)? {
            continue;
        }
        out.push(transit::commands::create_bootstrap(
            local,
            recipient_endpoint,
            &bytes,
        )?);
    }
    Ok(out)
}

fn is_identity_bootstrap_event(bytes: &[u8]) -> Result<bool, String> {
    match bytes.first().copied() {
        Some(workspace::codec::TYPE_WORKSPACE) => Ok(true),
        Some(signed::codec::TYPE_SIGNED) => {
            let envelope = signed::codec::decode(bytes)?;
            Ok(matches!(
                envelope.inner_type,
                admin::codec::TYPE_ADMIN
                    | user_invite::codec::TYPE_USER_INVITE
                    | user::codec::TYPE_USER
                    | device_invite::codec::TYPE_DEVICE_INVITE
                    | endpoint_shared::codec::TYPE_ENDPOINT_SHARED
            ))
        }
        _ => Ok(false),
    }
}

fn is_join_bootstrap_event(bytes: &[u8]) -> Result<bool, String> {
    if bytes.first().copied() != Some(signed::codec::TYPE_SIGNED) {
        return Ok(false);
    }
    let envelope = signed::codec::decode(bytes)?;
    Ok(matches!(
        envelope.inner_type,
        user::codec::TYPE_USER
            | device_invite::codec::TYPE_DEVICE_INVITE
            | endpoint_shared::codec::TYPE_ENDPOINT_SHARED
    ))
}

fn record_with_bootstrap_receive_metadata(
    record: EventRecord,
    metadata: UnwrappedFrameMetadata,
    local_endpoint: endpoint::types::EndpointId,
    invite_secret_event_id: types::ConnectionId,
    workspace_id: Option<[u8; 32]>,
) -> ReceivedRecord {
    ReceivedRecord::with_receive(
        record,
        ReceiveMetadata::bootstrap_invite(
            metadata.frame.origin,
            local_endpoint,
            metadata.sender_endpoint,
            metadata.frame.remember_origin,
            invite_secret_event_id,
            workspace_id,
        ),
    )
}

fn record_with_endpoint_receive_metadata(
    record: EventRecord,
    metadata: UnwrappedFrameMetadata,
    local_endpoint: endpoint::types::EndpointId,
) -> ReceivedRecord {
    ReceivedRecord::with_receive(
        record,
        ReceiveMetadata::endpoint_receive(
            metadata.frame.origin,
            local_endpoint,
            metadata.sender_endpoint,
            metadata.frame.remember_origin,
        ),
    )
}

fn apply_connection_result(
    connection: CommandOutput<types::InboundConnection>,
    result: &mut ConnectionFrameReport,
) {
    // Commands return proposed events. This worker strips the proposal wrapper
    // because its caller will admit every returned record through the common
    // event-module worker.
    result.records.extend(
        connection
            .events
            .into_iter()
            .map(ProposedEvent::into_record)
            .map(ReceivedRecord::new),
    );
    result.outgoing.extend(connection.value.outgoing);
    if connection.value.connection_id.is_some() {
        result.established_routes += 1;
    }
}

#[cfg(test)]
mod tests {
    use crate::core::network_queues::NetworkSource;
    use crate::protocol::event_modules::content::content_event;
    use crate::protocol::event_modules::types::event_id;
    use crate::protocol::Protocol;

    use super::*;

    fn keypair() -> endpoint::types::EndpointKeypair {
        endpoint::commands::create_local_keypair().value
    }

    fn connected_store(
        connection_id: types::ConnectionId,
        local: endpoint::types::EndpointKeypair,
        remote: endpoint::types::EndpointKeypair,
    ) -> Store {
        let store = Protocol::open_memory_store().expect("open store");
        let mut rows = endpoint::projector::local_endpoint(local);
        rows.push(schema::connection_row(connection_id, remote.endpoint));
        store
            .insert_table_rows(rows)
            .expect("insert connection row");
        store
    }

    fn add_endpoint_membership(
        store: &Store,
        workspace_id: [u8; 32],
        endpoint_shared_id: [u8; 32],
        endpoint: endpoint::types::EndpointKeypair,
    ) {
        let event = endpoint_shared::types::EndpointSharedEvent {
            created_at_ms: 1,
            workspace_id,
            user_authority_event_id: [44; 32],
            endpoint_id: endpoint.endpoint,
            signing_public_key: endpoint.signing_public_key,
            device_name: "test".to_string(),
        };
        store
            .insert_table_rows(vec![endpoint_shared::schema::endpoint_membership_row(
                endpoint_shared_id,
                [45; 32],
                &event,
            )])
            .expect("insert endpoint membership");
    }

    fn inbound_from_remote(
        remote: &endpoint::types::EndpointKeypair,
        local_endpoint: endpoint::types::EndpointId,
        connection_id: types::ConnectionId,
        inners: Vec<Vec<u8>>,
    ) -> InboundNetworkRow {
        let bytes = transit::commands::create_connection_batch(
            remote,
            local_endpoint,
            connection_id,
            inners,
        )
        .expect("create transit batch");
        InboundNetworkRow::new(
            NetworkSource::new("127.0.0.1:41001".parse().expect("test addr")),
            bytes,
        )
    }

    fn bootstrap_inbound_from_remote(
        remote: &endpoint::types::EndpointKeypair,
        local_endpoint: endpoint::types::EndpointId,
        inner: Vec<u8>,
    ) -> InboundNetworkRow {
        let bytes = transit::commands::create_bootstrap(remote, local_endpoint, &inner)
            .expect("create bootstrap transit");
        InboundNetworkRow::new(
            NetworkSource::new("127.0.0.1:41001".parse().expect("test addr")),
            bytes,
        )
    }

    fn signed_content_bytes(workspace_id: [u8; 32]) -> Vec<u8> {
        content_event::commands::generate(workspace_id, [8; 32], [9; 32], 1, 1, 8)
            .expect("generate signed content")
            .events[0]
            .record()
            .canonical_bytes
            .clone()
    }

    #[test]
    fn drain_outbox_routes_removes_rows_whose_bytes_are_gone() {
        let store = Protocol::open_memory_store().expect("open store");
        let local = endpoint::commands::create_local_keypair().value;
        let connection_id = [3; 32];
        let missing_event_id = [4; 32];
        let addr = "127.0.0.1:41000"
            .parse::<SocketAddr>()
            .expect("test socket addr");
        let mut rows = endpoint::projector::local_endpoint(local);
        rows.extend([
            schema::transport_target_row(connection_id, addr),
            schema::outbox_row(connection_id, missing_event_id),
        ]);
        store
            .insert_table_rows(rows)
            .expect("insert route and stale outbox row");

        let output =
            run(&store, &Protocol::new(), Work::ExchangeOutboundRoutes).expect("drain outbox");

        assert_eq!(
            output,
            Output::RoutesExchanged(types::RouteExchangeReport::default())
        );
        assert_eq!(
            store
                .table_row_count(schema::OUTBOX)
                .expect("count outbox rows"),
            0
        );
    }

    #[test]
    fn daemon_can_idle_without_local_endpoint_or_routes() {
        let store = Protocol::open_memory_store().expect("open store");

        let output = run(
            &store,
            &Protocol::new(),
            Work::RunDaemon {
                options: types::DaemonOptions {
                    listen: "127.0.0.1:0".parse().expect("test listen addr"),
                    duration: Some(std::time::Duration::from_millis(1)),
                    idle: std::time::Duration::from_millis(1),
                    ready_batch: DEFAULT_DAEMON_READY_BATCH,
                },
            },
        )
        .expect("daemon can idle on an empty store");

        let Output::DaemonRan(report) = output else {
            panic!("expected daemon report");
        };
        assert!(
            report.local_addr.is_some(),
            "daemon should bind even before endpoint creation"
        );
        assert!(
            report.sync_rounds > 0,
            "daemon should keep looping with no endpoint and no routes"
        );
    }

    #[test]
    fn rejects_local_only_events_received_inside_connection_transit() {
        let local = keypair();
        let remote = keypair();
        let connection_id = [3; 32];
        let store = connected_store(connection_id, local, remote);
        let local_only = endpoint::commands::create_local_keypair().events[0]
            .record()
            .canonical_bytes
            .clone();
        let local_only_id = event_id(&local_only);
        let inbound = inbound_from_remote(&remote, local.endpoint, connection_id, vec![local_only]);

        let err = ingest_network(&store, &Protocol::new(), inbound, false, None)
            .expect_err("remote local-only event must reject");

        assert!(err.contains("connection durable ingress only accepts shared events"));
        assert!(
            !event_schema::has_event(&store, &local_only_id).expect("check event table"),
            "rejected local-only event must not be stored"
        );
    }

    #[test]
    fn rejects_remote_workspace_event_when_sender_is_not_a_member() {
        let local = keypair();
        let remote = keypair();
        let connection_id = [3; 32];
        let store = connected_store(connection_id, local, remote);
        let content = signed_content_bytes([7; 32]);
        let content_id = event_id(&content);
        let inbound = inbound_from_remote(&remote, local.endpoint, connection_id, vec![content]);

        let err = ingest_network(&store, &Protocol::new(), inbound, false, None)
            .expect_err("out-of-scope workspace event must reject");

        assert!(
            err.contains("connection durable ingress rejected event outside sender workspace"),
            "{err}"
        );
        assert!(
            !event_schema::has_event(&store, &content_id).expect("check event table"),
            "out-of-scope remote event must not be stored"
        );
    }

    #[test]
    fn rejects_non_identity_events_inside_bootstrap_transit() {
        let local = keypair();
        let remote = keypair();
        let workspace_id = [7; 32];
        let store = Protocol::open_memory_store().expect("open store");
        store
            .insert_table_rows(endpoint::projector::local_endpoint(local))
            .expect("insert local endpoint");
        let content = signed_content_bytes(workspace_id);
        let content_id = event_id(&content);
        let inbound = bootstrap_inbound_from_remote(&remote, local.endpoint, content);

        let err = ingest_network(
            &store,
            &Protocol::new(),
            inbound,
            false,
            Some(BootstrapScope {
                workspace_id,
                authorized_endpoint: remote.endpoint,
            }),
        )
        .expect_err("bootstrap content must reject");

        assert!(
            err.contains("bootstrap durable ingress only accepts identity bootstrap events"),
            "{err}"
        );
        assert!(
            !event_schema::has_event(&store, &content_id).expect("check event table"),
            "rejected bootstrap content must not be stored"
        );
    }

    #[test]
    fn admits_remote_shareable_events_to_main_pipeline_after_workspace_check() {
        let local = keypair();
        let remote = keypair();
        let connection_id = [3; 32];
        let workspace_id = [7; 32];
        let store = connected_store(connection_id, local, remote);
        add_endpoint_membership(&store, workspace_id, [20; 32], local);
        add_endpoint_membership(&store, workspace_id, [21; 32], remote);
        let content = signed_content_bytes(workspace_id);
        let content_id = event_id(&content);
        let inbound = inbound_from_remote(&remote, local.endpoint, connection_id, vec![content]);

        let output = ingest_network(&store, &Protocol::new(), inbound, false, None)
            .expect("shareable content is admitted");

        assert_eq!(
            output,
            NetworkIngestResult {
                received_events: 1,
                ..NetworkIngestResult::default()
            }
        );
        assert!(
            event_schema::has_event(&store, &content_id).expect("check event table"),
            "shareable remote event should enter durable admission"
        );
        let counts = event_schema::status_counts(&store).expect("status counts");
        assert_eq!(
            counts.blocked, 1,
            "main pipeline should own dependency blocking"
        );
    }
}

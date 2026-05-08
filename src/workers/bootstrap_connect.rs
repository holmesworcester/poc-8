//! Outbound invite bootstrap exchange.
//!
//! This worker owns the active TCP behavior needed by the peer accepting an
//! invite before a steady-state connection route has done useful work. It does
//! not own inbound daemon sockets; those are accepted and admitted by
//! `transit_in`.
//!
//! Realm of responsibility:
//!
//! - send unscoped invite connection requests for the `connect` CLI path
//! - send one invite-key batch for identity invite acceptance
//! - receive same-stream invite-bootstrap response frames on the outbound accept
//!   connection
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

use std::net::SocketAddr;

use crate::core::network_queues::{self, InboundNetworkRow, NetworkTarget, OutboundNetworkRow};
use crate::core::store::Store;
use crate::core::tcp;
use crate::protocol::event_modules::connection::{connection_request, schema, transit, types};
use crate::protocol::event_modules::identity::{endpoint, invite, invite_accepted};
use crate::protocol::event_modules::types::EventRecord;
use crate::workers::pipeline_helpers::event_pipeline::{self as pipeline, EventRegistry};
use crate::workers::{event_admission, transit_in};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Work {
    ConnectInvite {
        invite: String,
        /// Caller-provided steady-state listen address to advertise inside
        /// the request body. CLI dispatch reads `core::daemon::current_listen_addr`
        /// from the lock file to populate this. The value remains request
        /// metadata; retry routing uses the invite address this side dialed.
        from_listen_addr: Option<SocketAddr>,
    },
    ConnectInviteWithInitialEvents {
        invite: String,
        records: Vec<EventRecord>,
        from_listen_addr: Option<SocketAddr>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    Connected(types::ConnectReport),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ExchangeState {
    sent_events: usize,
    received_events: usize,
    connection_ids: Vec<types::ConnectionId>,
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
    remember_connected_routes(store, request.addr, &state.connection_ids)?;
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
    // on the same stream. A local transport_target row is written when the
    // caller supplies a listener (i.e., a daemon is running) so the acceptor's
    // daemon can keep retrying the invite address after this stream closes.
    let request_output =
        connection_request::commands::create_with_local(store, &invite_link, from_listen_addr)
            .map_err(|err| format!("create connection request: {err}"))?;
    let (request, _) = pipeline::run(store, registry, request_output)
        .map_err(|err| format!("record connection request: {err}"))?;
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
    if from_listen_addr.is_some() {
        // A running local daemon can keep using the invite address after the
        // responder's connection event has arrived and named the real
        // connection id.
        remember_connected_routes(store, parsed_invite.addr, &state.connection_ids)?;
    }
    Ok(Output::Connected(types::ConnectReport {
        addr: parsed_invite.addr,
        sent_events: state.sent_events,
        received_events: state.received_events,
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
    let output = transit_in::process_inbound_exchange(store, registry, inbound)?;
    state.received_events += output.received_events;
    for connection_id in output.connection_ids {
        if !state
            .connection_ids
            .iter()
            .any(|known| known == &connection_id)
        {
            state.connection_ids.push(connection_id);
        }
    }
    Ok(output.outbound_rows)
}

fn remember_connected_routes(
    store: &Store,
    addr: SocketAddr,
    connection_ids: &[types::ConnectionId],
) -> Result<(), String> {
    if connection_ids.is_empty() {
        return Ok(());
    }
    let rows = connection_ids
        .iter()
        .map(|connection_id| schema::transport_target_row(*connection_id, addr))
        .collect();
    store
        .insert_table_rows(rows)
        .map(|_| ())
        .map_err(|err| format!("remember connection route: {err}"))
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
        if !event_admission::is_identity_bootstrap_event(&record.canonical_bytes)? {
            return Err("initial invite event must be an identity bootstrap event".to_string());
        }
        inners.push(record.canonical_bytes);
    }
    Ok(inners)
}

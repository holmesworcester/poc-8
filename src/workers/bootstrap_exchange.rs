//! Finite stream exchange for invite/bootstrap CLI workflows.
//!
//! Inputs: explicit connect or serve work from CLI tests and operator commands.
//! State: local endpoint keys, invite-derived request facts, and queued inbound
//! byte rows for one stream.
//! Step: write initial opaque frames, admit each returned frame through transit
//! projection and canonical admission, and answer invite-backed requests with
//! workspace identity bootstrap facts.
//! Outputs: opaque outbound network rows for the same stream plus ordinary
//! canonical admission side effects.
//! Consume: inbound rows are consumed by the core stream pump after this worker
//! accepts responsibility for them; canonical rows are consumed by event
//! admission.
//! Failure: malformed or unauthorized frames stop the stream exchange and leave
//! durable fact admission rolled back by the common pipeline.
//! Fairness: serve accepts a caller-specified finite number of streams; each
//! inbound callback handles one frame and bounded worker drains.

use std::net::SocketAddr;

use crate::core::network_queues::{self, InboundNetworkRow, NetworkTarget, OutboundNetworkRow};
use crate::core::store::Store;
use crate::core::tcp;
use crate::protocol::event_modules::connection::{connection_request, schema, transit, types};
use crate::protocol::event_modules::identity::{endpoint, invite};
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::types::{event_id, EventId, EventRecord};
use crate::workers::common::event_pipeline::{
    self as pipeline, DrainUntilIdle, EventRegistry, ProjectionOutput,
};
use crate::workers::{event_admission, schema as worker_schema};

const READY_BATCH: usize = 4096;

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

pub fn run<R>(store: &Store, registry: &R, work: Work) -> Result<Output, String>
where
    R: EventRegistry,
{
    match work {
        Work::ConnectInvite { invite } => connect(store, registry, invite, Vec::new()),
        Work::ConnectInviteWithInitialEvents { invite, records } => {
            connect(store, registry, invite, records)
        }
        Work::Serve {
            listen,
            accept_count,
        } => serve(store, registry, listen, accept_count),
    }
}

fn connect<R>(
    store: &Store,
    registry: &R,
    invite_link: String,
    initial_records: Vec<EventRecord>,
) -> Result<Output, String>
where
    R: EventRegistry,
{
    let parsed_invite = invite::commands::parse(&invite_link)?;
    let output = connection_request::commands::create_with_local(store, &invite_link)
        .map_err(|err| format!("create connection request: {err}"))?;
    let (request, _) = pipeline::run(store, registry, output)
        .map_err(|err| format!("record connection request: {err}"))?;
    store
        .insert_table_rows(vec![schema::transport_target_row(
            request.connection_id,
            request.addr,
        )])
        .map_err(|err| format!("remember connection route: {err}"))?;
    let local = local_endpoint(store)?;
    let mut frames = vec![request.bytes];
    frames.extend(initial_bootstrap_frames(
        local,
        &parsed_invite,
        initial_records,
    )?);

    let target = NetworkTarget::new(request.addr);
    let state = tcp::connect_exchange(
        store,
        target,
        network_queues::outbound_rows(target, frames),
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
    let inners = canonical_rows(&output)?;
    store
        .insert_table_rows(output.rows)
        .map_err(|err| format!("stage canonical input: {err}"))?;
    let admitted = event_admission::run(
        store,
        registry,
        event_admission::Work::Drain {
            limit: inners.len().max(1),
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

    let mut frames = Vec::new();
    for inner in inners {
        if connection_request::codec::is_request(&inner) {
            note_recent_peer_addr_for_request(store, &inner, target.addr())?;
            frames.extend(bootstrap_identity_frames_for_request(store, &inner)?);
        }
    }
    Ok(network_queues::outbound_rows(target, frames))
}

/// Record the inbound source address against the derived connection id so
/// debuggability tools (`connections`) can show the most recent observed peer
/// address. This is intentionally separate from `TRANSPORT_TARGETS` because
/// inbound source ports are usually ephemeral and must not be promoted into
/// dial-back routes used by sync.
fn note_recent_peer_addr_for_request(
    store: &Store,
    request_bytes: &[u8],
    addr: std::net::SocketAddr,
) -> Result<(), String> {
    let request = match connection_request::codec::decode(request_bytes) {
        Ok(request) => request,
        Err(_) => return Ok(()),
    };
    let local = local_endpoint(store)?;
    if request.to_endpoint != local.endpoint {
        return Ok(());
    }
    let request_id = event_id(request_bytes);
    let connection_id = types::connection_id(&request_id, &local.endpoint);
    store
        .insert_table_rows(vec![schema::recent_peer_addr_row(connection_id, addr)])
        .map_err(|err| format!("record recent peer addr: {err}"))?;
    Ok(())
}

fn canonical_rows(output: &ProjectionOutput) -> Result<Vec<Vec<u8>>, String> {
    output
        .rows
        .iter()
        .filter(|row| row.table == worker_schema::CANONICAL_IN)
        .map(|row| worker_schema::decode_canonical_in(&row.value).map(|decoded| decoded.0))
        .collect()
}

fn initial_bootstrap_frames(
    local: endpoint::types::EndpointKeypair,
    parsed_invite: &invite::types::Invite,
    records: Vec<EventRecord>,
) -> Result<Vec<Vec<u8>>, String> {
    if records.is_empty() {
        return Ok(Vec::new());
    }
    if !parsed_invite.identity_scope {
        return Err("initial invite events require an identity-scoped invite".to_string());
    }
    let mut frames = Vec::with_capacity(records.len());
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
        frames.push(transit::commands::create_bootstrap(
            &local,
            parsed_invite.endpoint,
            &record.canonical_bytes,
        )?);
    }
    Ok(frames)
}

fn bootstrap_identity_frames_for_request(
    store: &Store,
    request_bytes: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    let local = local_endpoint(store)?;
    let request = connection_request::codec::decode(request_bytes)?;
    let request_id = event_id(request_bytes);
    let connection_id = types::connection_id(&request_id, &local.endpoint);
    let Some(workspace_id) = schema::bootstrap_workspace_id(store, connection_id)? else {
        return Ok(Vec::new());
    };
    let mut frames = Vec::new();
    for bytes in workspace_identity_event_bytes(store, workspace_id)? {
        frames.push(transit::commands::create_bootstrap(
            &local,
            request.from_endpoint,
            &bytes,
        )?);
    }
    Ok(frames)
}

fn workspace_identity_event_bytes(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<Vec<u8>>, String> {
    let entries = event_schema::event_index_entries_in_timestamp_range(store, 0, u64::MAX)
        .map_err(|err| format!("load workspace events: {err}"))?;
    let mut out = Vec::new();
    for entry in entries {
        if entry.workspace_id != Some(workspace_id) {
            continue;
        }
        let Some(bytes) = event_schema::event_bytes(store, &entry.event_id)
            .map_err(|err| format!("load workspace event bytes: {err}"))?
        else {
            continue;
        };
        if !crate::protocol::event_modules::is_identity_bootstrap_event(&bytes)? {
            continue;
        }
        out.push(bytes);
    }
    Ok(out)
}

fn local_endpoint(store: &Store) -> Result<endpoint::types::EndpointKeypair, String> {
    endpoint::commands::local_keypair(store)?.ok_or_else(|| "local endpoint is missing".to_string())
}

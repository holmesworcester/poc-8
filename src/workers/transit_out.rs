//! Transit out worker.
//!
//! Inputs: `transit.out`, keyed by `(connection_id, event_id)`.
//! State: connection routes, endpoint scope policy, and transit wrapping.
//! Step: for each route, resolve queued event ids to canonical bytes, batch
//! them into encrypted transit frames, and hand opaque bytes to core networking.
//! Outputs: `core.network.outbound`.
//! Consume: transit out rows are deleted only after core reports the
//! corresponding outbound network rows were sent.
//! Failure: a failed route can be reported or ignored according to the caller's
//! `fail_on_route_error` policy; unsent transit out rows remain queued.
//! Fairness: one exchange pass is route-bounded and each route batches at a
//! fixed plaintext-size cap.

use std::{cell::RefCell, collections::HashMap, net::SocketAddr, str::FromStr};

use crate::core::daemon::{StepContext, Worker};
use crate::core::network_queues::{self, NetworkTarget, OutboundNetworkRow};
use crate::core::store::Store;
use crate::core::tcp;
use crate::protocol::event_modules::connection::{schema, transit, types};
use crate::protocol::event_modules::identity::endpoint;
use crate::protocol::event_modules::schema as event_schema;
use crate::workers::schema as worker_schema;
use crate::workers::DaemonWorkerContext;

/// Opaque bytes prepared for one route after draining protocol out rows.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OutboundSync {
    target: NetworkTarget,
    outgoing: Vec<OutboundNetworkRow>,
    sent_transit_out: Vec<Vec<Vec<u8>>>,
}

/// Opaque transit bytes ready for one concrete transport target.
///
/// `sent_transit_out` carries the protocol out keys represented by `outgoing`.
/// The caller deletes those rows only after it has committed the corresponding
/// core outbound network rows.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OutboundTransit {
    target: SocketAddr,
    outgoing: Vec<Vec<u8>>,
    sent_transit_out: Vec<Vec<Vec<u8>>>,
}

/// Result of draining one connection's protocol out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DrainedTransitOut {
    pub outgoing: Vec<Vec<u8>>,
    pub sent_transit_out: Vec<Vec<Vec<u8>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TransportRoute {
    connection_id: types::ConnectionId,
    addr: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TransitOutItem {
    key: worker_schema::TransitOutKey,
    event_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TransitOutDrain {
    items: Vec<TransitOutItem>,
    stale_keys: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SendReport {
    sent_events: usize,
    received_events: usize,
}

const TRANSIT_TARGET_PLAINTEXT_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Work {
    SendConnectionRequest {
        connection_id: types::ConnectionId,
        addr: SocketAddr,
        bytes: Vec<u8>,
    },
    ExchangeRoutes {
        fail_on_route_error: bool,
    },
    MarkSent {
        transit_out_keys: Vec<Vec<u8>>,
    },
}

pub fn run(store: &Store, work: Work) -> Result<types::RouteExchangeReport, String> {
    match work {
        Work::SendConnectionRequest {
            connection_id,
            addr,
            bytes,
        } => send_connection_request(store, connection_id, addr, bytes),
        Work::ExchangeRoutes {
            fail_on_route_error,
        } => exchange_outbound_routes(store, fail_on_route_error),
        Work::MarkSent { transit_out_keys } => {
            mark_transit_out_sent(store, transit_out_keys)?;
            Ok(types::RouteExchangeReport::default())
        }
    }
}

fn send_connection_request(
    store: &Store,
    connection_id: types::ConnectionId,
    addr: SocketAddr,
    bytes: Vec<u8>,
) -> Result<types::RouteExchangeReport, String> {
    store
        .insert_table_rows(vec![schema::transport_target_row(connection_id, addr)])
        .map_err(|err| format!("remember connection route: {err}"))?;

    let target = NetworkTarget::new(addr);
    tcp::send_once(
        store,
        target,
        vec![OutboundNetworkRow::new(target, bytes)],
        (),
        |_, _| Ok(()),
    )?;
    Ok(types::RouteExchangeReport {
        routes_synced: 1,
        sent_events: 1,
        ..types::RouteExchangeReport::default()
    })
}

pub(crate) fn daemon_worker<C>() -> Worker<C>
where
    C: DaemonWorkerContext,
{
    Worker {
        name: "transit_out",
        run: daemon_step::<C>,
    }
}

fn daemon_step<C>(ctx: &mut StepContext<'_, C>) -> Result<(), String>
where
    C: DaemonWorkerContext,
{
    let app = &*ctx.app;
    let report = run(
        app.store(),
        Work::ExchangeRoutes {
            fail_on_route_error: false,
        },
    )?;
    ctx.report.add("routes_synced", report.routes_synced);
    ctx.report.add("failed_routes", report.failed_routes);
    ctx.report.add("sent_events", report.sent_events);
    ctx.report.add("received_events", report.received_events);
    Ok(())
}

fn exchange_outbound_routes(
    store: &Store,
    fail_on_route_error: bool,
) -> Result<types::RouteExchangeReport, String> {
    let mut summary = types::RouteExchangeReport::default();
    for outbound in drain_transit_out_routes(store).map_err(|err| format!("drain out: {err}"))? {
        let outbound = outbound_sync(outbound);
        let target = outbound.target;
        match exchange_outbound_route(store, outbound) {
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

fn exchange_outbound_route(store: &Store, outbound: OutboundSync) -> Result<SendReport, String> {
    let sent_transit_out = RefCell::new(HashMap::new());
    let sent_events = outbound
        .sent_transit_out
        .iter()
        .map(Vec::len)
        .sum::<usize>();
    remember_sent_rows(
        &sent_transit_out,
        &outbound.outgoing,
        &outbound.sent_transit_out,
    )?;
    tcp::send_once(
        store,
        outbound.target,
        outbound.outgoing,
        SendReport::default(),
        |rows, _| mark_sent_network_rows(store, rows, &sent_transit_out),
    )
    .map(|mut report| {
        report.sent_events += sent_events;
        report
    })
}

fn outbound_sync(outbound: OutboundTransit) -> OutboundSync {
    let target = NetworkTarget::new(outbound.target);
    OutboundSync {
        target,
        outgoing: network_queues::outbound_rows(target, outbound.outgoing),
        sent_transit_out: outbound.sent_transit_out,
    }
}

fn drain_transit_out_routes(store: &Store) -> Result<Vec<OutboundTransit>, String> {
    // Route draining is deliberately route-based, not global "send everything".
    // Slow or absent targets should only starve their own route.
    let routes = routes(store)?;
    if routes.is_empty() {
        return Ok(Vec::new());
    }
    let local = local_endpoint(store)?;
    let mut outbound = Vec::new();
    for route in routes {
        let drained = drain_and_wrap_transit_out_for_connection(store, local, route.connection_id)?;
        if drained.outgoing.is_empty() {
            continue;
        }
        outbound.push(OutboundTransit {
            target: route.addr,
            outgoing: drained.outgoing,
            sent_transit_out: drained.sent_transit_out,
        });
    }
    Ok(outbound)
}

fn drain_and_wrap_transit_out_for_connection(
    store: &Store,
    local: endpoint::types::EndpointKeypair,
    connection_id: types::ConnectionId,
) -> Result<DrainedTransitOut, String> {
    let out = transit_out_items_for_connection(store, connection_id)?;
    if !out.stale_keys.is_empty() {
        store
            .delete_table_rows(worker_schema::TRANSIT_OUT, out.stale_keys)
            .map_err(|err| format!("delete stale out rows: {err}"))?;
    }
    let items = out.items;
    if items.is_empty() {
        return Ok(DrainedTransitOut::default());
    }
    let remote = schema::remote_endpoint(store, connection_id)?;
    let batches = batch_transit_out_items(items);
    let mut outgoing = Vec::with_capacity(batches.len());
    let mut sent_transit_out = Vec::with_capacity(batches.len());
    for batch in batches {
        // The queue names canonical events by id. This boundary only resolves
        // bytes and wraps them for the established connection; local is the
        // encryption sender key, not semantic state.
        let mut inner_events = Vec::with_capacity(batch.len());
        let mut batch_transit_out = Vec::with_capacity(batch.len());
        for item in batch {
            inner_events.push(item.event_bytes);
            batch_transit_out.push(item.key.to_bytes());
        }
        outgoing.push(transit::commands::create_connection_batch(
            &local,
            remote,
            connection_id,
            inner_events,
        )?);
        sent_transit_out.push(batch_transit_out);
    }
    Ok(DrainedTransitOut {
        outgoing,
        sent_transit_out,
    })
}

fn batch_transit_out_items(items: Vec<TransitOutItem>) -> Vec<Vec<TransitOutItem>> {
    let mut batches: Vec<Vec<TransitOutItem>> = Vec::new();
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

pub(crate) fn remember_sent_rows(
    sent_transit_out: &RefCell<HashMap<Vec<u8>, Vec<Vec<u8>>>>,
    rows: &[OutboundNetworkRow],
    transit_out_keys: &[Vec<Vec<u8>>],
) -> Result<(), String> {
    if transit_out_keys.is_empty() {
        return Ok(());
    }
    if transit_out_keys.len() > rows.len() {
        return Err("more out keys than outbound network rows".to_string());
    }
    let first = rows.len() - transit_out_keys.len();
    let mut sent_transit_out = sent_transit_out.borrow_mut();
    for (row, row_transit_out_keys) in rows[first..].iter().zip(transit_out_keys) {
        sent_transit_out
            .entry(row.key.clone())
            .or_default()
            .extend(row_transit_out_keys.iter().cloned());
    }
    Ok(())
}

pub(crate) fn mark_sent_network_rows(
    store: &Store,
    rows: &[OutboundNetworkRow],
    sent_transit_out: &RefCell<HashMap<Vec<u8>, Vec<Vec<u8>>>>,
) -> Result<(), String> {
    let mut transit_out_keys = Vec::new();
    {
        let mut sent_transit_out = sent_transit_out.borrow_mut();
        for row in rows {
            if let Some(mut row_transit_out_keys) = sent_transit_out.remove(&row.key) {
                transit_out_keys.append(&mut row_transit_out_keys);
            }
        }
    }
    mark_transit_out_sent(store, transit_out_keys)
}

fn mark_transit_out_sent(store: &Store, sent_transit_out: Vec<Vec<u8>>) -> Result<(), String> {
    if sent_transit_out.is_empty() {
        return Ok(());
    }
    // Delete only rows that have been converted into committed core outbound
    // network rows. A crash before this point may resend duplicate protocol
    // events, which is acceptable because event ids and out keys dedupe.
    store
        .delete_table_rows(worker_schema::TRANSIT_OUT, sent_transit_out)
        .map(|_| ())
        .map_err(|err| format!("delete sent out rows: {err}"))
}

fn local_endpoint(store: &Store) -> Result<endpoint::types::EndpointKeypair, String> {
    endpoint::commands::local_keypair(store)?.ok_or_else(|| "local endpoint is missing".to_string())
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

fn transit_out_items_for_connection(
    store: &Store,
    connection_id: types::ConnectionId,
) -> Result<TransitOutDrain, String> {
    // Transit out rows are id-only. Durable data resolves from the common event
    // store; connection-scoped protocol events resolve from the in-memory
    // connection byte cache populated by their projectors.
    let prefix = worker_schema::transit_out_prefix(connection_id);
    let rows = store
        .table_rows_with_key_prefix(worker_schema::TRANSIT_OUT, &prefix, 4096)
        .map_err(|err| format!("load out: {err}"))?;
    let mut drain = TransitOutDrain {
        items: Vec::with_capacity(rows.len()),
        stale_keys: Vec::new(),
    };
    for (key, _) in rows {
        let transit_out_key = worker_schema::decode_transit_out_key(&key)?;
        let Some(event_bytes) = resolve_transit_out_event_bytes(store, &transit_out_key.event_id)?
        else {
            drain.stale_keys.push(key);
            continue;
        };
        drain.items.push(TransitOutItem {
            key: transit_out_key,
            event_bytes,
        });
    }
    Ok(drain)
}

fn resolve_transit_out_event_bytes(
    store: &Store,
    event_id: &[u8; 32],
) -> Result<Option<Vec<u8>>, String> {
    if let Some(bytes) = event_schema::event_bytes(store, event_id)
        .map_err(|err| format!("load durable out event: {err}"))?
    {
        return Ok(Some(bytes));
    }
    store
        .table_row(schema::CONNECTION_SCOPED_EVENTS, event_id)
        .map_err(|err| format!("load connection-scoped out event: {err}"))
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::identity::endpoint;
    use crate::protocol::Protocol;

    use super::*;

    #[test]
    fn exchange_routes_removes_rows_whose_bytes_are_gone() {
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
            worker_schema::transit_out_row(connection_id, missing_event_id),
        ]);
        store
            .insert_table_rows(rows)
            .expect("insert route and stale out row");

        let output = run(
            &store,
            Work::ExchangeRoutes {
                fail_on_route_error: true,
            },
        )
        .expect("drain out");

        assert_eq!(output, types::RouteExchangeReport::default());
        assert_eq!(
            store
                .table_row_count(worker_schema::TRANSIT_OUT)
                .expect("count out rows"),
            0
        );
    }
}

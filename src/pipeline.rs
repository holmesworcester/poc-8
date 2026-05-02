use std::net::SocketAddr;

use crate::event_modules::{connection, sync};
use crate::store::Store;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IngestOptions {
    pub record_transport_target: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IngestResult {
    pub outgoing: Vec<Vec<u8>>,
    pub established_connections: usize,
    pub sent_events: usize,
    pub received_events: usize,
}

pub fn start_sync(
    store: &Store,
    route: connection::commands::TransportRoute,
) -> Result<IngestResult, String> {
    let mut result = IngestResult::default();
    let report = sync::commands::start(store, route.connection_id, |bytes| {
        result.outgoing.push(connection::commands::wrap_connection(
            store,
            route.connection_id,
            bytes,
        )?);
        Ok(())
    })?;
    result.sent_events += report.sent_events;
    result.received_events += report.received_events;
    Ok(result)
}

pub fn ingest_frame(
    store: &Store,
    origin: SocketAddr,
    bytes: Vec<u8>,
    options: IngestOptions,
) -> Result<IngestResult, String> {
    let transit = connection::commands::unwrap_transit(store, &bytes)?;
    if connection::commands::is_connection_event(&transit.inner) {
        return ingest_connection_frame(store, origin, transit.inner, options);
    }
    let connection_id = transit
        .connection_id
        .ok_or_else(|| "sync frame requires connection transit".to_string())?;
    ingest_sync_frame(store, connection_id, &transit.inner)
}

fn ingest_connection_frame(
    store: &Store,
    origin: SocketAddr,
    bytes: Vec<u8>,
    options: IngestOptions,
) -> Result<IngestResult, String> {
    let mut result = IngestResult::default();
    let connection = connection::commands::ingest_inner(store, bytes)?;
    if let Some(bytes) = connection.response {
        result.outgoing.push(bytes);
    }
    if let Some(connection_id) = connection.connection_id {
        if options.record_transport_target {
            connection::commands::record_transport_target(store, connection_id, origin)?;
        }
        result.established_connections += 1;
    }
    Ok(result)
}

fn ingest_sync_frame(
    store: &Store,
    connection_id: connection::codec::ConnectionId,
    bytes: &[u8],
) -> Result<IngestResult, String> {
    let mut result = IngestResult::default();
    let report = sync::commands::ingest_frame(store, connection_id, bytes, |bytes| {
        result.outgoing.push(connection::commands::wrap_connection(
            store,
            connection_id,
            bytes,
        )?);
        Ok(())
    })?;
    result.sent_events += report.sent_events;
    result.received_events += report.received_events;
    Ok(result)
}

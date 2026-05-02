use std::net::SocketAddr;

use crate::event_modules::{connection, sync};
use crate::store::Store;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IngestOptions<'a> {
    pub bootstrap_token: Option<&'a str>,
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
        result.outgoing.push(bytes);
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
    options: IngestOptions<'_>,
) -> Result<IngestResult, String> {
    if connection::commands::is_connection_event(&bytes) {
        return ingest_connection_frame(store, origin, bytes, options);
    }
    ingest_sync_frame(store, &bytes)
}

fn ingest_connection_frame(
    store: &Store,
    origin: SocketAddr,
    bytes: Vec<u8>,
    options: IngestOptions<'_>,
) -> Result<IngestResult, String> {
    let mut result = IngestResult::default();
    let connection = connection::commands::ingest(store, bytes, options.bootstrap_token)?;
    if let Some(bytes) = connection.response {
        result.outgoing.push(bytes);
    }
    if let Some(connection_id) = connection.connection_id {
        connection::commands::record_transport_target(store, connection_id, origin)?;
        result.established_connections += 1;
    }
    Ok(result)
}

fn ingest_sync_frame(store: &Store, bytes: &[u8]) -> Result<IngestResult, String> {
    let mut result = IngestResult::default();
    let report = sync::commands::ingest_frame(store, bytes, |bytes| {
        result.outgoing.push(bytes);
        Ok(())
    })?;
    result.sent_events += report.sent_events;
    result.received_events += report.received_events;
    Ok(result)
}

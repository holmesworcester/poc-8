use std::time::{SystemTime, UNIX_EPOCH};
use std::{net::SocketAddr, str::FromStr};

use crate::store::{EventId, Store};

use super::codec::{self, ConnectionEvent, ConnectionId, EndpointId};
use super::projector;
use super::tables;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundRequest {
    pub bytes: Vec<u8>,
    pub request_id: EventId,
    pub local_endpoint: EndpointId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundResult {
    pub response: Option<Vec<u8>>,
    pub connection_id: Option<ConnectionId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportRoute {
    pub connection_id: ConnectionId,
    pub addr: SocketAddr,
}

pub fn create_request(store: &Store, bootstrap_token: &str) -> Result<OutboundRequest, String> {
    let local_endpoint = ensure_local_endpoint(store)?;
    let request = ConnectionEvent::Request {
        from_endpoint: local_endpoint,
        nonce: nonce(),
        bootstrap_hash: codec::bootstrap_hash(bootstrap_token),
    };
    let bytes = codec::encode(&request);
    let request_id = codec::event_id(&bytes);
    apply(store, projector::project_outbound_request(bytes.clone())?)?;
    Ok(OutboundRequest {
        bytes,
        request_id,
        local_endpoint,
    })
}

pub fn accept_request(
    store: &Store,
    bytes: Vec<u8>,
    bootstrap_token: &str,
) -> Result<InboundResult, String> {
    let local_endpoint = ensure_local_endpoint(store)?;
    let projection = projector::project_inbound_request(
        bytes,
        local_endpoint,
        codec::bootstrap_hash(bootstrap_token),
    )?;
    let response = projection.response.clone();
    let connection_id = projection.connection_id;
    apply(store, projection)?;
    Ok(InboundResult {
        response,
        connection_id,
    })
}

pub fn accept_ack(
    store: &Store,
    bytes: Vec<u8>,
    local_endpoint: EndpointId,
    request_id: EventId,
) -> Result<InboundResult, String> {
    let projection = projector::project_inbound_ack(bytes, local_endpoint, request_id)?;
    let connection_id = projection.connection_id;
    apply(store, projection)?;
    Ok(InboundResult {
        response: None,
        connection_id,
    })
}

pub fn is_connection_event(bytes: &[u8]) -> bool {
    codec::decode(bytes).is_ok()
}

pub fn connection_count(store: &Store) -> Result<usize, String> {
    store
        .module_row_count(tables::CONNECTIONS)
        .map_err(|err| format!("count connections: {err}"))
}

pub fn connection_event_count(store: &Store) -> Result<usize, String> {
    store
        .module_row_count(tables::CONNECTION_EVENTS)
        .map_err(|err| format!("count connection events: {err}"))
}

pub fn record_transport_target(
    store: &Store,
    connection_id: ConnectionId,
    addr: SocketAddr,
) -> Result<(), String> {
    apply(
        store,
        projector::project_transport_target(connection_id, addr),
    )
}

pub fn transport_routes(store: &Store) -> Result<Vec<TransportRoute>, String> {
    let rows = store
        .module_rows(tables::TRANSPORT_TARGETS)
        .map_err(|err| format!("load transport targets: {err}"))?;
    rows.into_iter()
        .map(|(key, value)| {
            let connection_id = bytes_to_id(&key)?;
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

fn ensure_local_endpoint(store: &Store) -> Result<EndpointId, String> {
    if let Some(bytes) = store
        .module_row(tables::LOCAL_ENDPOINT, b"local")
        .map_err(|err| format!("load local endpoint: {err}"))?
    {
        return bytes_to_id(&bytes);
    }

    let endpoint = codec::endpoint_id(&nonce());
    apply(store, projector::project_local_endpoint(endpoint))?;
    Ok(endpoint)
}

fn apply(store: &Store, projection: projector::Projection) -> Result<(), String> {
    store
        .insert_module_rows(projection.rows)
        .map(|_| ())
        .map_err(|err| format!("apply connection projection: {err}"))
}

fn bytes_to_id(bytes: &[u8]) -> Result<EndpointId, String> {
    if bytes.len() != 32 {
        return Err("stored endpoint id is malformed".to_string());
    }
    let mut out = [0; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn nonce() -> [u8; 32] {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"topo-connection-nonce-v1");
    hasher.update(&now.to_be_bytes());
    hasher.update(&std::process::id().to_be_bytes());
    *hasher.finalize().as_bytes()
}

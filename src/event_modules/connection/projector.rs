use std::net::SocketAddr;

use crate::store::{EventId, ModuleRow};

use super::codec::{self, ConnectionEvent, ConnectionId, EndpointId};
use super::tables;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Projection {
    pub rows: Vec<ModuleRow>,
    pub response: Option<Vec<u8>>,
    pub connection_id: Option<ConnectionId>,
}

pub fn project_local_endpoint(endpoint: EndpointId, secret: [u8; 32]) -> Projection {
    Projection {
        rows: vec![
            ModuleRow {
                table: tables::LOCAL_ENDPOINT,
                key: b"local".to_vec(),
                value: endpoint.to_vec(),
            },
            ModuleRow {
                table: tables::LOCAL_ENDPOINT_SECRET,
                key: b"local".to_vec(),
                value: secret.to_vec(),
            },
        ],
        response: None,
        connection_id: None,
    }
}

pub fn project_outbound_request(bytes: Vec<u8>) -> Result<Projection, String> {
    let event = codec::decode(&bytes)?;
    let ConnectionEvent::Request { .. } = event else {
        return Err("outbound connection projection requires request".to_string());
    };
    let request_id = codec::event_id(&bytes);
    Ok(Projection {
        rows: vec![connection_event_row(request_id, bytes)],
        response: None,
        connection_id: None,
    })
}

pub fn project_inbound_request(
    bytes: Vec<u8>,
    local_endpoint: EndpointId,
    expected_bootstrap_hash: [u8; 32],
) -> Result<Projection, String> {
    let event = codec::decode(&bytes)?;
    let ConnectionEvent::Request {
        from_endpoint,
        bootstrap_hash,
        ..
    } = event
    else {
        return Err("expected connection request".to_string());
    };
    if bootstrap_hash != expected_bootstrap_hash {
        return Err("bootstrap token rejected".to_string());
    }

    let request_id = codec::event_id(&bytes);
    let connection_id = codec::connection_id(&request_id, &local_endpoint);
    let ack = ConnectionEvent::Ack {
        from_endpoint: local_endpoint,
        to_endpoint: from_endpoint,
        request_id,
        connection_id,
    };
    let ack_bytes = codec::encode(&ack);

    Ok(Projection {
        rows: vec![
            connection_event_row(request_id, bytes),
            connection_event_row(codec::event_id(&ack_bytes), ack_bytes.clone()),
            connection_row(connection_id, from_endpoint),
        ],
        response: Some(ack_bytes),
        connection_id: Some(connection_id),
    })
}

pub fn project_inbound_ack(
    bytes: Vec<u8>,
    local_endpoint: EndpointId,
    expected_request_id: EventId,
) -> Result<Projection, String> {
    let event = codec::decode(&bytes)?;
    let ConnectionEvent::Ack {
        from_endpoint,
        to_endpoint,
        request_id,
        connection_id,
    } = event
    else {
        return Err("expected connection ack".to_string());
    };
    if to_endpoint != local_endpoint {
        return Err("connection ack addressed to a different endpoint".to_string());
    }
    if request_id != expected_request_id {
        return Err("connection ack references a different request".to_string());
    }
    let expected_connection_id = codec::connection_id(&request_id, &from_endpoint);
    if connection_id != expected_connection_id {
        return Err("connection ack has an invalid connection id".to_string());
    }
    Ok(Projection {
        rows: vec![
            connection_event_row(codec::event_id(&bytes), bytes),
            connection_row(connection_id, from_endpoint),
        ],
        response: None,
        connection_id: Some(connection_id),
    })
}

pub fn project_transport_target(connection_id: ConnectionId, addr: SocketAddr) -> Projection {
    Projection {
        rows: vec![ModuleRow {
            table: tables::TRANSPORT_TARGETS,
            key: connection_id.to_vec(),
            value: addr.to_string().into_bytes(),
        }],
        response: None,
        connection_id: Some(connection_id),
    }
}

fn connection_event_row(event_id: EventId, bytes: Vec<u8>) -> ModuleRow {
    ModuleRow {
        table: tables::CONNECTION_EVENTS,
        key: event_id.to_vec(),
        value: bytes,
    }
}

fn connection_row(connection_id: ConnectionId, remote_endpoint: EndpointId) -> ModuleRow {
    ModuleRow {
        table: tables::CONNECTIONS,
        key: connection_id.to_vec(),
        value: remote_endpoint.to_vec(),
    }
}

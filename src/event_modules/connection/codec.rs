use crate::store::EventId;

pub type EndpointId = [u8; 32];
pub type ConnectionId = [u8; 32];

const MAGIC: &[u8; 10] = b"TOPOCONN1\0";
const TAG_REQUEST: u8 = 1;
const TAG_ACK: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionEvent {
    Request {
        from_endpoint: EndpointId,
        nonce: [u8; 32],
        bootstrap_hash: [u8; 32],
    },
    Ack {
        from_endpoint: EndpointId,
        to_endpoint: EndpointId,
        request_id: EventId,
        connection_id: ConnectionId,
    },
}

pub fn endpoint_id(seed: &[u8]) -> EndpointId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"topo-endpoint-v1");
    hasher.update(seed);
    *hasher.finalize().as_bytes()
}

pub fn bootstrap_hash(token: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"topo-bootstrap-token-v1");
    hasher.update(token.as_bytes());
    *hasher.finalize().as_bytes()
}

pub fn connection_id(request_id: &EventId, from_endpoint: &EndpointId) -> ConnectionId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"topo-connection-v1");
    hasher.update(request_id);
    hasher.update(from_endpoint);
    *hasher.finalize().as_bytes()
}

pub fn event_id(bytes: &[u8]) -> EventId {
    *blake3::hash(bytes).as_bytes()
}

pub fn encode(event: &ConnectionEvent) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + 1 + 32 * 4);
    out.extend_from_slice(MAGIC);
    match event {
        ConnectionEvent::Request {
            from_endpoint,
            nonce,
            bootstrap_hash,
        } => {
            out.push(TAG_REQUEST);
            out.extend_from_slice(from_endpoint);
            out.extend_from_slice(nonce);
            out.extend_from_slice(bootstrap_hash);
        }
        ConnectionEvent::Ack {
            from_endpoint,
            to_endpoint,
            request_id,
            connection_id,
        } => {
            out.push(TAG_ACK);
            out.extend_from_slice(from_endpoint);
            out.extend_from_slice(to_endpoint);
            out.extend_from_slice(request_id);
            out.extend_from_slice(connection_id);
        }
    }
    out
}

pub fn decode(bytes: &[u8]) -> Result<ConnectionEvent, String> {
    if !bytes.starts_with(MAGIC) {
        return Err("not a connection event".to_string());
    }
    let mut rest = &bytes[MAGIC.len()..];
    let tag = take_u8(&mut rest)?;
    let event = match tag {
        TAG_REQUEST => ConnectionEvent::Request {
            from_endpoint: take_id(&mut rest)?,
            nonce: take_id(&mut rest)?,
            bootstrap_hash: take_id(&mut rest)?,
        },
        TAG_ACK => ConnectionEvent::Ack {
            from_endpoint: take_id(&mut rest)?,
            to_endpoint: take_id(&mut rest)?,
            request_id: take_id(&mut rest)?,
            connection_id: take_id(&mut rest)?,
        },
        other => return Err(format!("unknown connection event tag {other}")),
    };
    if !rest.is_empty() {
        return Err("trailing connection event bytes".to_string());
    }
    Ok(event)
}

fn take_u8(rest: &mut &[u8]) -> Result<u8, String> {
    if rest.is_empty() {
        return Err("truncated connection event".to_string());
    }
    let value = rest[0];
    *rest = &rest[1..];
    Ok(value)
}

fn take_id(rest: &mut &[u8]) -> Result<[u8; 32], String> {
    if rest.len() < 32 {
        return Err("truncated connection event".to_string());
    }
    let mut out = [0; 32];
    out.copy_from_slice(&rest[..32]);
    *rest = &rest[32..];
    Ok(out)
}

use crate::store::EventId;
use crate::wire::{Reader, Writer};

pub type EndpointId = [u8; 32];
pub type ConnectionId = [u8; 32];
pub type TransitNonce = [u8; 24];

const MAGIC: &[u8; 10] = b"TOPOCONN1\0";
const TAG_REQUEST: u8 = 1;
const TAG_ACK: u8 = 2;

const TRANSIT_MAGIC: &[u8; 10] = b"TOPOTRANS1";
const TAG_BOOTSTRAP_TRANSIT: u8 = 1;
const TAG_CONNECTION_TRANSIT: u8 = 2;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitEnvelope {
    Bootstrap {
        sender_endpoint: EndpointId,
        recipient_endpoint: EndpointId,
        nonce: TransitNonce,
        ciphertext: Vec<u8>,
    },
    Connection {
        connection_id: ConnectionId,
        sender_endpoint: EndpointId,
        recipient_endpoint: EndpointId,
        nonce: TransitNonce,
        ciphertext: Vec<u8>,
    },
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

pub fn is_connection_event(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

pub fn encode(event: &ConnectionEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(10 + 1 + 32 * 4);
    out.raw(MAGIC);
    match event {
        ConnectionEvent::Request {
            from_endpoint,
            nonce,
            bootstrap_hash,
        } => {
            out.u8(TAG_REQUEST);
            out.id(from_endpoint);
            out.id(nonce);
            out.id(bootstrap_hash);
        }
        ConnectionEvent::Ack {
            from_endpoint,
            to_endpoint,
            request_id,
            connection_id,
        } => {
            out.u8(TAG_ACK);
            out.id(from_endpoint);
            out.id(to_endpoint);
            out.id(request_id);
            out.id(connection_id);
        }
    }
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<ConnectionEvent, String> {
    if !bytes.starts_with(MAGIC) {
        return Err("not a connection event".to_string());
    }
    let mut reader = Reader::new(&bytes[MAGIC.len()..], "connection event");
    let tag = reader.u8()?;
    let event = match tag {
        TAG_REQUEST => ConnectionEvent::Request {
            from_endpoint: reader.id()?,
            nonce: reader.id()?,
            bootstrap_hash: reader.id()?,
        },
        TAG_ACK => ConnectionEvent::Ack {
            from_endpoint: reader.id()?,
            to_endpoint: reader.id()?,
            request_id: reader.id()?,
            connection_id: reader.id()?,
        },
        other => return Err(format!("unknown connection event tag {other}")),
    };
    reader.finish()?;
    Ok(event)
}

pub fn transit_associated_data(envelope: &TransitEnvelope) -> Vec<u8> {
    let mut out = Writer::new();
    out.raw(TRANSIT_MAGIC);
    match envelope {
        TransitEnvelope::Bootstrap {
            sender_endpoint,
            recipient_endpoint,
            nonce,
            ciphertext: _,
        } => {
            out.u8(TAG_BOOTSTRAP_TRANSIT);
            out.id(sender_endpoint);
            out.id(recipient_endpoint);
            out.raw(nonce);
        }
        TransitEnvelope::Connection {
            connection_id,
            sender_endpoint,
            recipient_endpoint,
            nonce,
            ciphertext: _,
        } => {
            out.u8(TAG_CONNECTION_TRANSIT);
            out.id(connection_id);
            out.id(sender_endpoint);
            out.id(recipient_endpoint);
            out.raw(nonce);
        }
    }
    out.finish()
}

pub fn encode_transit(envelope: &TransitEnvelope) -> Vec<u8> {
    let mut out = Writer::new();
    out.raw(TRANSIT_MAGIC);
    match envelope {
        TransitEnvelope::Bootstrap {
            sender_endpoint,
            recipient_endpoint,
            nonce,
            ciphertext,
        } => {
            out.u8(TAG_BOOTSTRAP_TRANSIT);
            out.id(sender_endpoint);
            out.id(recipient_endpoint);
            out.raw(nonce);
            out.sized_bytes(ciphertext);
        }
        TransitEnvelope::Connection {
            connection_id,
            sender_endpoint,
            recipient_endpoint,
            nonce,
            ciphertext,
        } => {
            out.u8(TAG_CONNECTION_TRANSIT);
            out.id(connection_id);
            out.id(sender_endpoint);
            out.id(recipient_endpoint);
            out.raw(nonce);
            out.sized_bytes(ciphertext);
        }
    }
    out.finish()
}

pub fn decode_transit(bytes: &[u8]) -> Result<TransitEnvelope, String> {
    if !bytes.starts_with(TRANSIT_MAGIC) {
        return Err("not a transit envelope".to_string());
    }
    let mut reader = Reader::new(&bytes[TRANSIT_MAGIC.len()..], "transit envelope");
    let envelope = match reader.u8()? {
        TAG_BOOTSTRAP_TRANSIT => TransitEnvelope::Bootstrap {
            sender_endpoint: reader.id()?,
            recipient_endpoint: reader.id()?,
            nonce: nonce24(&mut reader)?,
            ciphertext: reader.sized_bytes()?,
        },
        TAG_CONNECTION_TRANSIT => TransitEnvelope::Connection {
            connection_id: reader.id()?,
            sender_endpoint: reader.id()?,
            recipient_endpoint: reader.id()?,
            nonce: nonce24(&mut reader)?,
            ciphertext: reader.sized_bytes()?,
        },
        other => return Err(format!("unknown transit envelope tag {other}")),
    };
    reader.finish()?;
    Ok(envelope)
}

fn nonce24(reader: &mut Reader<'_>) -> Result<TransitNonce, String> {
    let bytes = reader.bytes(24)?;
    let mut nonce = [0; 24];
    nonce.copy_from_slice(&bytes);
    Ok(nonce)
}

//! Codec for need-id sync events.
//!
//! A need-id event asks the peer to send bytes for exactly one event id. The
//! response path dedupes in transit out by `(connection_id, event_id)`.

use crate::protocol::event_modules::types::{ConnectionScope, EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::types::NeedIdEvent;

pub const TYPE_SYNC_NEED_ID: u8 = 142;
pub const ENCODED_BYTES: usize = 1 + 32 + 32;

pub fn encode(event: &NeedIdEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(ENCODED_BYTES);
    out.u8(TYPE_SYNC_NEED_ID);
    out.id(&event.connection_id);
    out.id(&event.id);
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<NeedIdEvent, String> {
    if bytes.len() != ENCODED_BYTES {
        return Err("sync need-id length mismatch".to_string());
    }
    let mut reader = Reader::new(bytes, "sync need-id");
    let tag = reader.u8()?;
    if tag != TYPE_SYNC_NEED_ID {
        return Err("unknown sync need-id event".to_string());
    }
    let event = NeedIdEvent {
        connection_id: reader.id()?,
        id: reader.id()?,
    };
    reader.finish()?;
    Ok(event)
}

pub fn is_event(bytes: &[u8]) -> bool {
    bytes.first() == Some(&TYPE_SYNC_NEED_ID)
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let event = decode(&bytes)?;
    record_with_scope(
        bytes,
        EventScope::Connection(ConnectionScope::Outgoing {
            connection_id: event.connection_id,
        }),
    )
}

fn record_with_scope(bytes: Vec<u8>, scope: EventScope) -> Result<EventRecord, String> {
    decode(&bytes)?;
    Ok(EventRecord {
        timestamp: 0,
        body_len: 0,
        canonical_bytes: bytes,
        dependencies: Vec::new(),
        workspace_id: None,
        scope,
    })
}

pub fn outbound_record(event: NeedIdEvent) -> Result<EventRecord, String> {
    let bytes = encode(&event);
    record_with_scope(
        bytes,
        EventScope::Connection(ConnectionScope::Outgoing {
            connection_id: event.connection_id,
        }),
    )
}

pub fn inbound_record_from_wire(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let event = decode(&bytes)?;
    record_with_scope(
        bytes,
        EventScope::Connection(ConnectionScope::Incoming {
            connection_id: event.connection_id,
        }),
    )
}

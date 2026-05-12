//! Codec for need-id sync events.
//!
//! A need-id event asks the peer to send bytes for exactly one event id. The
//! response path dedupes in transit out by `(connection_id, event_id)`.

use crate::protocol::event_modules::types::{ConnectionScope, EventRecord, EventScope};
use crate::protocol::wire_schema::{Field, WireSchema};

use super::types::NeedIdEvent;

pub const TYPE_SYNC_NEED_ID: u8 = 142;

pub const SCHEMA: WireSchema = WireSchema::new(
    "sync.need_id",
    TYPE_SYNC_NEED_ID,
    &[Field::id("connection_id"), Field::id("id")],
);

pub fn encode(event: &NeedIdEvent) -> Vec<u8> {
    SCHEMA
        .encoder()
        .id(&event.connection_id)
        .id(&event.id)
        .finish()
}

pub fn decode(bytes: &[u8]) -> Result<NeedIdEvent, String> {
    let v = SCHEMA.parse(bytes)?;
    Ok(NeedIdEvent {
        connection_id: v.id("connection_id")?,
        id: v.id("id")?,
    })
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

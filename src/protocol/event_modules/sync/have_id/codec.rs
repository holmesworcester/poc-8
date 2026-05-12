//! Codec for have-id sync events.
//!
//! A have-id event advertises one event id at one timestamp. It is cheap to
//! duplicate and cheap to dedupe, and it has its own event id before transit
//! wrapping.

use crate::protocol::event_modules::types::{ConnectionScope, EventRecord, EventScope};
use crate::protocol::wire_schema::{Field, WireSchema};

use super::types::HaveIdEvent;

pub const TYPE_SYNC_HAVE_ID: u8 = 141;

pub const SCHEMA: WireSchema = WireSchema::new(
    "sync.have_id",
    TYPE_SYNC_HAVE_ID,
    &[
        Field::id("connection_id"),
        Field::u64("timestamp"),
        Field::id("id"),
    ],
);

pub fn encode(event: &HaveIdEvent) -> Vec<u8> {
    SCHEMA
        .encoder()
        .id(&event.connection_id)
        .u64(event.timestamp)
        .id(&event.id)
        .finish()
}

pub fn decode(bytes: &[u8]) -> Result<HaveIdEvent, String> {
    let v = SCHEMA.parse(bytes)?;
    Ok(HaveIdEvent {
        connection_id: v.id("connection_id")?,
        timestamp: v.u64("timestamp")?,
        id: v.id("id")?,
    })
}

pub fn is_event(bytes: &[u8]) -> bool {
    bytes.first() == Some(&TYPE_SYNC_HAVE_ID)
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

pub fn outbound_record(event: HaveIdEvent) -> Result<EventRecord, String> {
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

//! Codec for compare sync events.
//!
//! A compare event carries one connection id, one inclusive timestamp range,
//! and the sender's summary for that range. It is a real connection-scoped
//! transient event, not a nested packet item.

use crate::protocol::event_modules::types::{ConnectionScope, EventRecord, EventScope};
use crate::protocol::wire_schema::{Field, WireSchema};

use super::types::{CompareEvent, RangeSummary, TimestampRange};

pub const TYPE_SYNC_COMPARE: u8 = 140;

pub const SCHEMA: WireSchema = WireSchema::new(
    "sync.compare",
    TYPE_SYNC_COMPARE,
    &[
        Field::id("connection_id"),
        Field::u64("range_start"),
        Field::u64("range_end"),
        Field::u64("summary_count"),
        Field::id("summary_fingerprint"),
        Field::u8("response_requested"),
    ],
);

pub fn encode(event: &CompareEvent) -> Vec<u8> {
    SCHEMA
        .encoder()
        .id(&event.connection_id)
        .u64(event.range.start)
        .u64(event.range.end)
        .u64(event.summary.count)
        .id(&event.summary.fingerprint)
        .u8(u8::from(event.response_requested))
        .finish()
}

pub fn decode(bytes: &[u8]) -> Result<CompareEvent, String> {
    let v = SCHEMA.parse(bytes)?;
    let range = TimestampRange {
        start: v.u64("range_start")?,
        end: v.u64("range_end")?,
    };
    if range.start > range.end {
        return Err("sync compare range is inverted".to_string());
    }
    let summary = RangeSummary {
        count: v.u64("summary_count")?,
        fingerprint: v.id("summary_fingerprint")?,
    };
    let response_requested = match v.u8("response_requested")? {
        0 => false,
        1 => true,
        _ => return Err("sync compare response flag is invalid".to_string()),
    };
    Ok(CompareEvent {
        connection_id: v.id("connection_id")?,
        range,
        summary,
        response_requested,
    })
}

pub fn is_event(bytes: &[u8]) -> bool {
    bytes.first() == Some(&TYPE_SYNC_COMPARE)
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

pub fn outbound_record(event: CompareEvent) -> Result<EventRecord, String> {
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

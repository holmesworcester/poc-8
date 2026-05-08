//! Codec for compare sync events.
//!
//! A compare event carries one connection id, one inclusive timestamp range,
//! and the sender's summary for that range. It is a real connection-scoped
//! event, not a nested packet item.

use crate::protocol::event_modules::types::{ConnectionScope, EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::types::{CompareEvent, RangeSummary, TimestampRange};

pub const TYPE_SYNC_COMPARE: u8 = 140;
pub const ENCODED_BYTES: usize = 1 + 32 + 8 + 8 + 8 + 32 + 1;

pub fn encode(event: &CompareEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(ENCODED_BYTES);
    out.u8(TYPE_SYNC_COMPARE);
    out.id(&event.connection_id);
    out.u64(event.range.start);
    out.u64(event.range.end);
    out.u64(event.summary.count);
    out.id(&event.summary.fingerprint);
    out.u8(u8::from(event.response_requested));
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<CompareEvent, String> {
    if bytes.len() != ENCODED_BYTES {
        return Err("sync compare length mismatch".to_string());
    }
    let mut reader = Reader::new(bytes, "sync compare");
    let tag = reader.u8()?;
    if tag != TYPE_SYNC_COMPARE {
        return Err("unknown sync compare event".to_string());
    }
    let connection_id = reader.id()?;
    let range = TimestampRange {
        start: reader.u64()?,
        end: reader.u64()?,
    };
    if range.start > range.end {
        return Err("sync compare range is inverted".to_string());
    }
    let summary = RangeSummary {
        count: reader.u64()?,
        fingerprint: reader.id()?,
    };
    let response_requested = match reader.u8()? {
        0 => false,
        1 => true,
        _ => return Err("sync compare response flag is invalid".to_string()),
    };
    reader.finish()?;
    Ok(CompareEvent {
        connection_id,
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

//! Fixed-width codec for dependency-cascade test events.
//!
//! The event body is deliberately rigid: a timestamp, a bounded dependency
//! array, and a fixed payload. This makes out-of-order replay tests deterministic
//! and makes malformed dependency padding visible. The staged wrapper is a
//! local-only event that stores canonical shared event bytes for later replay.

use crate::protocol::event_modules::types::{EventRecord, EventScope};
use crate::protocol::wire_schema::{Field, WireSchema};

use super::types::{EventWithDeps, StagedEventWithDeps, MAX_DEPS, PAYLOAD_BYTES};

pub const TYPE_EVENT_WITH_DEPS: u8 = 2;
pub const TYPE_STAGED_EVENT_WITH_DEPS: u8 = 3;

pub const SCHEMA: WireSchema = WireSchema::new(
    "event_with_deps",
    TYPE_EVENT_WITH_DEPS,
    &[
        Field::u64("timestamp"),
        Field::u8("dependency_count"),
        Field::bytes("dependency_slots", MAX_DEPS * 32),
        Field::bytes("payload", PAYLOAD_BYTES),
    ],
);

pub const STAGED_SCHEMA: WireSchema = WireSchema::new(
    "staged event_with_deps",
    TYPE_STAGED_EVENT_WITH_DEPS,
    &[
        Field::u64("index"),
        Field::bytes("inner_bytes", SCHEMA.wire_size()),
    ],
);

pub const ENCODED_BYTES: usize = SCHEMA.wire_size();
pub const STAGED_ENCODED_BYTES: usize = STAGED_SCHEMA.wire_size();

pub fn encode(event: &EventWithDeps) -> Vec<u8> {
    assert!(
        event.dependencies.len() <= MAX_DEPS,
        "event_with_deps dependencies exceed fixed field count"
    );
    let mut dependency_slots = vec![0u8; MAX_DEPS * 32];
    for idx in 0..MAX_DEPS {
        if let Some(dep) = event.dependencies.get(idx) {
            dependency_slots[idx * 32..(idx + 1) * 32].copy_from_slice(dep);
        }
    }
    SCHEMA
        .encoder()
        .u64(event.timestamp)
        .u8(event.dependencies.len() as u8)
        .bytes(&dependency_slots)
        .bytes(&event.payload)
        .finish()
}

pub fn decode(bytes: &[u8]) -> Result<EventWithDeps, String> {
    // Unused dependency slots must be zero. This prevents two encodings of the
    // same semantic dependency set from producing different event ids.
    let v = SCHEMA.parse(bytes)?;
    let timestamp = v.u64("timestamp")?;
    let dep_count = v.u8("dependency_count")? as usize;
    if dep_count > MAX_DEPS {
        return Err("event_with_deps dependency count exceeds fixed fields".to_string());
    }

    let mut dependencies = Vec::with_capacity(dep_count);
    let dependency_slots = v.raw("dependency_slots")?;
    for idx in 0..MAX_DEPS {
        let dep: [u8; 32] = dependency_slots[idx * 32..(idx + 1) * 32]
            .try_into()
            .map_err(|_| "event_with_deps dependency slot is malformed".to_string())?;
        if idx < dep_count {
            dependencies.push(dep);
        } else if dep != [0; 32] {
            return Err("event_with_deps unused dependency field is nonzero".to_string());
        }
    }

    let mut fixed_payload = [0; PAYLOAD_BYTES];
    fixed_payload.copy_from_slice(v.raw("payload")?);

    Ok(EventWithDeps {
        timestamp,
        dependencies,
        payload: fixed_payload,
    })
}

pub fn encode_staged(event: &StagedEventWithDeps) -> Vec<u8> {
    assert_eq!(
        event.inner_bytes.len(),
        ENCODED_BYTES,
        "staged event_with_deps bytes must be fixed width"
    );
    STAGED_SCHEMA
        .encoder()
        .u64(event.index)
        .bytes(&event.inner_bytes)
        .finish()
}

pub fn decode_staged(bytes: &[u8]) -> Result<StagedEventWithDeps, String> {
    let v = STAGED_SCHEMA.parse(bytes)?;
    let index = v.u64("index")?;
    let inner_bytes = v.raw("inner_bytes")?.to_vec();
    record_from_bytes(inner_bytes.clone())?;
    Ok(StagedEventWithDeps { index, inner_bytes })
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let decoded = decode(&bytes)?;
    Ok(EventRecord {
        timestamp: decoded.timestamp,
        body_len: PAYLOAD_BYTES,
        canonical_bytes: bytes,
        dependencies: decoded.dependencies,
        workspace_id: None,
        scope: EventScope::Shared,
    })
}

pub fn staged_record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    decode_staged(&bytes)?;
    Ok(EventRecord {
        timestamp: 0,
        body_len: ENCODED_BYTES,
        canonical_bytes: bytes,
        dependencies: Vec::new(),
        workspace_id: None,
        scope: EventScope::Local,
    })
}

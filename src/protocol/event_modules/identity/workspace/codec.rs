//! Codec for shared workspace events.
//!
//! The workspace format is fixed-width:
//!
//! ```text
//! type(1) || created_at_ms(8) || public_key(32) || name_utf8_zero_padded(64)
//! ```
//!
//! The event id of these canonical bytes is the workspace id.

use crate::protocol::event_modules::types::{EventRecord, EventScope};
use crate::protocol::wire_schema::{Field, WireSchema};

use super::types::{WorkspaceEvent, WORKSPACE_NAME_BYTES};

pub const TYPE_WORKSPACE: u8 = 131;

pub const SCHEMA: WireSchema = WireSchema::new(
    "workspace",
    TYPE_WORKSPACE,
    &[
        Field::u64("created_at_ms"),
        Field::id("public_key"),
        Field::bytes("name", WORKSPACE_NAME_BYTES),
    ],
);

pub const WORKSPACE_WIRE_SIZE: usize = SCHEMA.wire_size();

pub fn encode(event: &WorkspaceEvent) -> Result<Vec<u8>, String> {
    let name = encode_name(&event.name)?;
    Ok(SCHEMA
        .encoder()
        .u64(event.created_at_ms)
        .id(&event.public_key)
        .bytes(&name)
        .finish())
}

pub fn decode(bytes: &[u8]) -> Result<WorkspaceEvent, String> {
    let v = SCHEMA.parse(bytes)?;
    Ok(WorkspaceEvent {
        created_at_ms: v.u64("created_at_ms")?,
        public_key: v.id("public_key")?,
        name: decode_name(v.raw("name")?)?,
    })
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let event = decode(&bytes)?;
    let workspace_id = crate::protocol::event_modules::types::event_id(&bytes);
    Ok(EventRecord {
        timestamp: event.created_at_ms,
        body_len: WORKSPACE_WIRE_SIZE - 1,
        canonical_bytes: bytes,
        dependencies: Vec::new(),
        workspace_id: Some(workspace_id),
        scope: EventScope::Shared,
    })
}

fn encode_name(name: &str) -> Result<[u8; WORKSPACE_NAME_BYTES], String> {
    let bytes = name.as_bytes();
    if bytes.len() > WORKSPACE_NAME_BYTES {
        return Err("workspace name is too long".to_string());
    }
    if bytes.contains(&0) {
        return Err("workspace name cannot contain NUL".to_string());
    }

    let mut out = [0; WORKSPACE_NAME_BYTES];
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(out)
}

fn decode_name(bytes: &[u8]) -> Result<String, String> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if bytes[end..].iter().any(|byte| *byte != 0) {
        return Err("workspace name has non-canonical padding".to_string());
    }
    std::str::from_utf8(&bytes[..end])
        .map_err(|_| "workspace name is not valid utf-8".to_string())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> WorkspaceEvent {
        WorkspaceEvent {
            created_at_ms: 42,
            public_key: [7; 32],
            name: "Engineering".to_string(),
        }
    }

    #[test]
    fn roundtrips_fixed_width_workspace_event() {
        let encoded = encode(&event()).expect("encode workspace");
        assert_eq!(encoded.len(), WORKSPACE_WIRE_SIZE);
        assert_eq!(decode(&encoded).expect("decode workspace"), event());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut encoded = encode(&event()).expect("encode workspace");
        encoded.push(1);
        assert!(decode(&encoded).is_err());
    }

    #[test]
    fn rejects_non_canonical_name_padding() {
        let mut encoded = encode(&event()).expect("encode workspace");
        let name_start = 1 + 8 + 32;
        encoded[name_start + "Engineering".len() + 1] = b'x';
        assert!(decode(&encoded).is_err());
    }

    #[test]
    fn record_is_shared_root_event() {
        let encoded = encode(&event()).expect("encode workspace");
        let record = record_from_bytes(encoded.clone()).expect("workspace record");
        assert_eq!(record.timestamp, 42);
        assert_eq!(record.body_len, WORKSPACE_WIRE_SIZE - 1);
        assert_eq!(record.canonical_bytes, encoded);
        assert!(record.dependencies.is_empty());
        assert_eq!(record.scope, EventScope::Shared);
    }
}

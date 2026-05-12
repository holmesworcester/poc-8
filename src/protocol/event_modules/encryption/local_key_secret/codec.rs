//! Codec for local key-secret events.
//!
//! A local key-secret event commits secret bytes to one workspace frontier and
//! depends on that frontier. Scope is `Local`, so sync never transmits the
//! canonical bytes. This codec only validates event shape; authority is checked
//! by projection against the removal frontier dependency.

use crate::core::crypto::XCHACHA20_POLY1305_KEY_BYTES;
use crate::protocol::event_modules::types::{EventRecord, EventScope};
use crate::protocol::wire_schema::{Field, WireSchema};

use super::types::LocalKeySecret;

pub const TYPE_LOCAL_KEY_SECRET: u8 = 144;

pub const SCHEMA: WireSchema = WireSchema::new(
    "local_key_secret",
    TYPE_LOCAL_KEY_SECRET,
    &[
        Field::id("workspace_id"),
        Field::id("removal_frontier_id"),
        Field::bytes("key_secret", XCHACHA20_POLY1305_KEY_BYTES),
    ],
);

pub const LOCAL_KEY_SECRET_WIRE_SIZE: usize = SCHEMA.wire_size();

pub fn encode(event: &LocalKeySecret) -> Vec<u8> {
    SCHEMA
        .encoder()
        .id(&event.workspace_id)
        .id(&event.removal_frontier_id)
        .bytes(&event.key_secret)
        .finish()
}

pub fn decode(bytes: &[u8]) -> Result<LocalKeySecret, String> {
    let v = SCHEMA.parse(bytes)?;
    let event = LocalKeySecret {
        workspace_id: v.id("workspace_id")?,
        removal_frontier_id: v.id("removal_frontier_id")?,
        key_secret: v
            .raw("key_secret")?
            .try_into()
            .map_err(|_| "key_secret length".to_string())?,
    };
    validate(&event)?;
    Ok(event)
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let event = decode(&bytes)?;
    Ok(EventRecord {
        timestamp: 0,
        body_len: 0,
        canonical_bytes: bytes,
        dependencies: vec![event.removal_frontier_id],
        workspace_id: Some(event.workspace_id),
        scope: EventScope::Local,
    })
}

fn validate(event: &LocalKeySecret) -> Result<(), String> {
    if is_zero(&event.workspace_id) {
        return Err("local key secret workspace cannot be empty".to_string());
    }
    if is_zero(&event.removal_frontier_id) {
        return Err("local key secret removal_frontier_id cannot be empty".to_string());
    }
    if is_zero(&event.key_secret) {
        return Err("local key secret material cannot be empty".to_string());
    }
    Ok(())
}

fn is_zero(bytes: &[u8; XCHACHA20_POLY1305_KEY_BYTES]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::types::EventScope;

    use super::super::commands;
    use super::*;

    #[test]
    fn roundtrips_local_key_secret() {
        let event = commands::create([1; 32], [2; 32])
            .expect("create")
            .value
            .event;
        let bytes = encode(&event);

        assert_eq!(decode(&bytes).expect("decode"), event);
    }

    #[test]
    fn record_is_local_and_depends_on_frontier() {
        let bytes = encode(
            &commands::create([1; 32], [2; 32])
                .expect("create")
                .value
                .event,
        );
        let record = record_from_bytes(bytes).expect("record");

        assert_eq!(record.scope, EventScope::Local);
        assert_eq!(record.workspace_id, Some([1; 32]));
        assert_eq!(record.dependencies, vec![[2; 32]]);
    }

    #[test]
    fn decode_rejects_empty_required_fields() {
        let mut event = commands::create([1; 32], [2; 32])
            .expect("create")
            .value
            .event;
        event.removal_frontier_id = [0; 32];

        assert_eq!(
            decode(&encode(&event)).expect_err("empty frontier must fail"),
            "local key secret removal_frontier_id cannot be empty"
        );
    }
}

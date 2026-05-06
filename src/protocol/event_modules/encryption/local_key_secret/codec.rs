//! Codec for local key-secret events.

use crate::core::crypto::XCHACHA20_POLY1305_KEY_BYTES;
use crate::protocol::event_modules::types::{EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::types::LocalKeySecret;

pub const TYPE_LOCAL_KEY_SECRET: u8 = 144;
pub const LOCAL_KEY_SECRET_WIRE_SIZE: usize = 1 + 32 + 32 + XCHACHA20_POLY1305_KEY_BYTES;

pub fn encode(event: &LocalKeySecret) -> Vec<u8> {
    let mut out = Writer::with_capacity(LOCAL_KEY_SECRET_WIRE_SIZE);
    out.u8(TYPE_LOCAL_KEY_SECRET);
    out.id(&event.workspace_id);
    out.id(&event.removal_frontier_id);
    out.id(&event.key_secret);
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<LocalKeySecret, String> {
    let mut reader = Reader::new(bytes, "local key secret");
    let tag = reader.u8()?;
    if tag != TYPE_LOCAL_KEY_SECRET {
        return Err("expected local key secret".to_string());
    }
    let event = LocalKeySecret {
        workspace_id: reader.id()?,
        removal_frontier_id: reader.id()?,
        key_secret: reader.id()?,
    };
    reader.finish()?;
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

fn is_zero(bytes: &[u8; 32]) -> bool {
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

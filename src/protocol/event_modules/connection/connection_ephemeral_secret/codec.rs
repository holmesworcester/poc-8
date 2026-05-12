//! Wire codec for local connection-handshake ephemeral secret events.

use crate::core::crypto;
use crate::protocol::event_modules::types::{EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::super::types::EVENT_MAGIC;
use super::types::EphemeralSecretEvent;

pub const TAG: u8 = 3;

pub fn encode(event: &EphemeralSecretEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(10 + 1 + 32 * 3 + 8);
    out.raw(EVENT_MAGIC);
    out.u8(TAG);
    out.id(&event.owner_endpoint);
    out.id(&event.ephemeral_private_key);
    out.id(&event.ephemeral_public_key);
    out.u64(event.created_at_ms);
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<EphemeralSecretEvent, String> {
    if !bytes.starts_with(EVENT_MAGIC) {
        return Err("not a connection event".to_string());
    }
    let mut reader = Reader::new(&bytes[EVENT_MAGIC.len()..], "connection ephemeral secret");
    if reader.u8()? != TAG {
        return Err("expected connection ephemeral secret".to_string());
    }
    let event = EphemeralSecretEvent {
        owner_endpoint: reader.id()?,
        ephemeral_private_key: reader.id()?,
        ephemeral_public_key: reader.id()?,
        created_at_ms: reader.u64()?,
    };
    reader.finish()?;
    Ok(event)
}

pub fn is_ephemeral_secret(bytes: &[u8]) -> bool {
    bytes.starts_with(EVENT_MAGIC) && bytes.get(EVENT_MAGIC.len()) == Some(&TAG)
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let event = decode(&bytes)?;
    if crypto::x25519_public_key(&event.ephemeral_private_key) != event.ephemeral_public_key {
        return Err("connection ephemeral public key does not match private key".to_string());
    }
    Ok(EventRecord {
        timestamp: event.created_at_ms,
        body_len: 0,
        canonical_bytes: bytes,
        dependencies: Vec::new(),
        workspace_id: None,
        scope: EventScope::Local,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_is_local_and_dependency_free() {
        let ephemeral_private_key = [2; 32];
        let event = EphemeralSecretEvent {
            owner_endpoint: [1; 32],
            ephemeral_private_key,
            ephemeral_public_key: crypto::x25519_public_key(&ephemeral_private_key),
            created_at_ms: 4,
        };

        let record = record_from_bytes(encode(&event)).expect("record");

        assert_eq!(record.scope, EventScope::Local);
        assert!(record.dependencies.is_empty());
        assert_eq!(record.timestamp, 4);
    }

    #[test]
    fn record_rejects_mismatched_public_key() {
        let event = EphemeralSecretEvent {
            owner_endpoint: [1; 32],
            ephemeral_private_key: [2; 32],
            ephemeral_public_key: [3; 32],
            created_at_ms: 4,
        };

        let err = record_from_bytes(encode(&event)).expect_err("reject mismatched key");

        assert!(err.contains("does not match"));
    }
}

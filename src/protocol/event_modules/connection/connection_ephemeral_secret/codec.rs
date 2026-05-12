//! Wire codec for local connection-handshake ephemeral secret events.

use crate::core::crypto;
use crate::protocol::event_modules::types::{EventRecord, EventScope};
use crate::protocol::wire_schema::{Field, WireSchema};

use super::types::EphemeralSecretEvent;

pub const TYPE_CONNECTION_EPHEMERAL_SECRET: u8 = 138;
pub const TAG: u8 = TYPE_CONNECTION_EPHEMERAL_SECRET;

pub const SCHEMA: WireSchema = WireSchema::new(
    "connection.ephemeral_secret",
    TYPE_CONNECTION_EPHEMERAL_SECRET,
    &[
        Field::id("owner_endpoint"),
        Field::id("ephemeral_private_key"),
        Field::id("ephemeral_public_key"),
        Field::u64("created_at_ms"),
    ],
);

pub fn encode(event: &EphemeralSecretEvent) -> Vec<u8> {
    SCHEMA
        .encoder()
        .id(&event.owner_endpoint)
        .id(&event.ephemeral_private_key)
        .id(&event.ephemeral_public_key)
        .u64(event.created_at_ms)
        .finish()
}

pub fn decode(bytes: &[u8]) -> Result<EphemeralSecretEvent, String> {
    let v = SCHEMA.parse(bytes)?;
    Ok(EphemeralSecretEvent {
        owner_endpoint: v.id("owner_endpoint")?,
        ephemeral_private_key: v.id("ephemeral_private_key")?,
        ephemeral_public_key: v.id("ephemeral_public_key")?,
        created_at_ms: v.u64("created_at_ms")?,
    })
}

pub fn is_ephemeral_secret(bytes: &[u8]) -> bool {
    bytes.first() == Some(&TYPE_CONNECTION_EPHEMERAL_SECRET)
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

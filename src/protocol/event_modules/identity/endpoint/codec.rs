//! Codec for the local endpoint event.
//!
//! The event stores the transit endpoint keypair and the endpoint signing
//! keypair as a local-only fact. Decoding re-derives both public keys from the
//! private keys, so corrupted or mismatched identity rows fail before
//! projection.

use crate::core::crypto;
use crate::protocol::event_modules::types::{EventRecord, EventScope};
use crate::protocol::wire_schema::{Field, WireSchema};

use super::types::EndpointKeypair;

pub const TYPE_LOCAL_ENDPOINT: u8 = 128;

pub const SCHEMA: WireSchema = WireSchema::new(
    "identity.local_endpoint",
    TYPE_LOCAL_ENDPOINT,
    &[
        Field::id("endpoint"),
        Field::id("secret"),
        Field::id("signing_public_key"),
        Field::id("signing_secret"),
    ],
);

pub fn encode(event: &EndpointKeypair) -> Vec<u8> {
    SCHEMA
        .encoder()
        .id(&event.endpoint)
        .id(&event.secret)
        .id(&event.signing_public_key)
        .id(&event.signing_secret)
        .finish()
}

pub fn decode(bytes: &[u8]) -> Result<EndpointKeypair, String> {
    let v = SCHEMA.parse(bytes)?;
    let endpoint = v.id("endpoint")?;
    let secret = v.id("secret")?;
    let signing_public_key = v.id("signing_public_key")?;
    let signing_secret = v.id("signing_secret")?;
    let derived = crypto::x25519_public_key(&secret);
    if derived != endpoint {
        return Err("local endpoint secret does not match endpoint".to_string());
    }
    let derived_signing_public_key = crypto::ed25519_public_key(&signing_secret);
    if derived_signing_public_key != signing_public_key {
        return Err("local endpoint signing secret does not match signing public key".to_string());
    }
    Ok(EndpointKeypair {
        endpoint,
        secret,
        signing_public_key,
        signing_secret,
    })
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    decode(&bytes)?;
    Ok(EventRecord {
        timestamp: 0,
        body_len: 0,
        canonical_bytes: bytes,
        dependencies: Vec::new(),
        workspace_id: None,
        scope: EventScope::Local,
    })
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::identity::endpoint::commands;
    use crate::protocol::event_modules::types::EventScope;

    use super::*;

    #[test]
    fn decode_rejects_endpoint_that_does_not_match_secret() {
        let good = commands::create_local_keypair().value;
        let bad = commands::create_local_keypair().value;
        let bytes = encode(&EndpointKeypair {
            endpoint: good.endpoint,
            secret: bad.secret,
            signing_public_key: good.signing_public_key,
            signing_secret: good.signing_secret,
        });

        let err = decode(&bytes).expect_err("mismatched endpoint must fail");

        assert_eq!(err, "local endpoint secret does not match endpoint");
    }

    #[test]
    fn decode_rejects_signing_public_key_that_does_not_match_secret() {
        let good = commands::create_local_keypair().value;
        let bad = commands::create_local_keypair().value;
        let bytes = encode(&EndpointKeypair {
            endpoint: good.endpoint,
            secret: good.secret,
            signing_public_key: good.signing_public_key,
            signing_secret: bad.signing_secret,
        });

        let err = decode(&bytes).expect_err("mismatched signing keypair must fail");

        assert_eq!(
            err,
            "local endpoint signing secret does not match signing public key"
        );
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut bytes = encode(&commands::create_local_keypair().value);
        bytes.push(0);

        let err = decode(&bytes).expect_err("trailing byte must fail");

        assert!(err.contains("expected"), "{err}");
    }

    #[test]
    fn record_from_bytes_marks_endpoint_local_only() {
        let bytes = encode(&commands::create_local_keypair().value);
        let record = record_from_bytes(bytes).expect("record");

        assert_eq!(record.scope, EventScope::Local);
        assert!(!record.scope.is_shared());
    }
}

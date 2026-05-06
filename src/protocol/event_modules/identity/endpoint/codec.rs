//! Codec for the local endpoint event.
//!
//! The event stores the transit endpoint keypair and the endpoint signing
//! keypair as a local-only fact. Decoding re-derives both public keys from the
//! private keys, so corrupted or mismatched identity rows fail before
//! projection.

use crate::core::crypto;
use crate::protocol::event_modules::types::{EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::types::EndpointKeypair;

pub const TYPE_LOCAL_ENDPOINT: u8 = 128;

pub fn encode(event: &EndpointKeypair) -> Vec<u8> {
    let mut out = Writer::with_capacity(1 + 32 + 32 + 32 + 32);
    out.u8(TYPE_LOCAL_ENDPOINT);
    out.id(&event.endpoint);
    out.id(&event.secret);
    out.id(&event.signing_public_key);
    out.id(&event.signing_secret);
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<EndpointKeypair, String> {
    let mut reader = Reader::new(bytes, "local endpoint");
    let tag = reader.u8()?;
    if tag != TYPE_LOCAL_ENDPOINT {
        return Err("expected local endpoint".to_string());
    }
    let endpoint = reader.id()?;
    let secret = reader.id()?;
    let signing_public_key = reader.id()?;
    let signing_secret = reader.id()?;
    reader.finish()?;
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

    // Invariant: decode rejects endpoint that does not match secret.
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

    // Invariant: decode rejects signing public key that does not match secret.
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

    // Invariant: decode rejects trailing bytes.
    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut bytes = encode(&commands::create_local_keypair().value);
        bytes.push(0);

        let err = decode(&bytes).expect_err("trailing byte must fail");

        assert!(err.starts_with("trailing "), "{err}");
    }

    // Invariant: record from bytes marks endpoint local only.
    #[test]
    fn record_from_bytes_marks_endpoint_local_only() {
        let bytes = encode(&commands::create_local_keypair().value);
        let record = record_from_bytes(bytes).expect("record");

        assert_eq!(record.scope, EventScope::Local);
        assert!(!record.scope.is_shared());
    }
}

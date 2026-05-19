//! Codec for signed recipient key tombstones.
//!
//! The canonical payload names the endpoint membership and the old/new
//! recipient-key event ids. Projection verifies that both keys belong to the
//! same endpoint; the codec only enforces fixed wire shape, signature envelope
//! shape, and deterministic dependencies.

use crate::core::crypto::{self, Ed25519PrivateKey, ED25519_SIGNATURE_BYTES};
use crate::protocol::event_modules::types::{EventId, EventRecord, EventScope};
use crate::protocol::wire_schema::{Field, WireSchema};

use super::types::{RecipientKeyTombstoneEvent, SignedRecipientKeyTombstoneEnvelope};

pub const TYPE_RECIPIENT_KEY_TOMBSTONE: u8 = 24;
pub const TYPE_SIGNED_RECIPIENT_KEY_TOMBSTONE: u8 = 25;

pub const SCHEMA: WireSchema = WireSchema::new(
    "recipient_key_tombstone",
    TYPE_RECIPIENT_KEY_TOMBSTONE,
    &[
        Field::id("workspace_id"),
        Field::u64("created_at_ms"),
        Field::id("endpoint_shared_id"),
        Field::id("old_recipient_key_id"),
        Field::id("new_recipient_key_id"),
    ],
);

pub const RECIPIENT_KEY_TOMBSTONE_WIRE_SIZE: usize = SCHEMA.wire_size();

pub const SIGNED_SCHEMA: WireSchema = WireSchema::new(
    "signed recipient_key_tombstone",
    TYPE_SIGNED_RECIPIENT_KEY_TOMBSTONE,
    &[
        Field::id("signer_endpoint_shared_id"),
        Field::id("signer_public_key"),
        Field::bytes("payload", RECIPIENT_KEY_TOMBSTONE_WIRE_SIZE),
        Field::bytes("signature", ED25519_SIGNATURE_BYTES),
    ],
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecipientKeyTombstoneMetadata {
    workspace_id: EventId,
    created_at_ms: u64,
    endpoint_shared_id: EventId,
    old_recipient_key_id: EventId,
    new_recipient_key_id: EventId,
}

pub fn encode(event: &RecipientKeyTombstoneEvent) -> Vec<u8> {
    SCHEMA
        .encoder()
        .id(&event.workspace_id)
        .u64(event.created_at_ms)
        .id(&event.endpoint_shared_id)
        .id(&event.old_recipient_key_id)
        .id(&event.new_recipient_key_id)
        .finish()
}

pub fn decode(bytes: &[u8]) -> Result<RecipientKeyTombstoneEvent, String> {
    let v = SCHEMA.parse(bytes)?;
    let event = RecipientKeyTombstoneEvent {
        workspace_id: v.id("workspace_id")?,
        created_at_ms: v.u64("created_at_ms")?,
        endpoint_shared_id: v.id("endpoint_shared_id")?,
        old_recipient_key_id: v.id("old_recipient_key_id")?,
        new_recipient_key_id: v.id("new_recipient_key_id")?,
    };
    validate_event(&event)?;
    Ok(event)
}

pub fn sign(
    signer_endpoint_shared_id: EventId,
    signer_private_key: &Ed25519PrivateKey,
    payload: Vec<u8>,
) -> SignedRecipientKeyTombstoneEnvelope {
    let mut envelope = SignedRecipientKeyTombstoneEnvelope {
        signer_endpoint_shared_id,
        signer_public_key: crypto::ed25519_public_key(signer_private_key),
        payload,
        signature: [0; ED25519_SIGNATURE_BYTES],
    };
    envelope.signature = crypto::ed25519_sign(signer_private_key, &signing_bytes(&envelope));
    envelope
}

pub fn encode_signed(event: &SignedRecipientKeyTombstoneEnvelope) -> Vec<u8> {
    SIGNED_SCHEMA
        .encoder()
        .id(&event.signer_endpoint_shared_id)
        .id(&event.signer_public_key)
        .bytes(&event.payload)
        .bytes(&event.signature)
        .finish()
}

pub fn decode_signed(bytes: &[u8]) -> Result<SignedRecipientKeyTombstoneEnvelope, String> {
    let v = SIGNED_SCHEMA.parse(bytes)?;
    let signature = fixed_signature(v.raw("signature")?.to_vec())?;
    let event = SignedRecipientKeyTombstoneEnvelope {
        signer_endpoint_shared_id: v.id("signer_endpoint_shared_id")?,
        signer_public_key: v.id("signer_public_key")?,
        payload: v.raw("payload")?.to_vec(),
        signature,
    };
    validate_signed_payload(&event)?;
    if !crypto::ed25519_verify(
        &event.signer_public_key,
        &signing_bytes(&event),
        &event.signature,
    ) {
        return Err("signed recipient key tombstone signature verification failed".to_string());
    }
    Ok(event)
}

pub fn signing_bytes(event: &SignedRecipientKeyTombstoneEnvelope) -> Vec<u8> {
    SIGNED_SCHEMA
        .encoder()
        .id(&event.signer_endpoint_shared_id)
        .id(&event.signer_public_key)
        .bytes(&event.payload)
        .finish_without_trailing_fields(1)
}

pub fn signed_record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let envelope = decode_signed(&bytes)?;
    let metadata = metadata(&envelope.payload)?;
    if envelope.signer_endpoint_shared_id != metadata.endpoint_shared_id {
        return Err(
            "signed recipient key tombstone signer does not match payload endpoint".to_string(),
        );
    }
    let mut dependencies = Vec::with_capacity(4);
    push_unique(&mut dependencies, metadata.endpoint_shared_id);
    push_unique(&mut dependencies, metadata.workspace_id);
    push_unique(&mut dependencies, metadata.old_recipient_key_id);
    push_unique(&mut dependencies, metadata.new_recipient_key_id);
    Ok(EventRecord {
        timestamp: metadata.created_at_ms,
        body_len: RECIPIENT_KEY_TOMBSTONE_WIRE_SIZE - 1,
        canonical_bytes: bytes,
        dependencies,
        workspace_id: Some(metadata.workspace_id),
        scope: EventScope::Shared,
    })
}

fn metadata(bytes: &[u8]) -> Result<RecipientKeyTombstoneMetadata, String> {
    let event = decode(bytes)?;
    Ok(RecipientKeyTombstoneMetadata {
        workspace_id: event.workspace_id,
        created_at_ms: event.created_at_ms,
        endpoint_shared_id: event.endpoint_shared_id,
        old_recipient_key_id: event.old_recipient_key_id,
        new_recipient_key_id: event.new_recipient_key_id,
    })
}

fn validate_signed_payload(event: &SignedRecipientKeyTombstoneEnvelope) -> Result<(), String> {
    let Some(actual_type) = event.payload.first().copied() else {
        return Err("signed recipient key tombstone payload is empty".to_string());
    };
    if actual_type != TYPE_RECIPIENT_KEY_TOMBSTONE {
        return Err(
            "signed recipient key tombstone payload is not a recipient key tombstone".to_string(),
        );
    }
    metadata(&event.payload).map(|_| ())
}

fn validate_event(event: &RecipientKeyTombstoneEvent) -> Result<(), String> {
    if is_zero(&event.workspace_id) {
        return Err("recipient key tombstone workspace cannot be empty".to_string());
    }
    if is_zero(&event.endpoint_shared_id) {
        return Err("recipient key tombstone endpoint_shared_id cannot be empty".to_string());
    }
    if is_zero(&event.old_recipient_key_id) {
        return Err("recipient key tombstone old key cannot be empty".to_string());
    }
    if is_zero(&event.new_recipient_key_id) {
        return Err("recipient key tombstone new key cannot be empty".to_string());
    }
    if event.old_recipient_key_id == event.new_recipient_key_id {
        return Err("recipient key tombstone must name different keys".to_string());
    }
    Ok(())
}

fn fixed_signature(bytes: Vec<u8>) -> Result<[u8; ED25519_SIGNATURE_BYTES], String> {
    bytes
        .try_into()
        .map_err(|_| "signed recipient key tombstone signature length mismatch".to_string())
}

fn push_unique(out: &mut Vec<EventId>, id: EventId) {
    if !out.iter().any(|candidate| candidate == &id) {
        out.push(id);
    }
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use crate::core::crypto::ED25519_PRIVATE_KEY_BYTES;
    use crate::protocol::event_modules::types::EventScope;

    use super::*;

    fn event() -> RecipientKeyTombstoneEvent {
        RecipientKeyTombstoneEvent {
            workspace_id: [1; 32],
            created_at_ms: 1234,
            endpoint_shared_id: [2; 32],
            old_recipient_key_id: [3; 32],
            new_recipient_key_id: [4; 32],
        }
    }

    fn signed_event() -> Vec<u8> {
        let payload = encode(&event());
        let envelope = sign([2; 32], &[9; ED25519_PRIVATE_KEY_BYTES], payload);
        encode_signed(&envelope)
    }

    #[test]
    fn roundtrips_tombstone_event() {
        let event = event();
        let bytes = encode(&event);

        assert_eq!(decode(&bytes).expect("decode"), event);
    }

    #[test]
    fn signed_record_is_shared_workspace_scoped_and_depends_on_old_and_new_keys() {
        let record = signed_record_from_bytes(signed_event()).expect("record");

        assert_eq!(record.scope, EventScope::Shared);
        assert_eq!(record.workspace_id, Some([1; 32]));
        assert_eq!(record.timestamp, 1234);
        assert_eq!(
            record.dependencies,
            vec![[2; 32], [1; 32], [3; 32], [4; 32]]
        );
    }

    #[test]
    fn decode_signed_rejects_tampered_signature() {
        let mut bytes = signed_event();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;

        assert_eq!(
            decode_signed(&bytes).expect_err("tamper must fail"),
            "signed recipient key tombstone signature verification failed"
        );
    }

    #[test]
    fn signed_record_rejects_signer_endpoint_that_does_not_match_payload() {
        let payload = encode(&event());
        let envelope = sign([9; 32], &[8; ED25519_PRIVATE_KEY_BYTES], payload);

        assert_eq!(
            signed_record_from_bytes(encode_signed(&envelope)).expect_err("reject"),
            "signed recipient key tombstone signer does not match payload endpoint"
        );
    }
}

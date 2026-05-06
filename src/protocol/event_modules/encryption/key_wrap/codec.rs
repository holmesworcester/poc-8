//! Codec for signed key-wrap events.

use crate::core::crypto::{
    self, Ed25519PrivateKey, ED25519_SIGNATURE_BYTES, X25519_PUBLIC_KEY_BYTES,
    XCHACHA20_POLY1305_NONCE_BYTES,
};
use crate::protocol::event_modules::types::{EventId, EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::types::{
    KeyWrapCiphertext, KeyWrapEvent, SignedKeyWrapEnvelope, KEY_WRAP_CIPHERTEXT_BYTES,
};

pub const TYPE_KEY_WRAP: u8 = 22;
pub const TYPE_SIGNED_KEY_WRAP: u8 = 23;
pub const KEY_WRAP_PURPOSE: &[u8] = b"topo key wrap v1";
pub const KEY_WRAP_WIRE_SIZE: usize = 1
    + 32
    + 8
    + 32
    + 32
    + 32
    + X25519_PUBLIC_KEY_BYTES
    + XCHACHA20_POLY1305_NONCE_BYTES
    + KEY_WRAP_CIPHERTEXT_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KeyWrapMetadata {
    workspace_id: EventId,
    created_at_ms: u64,
    removal_frontier_id: EventId,
    recipient_key_id: EventId,
}

pub fn encode(event: &KeyWrapEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(KEY_WRAP_WIRE_SIZE);
    out.u8(TYPE_KEY_WRAP);
    out.id(&event.workspace_id);
    out.u64(event.created_at_ms);
    out.id(&event.removal_frontier_id);
    out.id(&event.local_key_secret_id);
    out.id(&event.recipient_key_id);
    out.id(&event.sender_wrap_public_key);
    out.raw(&event.nonce);
    out.raw(&event.ciphertext);
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<KeyWrapEvent, String> {
    let mut reader = Reader::new(bytes, "key wrap event");
    let tag = reader.u8()?;
    if tag != TYPE_KEY_WRAP {
        return Err("expected key wrap event".to_string());
    }
    let event = KeyWrapEvent {
        workspace_id: reader.id()?,
        created_at_ms: reader.u64()?,
        removal_frontier_id: reader.id()?,
        local_key_secret_id: reader.id()?,
        recipient_key_id: reader.id()?,
        sender_wrap_public_key: reader.id()?,
        nonce: fixed_nonce(reader.bytes(XCHACHA20_POLY1305_NONCE_BYTES)?)?,
        ciphertext: fixed_ciphertext(reader.bytes(KEY_WRAP_CIPHERTEXT_BYTES)?)?,
    };
    reader.finish()?;
    validate_event(&event)?;
    Ok(event)
}

pub fn sign(
    signer_endpoint_shared_id: EventId,
    signer_private_key: &Ed25519PrivateKey,
    payload: Vec<u8>,
) -> SignedKeyWrapEnvelope {
    let mut envelope = SignedKeyWrapEnvelope {
        signer_endpoint_shared_id,
        signer_public_key: crypto::ed25519_public_key(signer_private_key),
        payload,
        signature: [0; ED25519_SIGNATURE_BYTES],
    };
    envelope.signature = crypto::ed25519_sign(signer_private_key, &signing_bytes(&envelope));
    envelope
}

pub fn encode_signed(event: &SignedKeyWrapEnvelope) -> Vec<u8> {
    let mut out = Writer::with_capacity(signing_len(event.payload.len()) + ED25519_SIGNATURE_BYTES);
    write_signing_fields(&mut out, event);
    out.raw(&event.signature);
    out.finish()
}

pub fn decode_signed(bytes: &[u8]) -> Result<SignedKeyWrapEnvelope, String> {
    let mut reader = Reader::new(bytes, "signed key wrap envelope");
    let tag = reader.u8()?;
    if tag != TYPE_SIGNED_KEY_WRAP {
        return Err("expected signed key wrap envelope".to_string());
    }
    let signer_endpoint_shared_id = reader.id()?;
    let signer_public_key = reader.id()?;
    let payload = reader.sized_bytes()?;
    let signature_bytes = reader.bytes(ED25519_SIGNATURE_BYTES)?;
    reader.finish()?;

    let signature = fixed_signature(signature_bytes)?;
    let event = SignedKeyWrapEnvelope {
        signer_endpoint_shared_id,
        signer_public_key,
        payload,
        signature,
    };
    validate_signed_payload(&event)?;
    if !crypto::ed25519_verify(
        &event.signer_public_key,
        &signing_bytes(&event),
        &event.signature,
    ) {
        return Err("signed key wrap signature verification failed".to_string());
    }
    Ok(event)
}

pub fn signing_bytes(event: &SignedKeyWrapEnvelope) -> Vec<u8> {
    let mut out = Writer::with_capacity(signing_len(event.payload.len()));
    write_signing_fields(&mut out, event);
    out.finish()
}

pub fn associated_data(event: &KeyWrapEvent, signer_endpoint_shared_id: EventId) -> Vec<u8> {
    let mut out = Writer::with_capacity(1 + (32 * 6));
    out.u8(TYPE_KEY_WRAP);
    out.id(&event.workspace_id);
    out.id(&event.removal_frontier_id);
    out.id(&event.local_key_secret_id);
    out.id(&event.recipient_key_id);
    out.id(&event.sender_wrap_public_key);
    out.id(&signer_endpoint_shared_id);
    out.finish()
}

pub fn signed_record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let envelope = decode_signed(&bytes)?;
    let metadata = metadata(&envelope.payload)?;
    let mut dependencies = Vec::with_capacity(4);
    push_unique(&mut dependencies, envelope.signer_endpoint_shared_id);
    push_unique(&mut dependencies, metadata.workspace_id);
    push_unique(&mut dependencies, metadata.removal_frontier_id);
    push_unique(&mut dependencies, metadata.recipient_key_id);
    Ok(EventRecord {
        timestamp: metadata.created_at_ms,
        body_len: KEY_WRAP_WIRE_SIZE - 1,
        canonical_bytes: bytes,
        dependencies,
        workspace_id: Some(metadata.workspace_id),
        scope: EventScope::Shared,
    })
}

fn metadata(bytes: &[u8]) -> Result<KeyWrapMetadata, String> {
    let event = decode(bytes)?;
    Ok(KeyWrapMetadata {
        workspace_id: event.workspace_id,
        created_at_ms: event.created_at_ms,
        removal_frontier_id: event.removal_frontier_id,
        recipient_key_id: event.recipient_key_id,
    })
}

fn validate_signed_payload(event: &SignedKeyWrapEnvelope) -> Result<(), String> {
    let Some(actual_type) = event.payload.first().copied() else {
        return Err("signed key wrap payload is empty".to_string());
    };
    if actual_type != TYPE_KEY_WRAP {
        return Err("signed key wrap payload is not a key wrap event".to_string());
    }
    metadata(&event.payload).map(|_| ())
}

fn validate_event(event: &KeyWrapEvent) -> Result<(), String> {
    for (name, id) in [
        ("key wrap workspace", &event.workspace_id),
        ("key wrap removal_frontier_id", &event.removal_frontier_id),
        ("key wrap local_key_secret_id", &event.local_key_secret_id),
        ("key wrap recipient_key_id", &event.recipient_key_id),
        ("key wrap sender public key", &event.sender_wrap_public_key),
    ] {
        if is_zero(id) {
            return Err(format!("{name} cannot be empty"));
        }
    }
    Ok(())
}

fn write_signing_fields(out: &mut Writer, event: &SignedKeyWrapEnvelope) {
    out.u8(TYPE_SIGNED_KEY_WRAP);
    out.id(&event.signer_endpoint_shared_id);
    out.id(&event.signer_public_key);
    out.sized_bytes(&event.payload);
}

fn signing_len(payload_len: usize) -> usize {
    1 + 32 + 32 + 4 + payload_len
}

fn fixed_signature(bytes: Vec<u8>) -> Result<[u8; ED25519_SIGNATURE_BYTES], String> {
    bytes
        .try_into()
        .map_err(|_| "signed key wrap signature length mismatch".to_string())
}

fn fixed_nonce(bytes: Vec<u8>) -> Result<[u8; XCHACHA20_POLY1305_NONCE_BYTES], String> {
    bytes
        .try_into()
        .map_err(|_| "key wrap nonce length mismatch".to_string())
}

fn fixed_ciphertext(bytes: Vec<u8>) -> Result<KeyWrapCiphertext, String> {
    bytes
        .try_into()
        .map_err(|_| "key wrap ciphertext length mismatch".to_string())
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

    fn event() -> KeyWrapEvent {
        KeyWrapEvent {
            workspace_id: [1; 32],
            created_at_ms: 1234,
            removal_frontier_id: [2; 32],
            local_key_secret_id: [3; 32],
            recipient_key_id: [4; 32],
            sender_wrap_public_key: [5; 32],
            nonce: [6; XCHACHA20_POLY1305_NONCE_BYTES],
            ciphertext: [7; KEY_WRAP_CIPHERTEXT_BYTES],
        }
    }

    fn signed_event() -> Vec<u8> {
        let payload = encode(&event());
        let envelope = sign([8; 32], &[9; ED25519_PRIVATE_KEY_BYTES], payload);
        encode_signed(&envelope)
    }

    #[test]
    fn roundtrips_fixed_width_key_wrap() {
        let event = event();
        let bytes = encode(&event);

        assert_eq!(bytes.len(), KEY_WRAP_WIRE_SIZE);
        assert_eq!(decode(&bytes).expect("decode"), event);
    }

    #[test]
    fn record_does_not_depend_on_local_key_secret() {
        let record = signed_record_from_bytes(signed_event()).expect("record");

        assert_eq!(record.scope, EventScope::Shared);
        assert_eq!(record.workspace_id, Some([1; 32]));
        assert_eq!(
            record.dependencies,
            vec![[8; 32], [1; 32], [2; 32], [4; 32]]
        );
        assert!(!record.dependencies.contains(&[3; 32]));
    }

    #[test]
    fn decode_signed_rejects_tampered_signature() {
        let mut bytes = signed_event();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;

        assert_eq!(
            decode_signed(&bytes).expect_err("tamper must fail"),
            "signed key wrap signature verification failed"
        );
    }
}

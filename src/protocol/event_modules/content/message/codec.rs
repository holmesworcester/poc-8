//! Codec for signed message events.
//!
//! Inner messages have a fixed wire layout per event type so canonical bytes
//! stay deterministic. The signed envelope wraps the inner bytes, names the
//! signer endpoint_shared, and carries the Ed25519 signature over the
//! envelope's signing prefix. Raw inner bytes are not admissible; admission
//! goes through the signed envelope.

use crate::core::crypto::{
    self, Ed25519PrivateKey, ED25519_SIGNATURE_BYTES, XCHACHA20_POLY1305_NONCE_BYTES,
};
use crate::protocol::event_modules::types::{EventId, EventRecord, EventScope};
use crate::protocol::wire::Writer;
use crate::protocol::wire_schema::{Field, WireSchema};

use super::types::{
    MessageCiphertext, MessageEvent, SignedMessageEnvelope, MESSAGE_CIPHERTEXT_BYTES,
    MESSAGE_TEXT_BYTES,
};

pub const TYPE_MESSAGE: u8 = 5;
pub const TYPE_SIGNED_MESSAGE: u8 = 6;
pub const MESSAGE_ENCRYPTION_PURPOSE: &[u8] = b"topo message text v4";

/// Message canonical wire size with disappearing-message expiry stamping
/// and per-message setting reference.
///
/// `expires_at_minute` is the authored-time expiry; `u64::MAX` means no
/// expiry. `disappearing_setting_id` references the policy under which
/// the message was authored — either a signed
/// `disappearing_messages_setting` event id or the workspace event id
/// when no setting has been authored. The projector validates that
/// `expires_at_minute` is consistent with the referenced policy.
pub const SCHEMA: WireSchema = WireSchema::new(
    "message",
    TYPE_MESSAGE,
    &[
        Field::id("workspace_id"),
        Field::u64("created_at_ms"),
        Field::id("author_user_id"),
        Field::id("removal_frontier_id"),
        Field::id("local_history_node_secret_id"),
        Field::u64("expires_at_minute"),
        Field::id("disappearing_setting_id"),
        Field::bytes("nonce", XCHACHA20_POLY1305_NONCE_BYTES),
        Field::bytes("ciphertext", MESSAGE_CIPHERTEXT_BYTES),
    ],
);

pub const MESSAGE_WIRE_SIZE: usize = SCHEMA.wire_size();

pub const SIGNED_SCHEMA: WireSchema = WireSchema::new(
    "signed message",
    TYPE_SIGNED_MESSAGE,
    &[
        Field::id("signer_endpoint_shared_id"),
        Field::id("signer_public_key"),
        Field::bytes("payload", MESSAGE_WIRE_SIZE),
        Field::bytes("signature", ED25519_SIGNATURE_BYTES),
    ],
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MessageMetadata {
    workspace_id: EventId,
    created_at_ms: u64,
    author_user_id: EventId,
    removal_frontier_id: EventId,
    local_history_node_secret_id: EventId,
    expires_at_minute: u64,
    disappearing_setting_id: EventId,
}

pub fn encode(event: &MessageEvent) -> Vec<u8> {
    SCHEMA
        .encoder()
        .id(&event.workspace_id)
        .u64(event.created_at_ms)
        .id(&event.author_user_id)
        .id(&event.removal_frontier_id)
        .id(&event.local_history_node_secret_id)
        .u64(event.expires_at_minute)
        .id(&event.disappearing_setting_id)
        .bytes(&event.nonce)
        .bytes(&event.ciphertext)
        .finish()
}

pub fn decode(bytes: &[u8]) -> Result<MessageEvent, String> {
    let v = SCHEMA.parse(bytes)?;
    let event = MessageEvent {
        workspace_id: v.id("workspace_id")?,
        created_at_ms: v.u64("created_at_ms")?,
        author_user_id: v.id("author_user_id")?,
        removal_frontier_id: v.id("removal_frontier_id")?,
        local_history_node_secret_id: v.id("local_history_node_secret_id")?,
        expires_at_minute: v.u64("expires_at_minute")?,
        disappearing_setting_id: v.id("disappearing_setting_id")?,
        nonce: fixed_nonce(v.raw("nonce")?.to_vec())?,
        ciphertext: fixed_ciphertext(v.raw("ciphertext")?.to_vec())?,
    };
    validate_event(&event)?;
    Ok(event)
}

pub fn sign(
    signer_endpoint_shared_id: EventId,
    signer_private_key: &Ed25519PrivateKey,
    payload: Vec<u8>,
) -> SignedMessageEnvelope {
    let mut envelope = SignedMessageEnvelope {
        signer_endpoint_shared_id,
        signer_public_key: crypto::ed25519_public_key(signer_private_key),
        payload,
        signature: [0; ED25519_SIGNATURE_BYTES],
    };
    envelope.signature = crypto::ed25519_sign(signer_private_key, &signing_bytes(&envelope));
    envelope
}

pub fn encode_signed(event: &SignedMessageEnvelope) -> Vec<u8> {
    SIGNED_SCHEMA
        .encoder()
        .id(&event.signer_endpoint_shared_id)
        .id(&event.signer_public_key)
        .bytes(&event.payload)
        .bytes(&event.signature)
        .finish()
}

pub fn decode_signed(bytes: &[u8]) -> Result<SignedMessageEnvelope, String> {
    let v = SIGNED_SCHEMA.parse(bytes)?;
    let signature = fixed_signature(v.raw("signature")?.to_vec())?;
    let event = SignedMessageEnvelope {
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
        return Err("signed message signature verification failed".to_string());
    }
    Ok(event)
}

pub fn signing_bytes(event: &SignedMessageEnvelope) -> Vec<u8> {
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
    let mut dependencies = Vec::with_capacity(6);
    push_unique(&mut dependencies, envelope.signer_endpoint_shared_id);
    push_unique(&mut dependencies, metadata.workspace_id);
    push_unique(&mut dependencies, metadata.author_user_id);
    push_unique(&mut dependencies, metadata.removal_frontier_id);
    push_unique(&mut dependencies, metadata.local_history_node_secret_id);
    push_unique(&mut dependencies, metadata.disappearing_setting_id);
    Ok(EventRecord {
        timestamp: metadata.created_at_ms,
        body_len: MESSAGE_WIRE_SIZE - 1,
        canonical_bytes: bytes,
        dependencies,
        workspace_id: Some(metadata.workspace_id),
        scope: EventScope::Shared,
    })
}

fn metadata(bytes: &[u8]) -> Result<MessageMetadata, String> {
    let v = SCHEMA.parse(bytes)?;
    let metadata = MessageMetadata {
        workspace_id: v.id("workspace_id")?,
        created_at_ms: v.u64("created_at_ms")?,
        author_user_id: v.id("author_user_id")?,
        removal_frontier_id: v.id("removal_frontier_id")?,
        local_history_node_secret_id: v.id("local_history_node_secret_id")?,
        expires_at_minute: v.u64("expires_at_minute")?,
        disappearing_setting_id: v.id("disappearing_setting_id")?,
    };
    validate_id("message workspace", &metadata.workspace_id)?;
    validate_id("message author_user_id", &metadata.author_user_id)?;
    validate_id("message removal_frontier_id", &metadata.removal_frontier_id)?;
    validate_id(
        "message local_history_node_secret_id",
        &metadata.local_history_node_secret_id,
    )?;
    validate_id(
        "message disappearing_setting_id",
        &metadata.disappearing_setting_id,
    )?;
    validate_expires_at_minute(metadata.created_at_ms, metadata.expires_at_minute)?;
    Ok(metadata)
}

/// Authoring sanity guard. The projector additionally rejects messages that
/// are already past their expiry at receive time; this check only enforces
/// the canonical-bytes invariant that an authored message's stamped expiry
/// cannot be earlier than its authored unix_minute.
fn validate_expires_at_minute(created_at_ms: u64, expires_at_minute: u64) -> Result<(), String> {
    use crate::protocol::event_modules::content::message::types::EXPIRES_NEVER;
    if expires_at_minute == EXPIRES_NEVER {
        return Ok(());
    }
    let authored_minute = created_at_ms / super::types::UNIX_MINUTE_MS;
    if expires_at_minute < authored_minute {
        return Err("message expires_at_minute is earlier than authored minute".to_string());
    }
    Ok(())
}

/// Build the AEAD associated-data block for a message ciphertext.
///
/// The block binds every fixed field of the canonical bytes plus the signer
/// endpoint id. The leaf coordinate is recoverable from the canonical fields
/// alone (see `message_event_id_in_minute`), so AAD does not need a separate
/// leaf-nonce slot.
pub fn associated_data(event: &MessageEvent, signer_endpoint_shared_id: EventId) -> Vec<u8> {
    let mut out = Writer::with_capacity(1 + 8 + 8 + (32 * 6) + XCHACHA20_POLY1305_NONCE_BYTES);
    out.u8(TYPE_MESSAGE);
    out.id(&event.workspace_id);
    out.u64(event.created_at_ms);
    out.id(&event.author_user_id);
    out.id(&event.removal_frontier_id);
    out.id(&event.local_history_node_secret_id);
    out.u64(event.expires_at_minute);
    out.id(&event.disappearing_setting_id);
    out.raw(&event.nonce);
    out.id(&signer_endpoint_shared_id);
    out.finish()
}

fn validate_signed_payload(event: &SignedMessageEnvelope) -> Result<(), String> {
    let Some(actual_type) = event.payload.first().copied() else {
        return Err("signed message payload is empty".to_string());
    };
    if actual_type != TYPE_MESSAGE {
        return Err("signed message payload is not a message event".to_string());
    }
    metadata(&event.payload).map(|_| ())
}

fn fixed_signature(bytes: Vec<u8>) -> Result<[u8; ED25519_SIGNATURE_BYTES], String> {
    bytes
        .try_into()
        .map_err(|_| "signed message signature length mismatch".to_string())
}

fn fixed_nonce(bytes: Vec<u8>) -> Result<[u8; XCHACHA20_POLY1305_NONCE_BYTES], String> {
    bytes
        .try_into()
        .map_err(|_| "message nonce length mismatch".to_string())
}

fn fixed_ciphertext(bytes: Vec<u8>) -> Result<MessageCiphertext, String> {
    bytes
        .try_into()
        .map_err(|_| "message ciphertext length mismatch".to_string())
}

fn validate_event(event: &MessageEvent) -> Result<(), String> {
    validate_id("message workspace", &event.workspace_id)?;
    validate_id("message author_user_id", &event.author_user_id)?;
    validate_id("message removal_frontier_id", &event.removal_frontier_id)?;
    validate_id(
        "message local_history_node_secret_id",
        &event.local_history_node_secret_id,
    )?;
    validate_id(
        "message disappearing_setting_id",
        &event.disappearing_setting_id,
    )?;
    Ok(())
}

fn validate_id(name: &str, id: &EventId) -> Result<(), String> {
    if id.iter().all(|byte| *byte == 0) {
        return Err(format!("{name} cannot be empty"));
    }
    Ok(())
}

fn push_unique(out: &mut Vec<EventId>, id: EventId) {
    if !out.iter().any(|candidate| candidate == &id) {
        out.push(id);
    }
}

pub(crate) fn encode_text_slot(text: &str) -> Result<[u8; MESSAGE_TEXT_BYTES], String> {
    let bytes = text.as_bytes();
    if bytes.len() > MESSAGE_TEXT_BYTES {
        return Err("message text is too long".to_string());
    }
    if bytes.contains(&0) {
        return Err("message text cannot contain NUL".to_string());
    }
    let mut out = [0; MESSAGE_TEXT_BYTES];
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(out)
}

pub(crate) fn decode_text_slot(bytes: &[u8]) -> Result<String, String> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if bytes[end..].iter().any(|byte| *byte != 0) {
        return Err("message text has non-canonical padding".to_string());
    }
    std::str::from_utf8(&bytes[..end])
        .map_err(|_| "message text is not valid utf-8".to_string())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> MessageEvent {
        MessageEvent {
            workspace_id: [1; 32],
            created_at_ms: 1234,
            author_user_id: [2; 32],
            removal_frontier_id: [3; 32],
            local_history_node_secret_id: [4; 32],
            expires_at_minute: super::super::types::EXPIRES_NEVER,
            disappearing_setting_id: [1; 32],
            nonce: [5; XCHACHA20_POLY1305_NONCE_BYTES],
            ciphertext: [6; MESSAGE_CIPHERTEXT_BYTES],
        }
    }

    #[test]
    fn roundtrips_inner_message_event() {
        let bytes = encode(&event());
        assert_eq!(bytes.len(), MESSAGE_WIRE_SIZE);
        assert_eq!(decode(&bytes).expect("decode"), event());
    }

    #[test]
    fn rejects_too_long_text_and_nul_text_and_bad_padding() {
        let mut bytes = encode(&event());
        bytes.push(0);
        let err = decode(&bytes).expect_err("trailing must fail");
        assert!(err.contains("expected"), "{err}");

        assert_eq!(
            encode_text_slot(&"x".repeat(MESSAGE_TEXT_BYTES + 1)).expect_err("oversize must fail"),
            "message text is too long"
        );

        assert_eq!(
            encode_text_slot("bad\0text").expect_err("nul text must fail"),
            "message text cannot contain NUL"
        );

        let mut bytes = encode_text_slot("hello world").expect("encode");
        let text_start = 0;
        bytes[text_start + "hello world".len() + 1] = b'x';
        assert_eq!(
            decode_text_slot(&bytes).expect_err("padding must fail"),
            "message text has non-canonical padding"
        );
    }

    #[test]
    fn signed_envelope_roundtrips_and_records_dependencies() {
        let payload = encode(&event());
        let envelope = sign([8; 32], &[7; 32], payload);
        let bytes = encode_signed(&envelope);

        let decoded = decode_signed(&bytes).expect("decode signed");
        assert_eq!(decoded, envelope);

        let record = signed_record_from_bytes(bytes.clone()).expect("record");
        assert_eq!(record.canonical_bytes, bytes);
        assert_eq!(record.timestamp, 1234);
        assert_eq!(
            record.dependencies,
            vec![[8; 32], [1; 32], [2; 32], [3; 32], [4; 32]]
        );
        assert_eq!(record.workspace_id, Some([1; 32]));
        assert_eq!(record.scope, EventScope::Shared);
    }

    #[test]
    fn signed_envelope_rejects_tamper() {
        let payload = encode(&event());
        let envelope = sign([3; 32], &[7; 32], payload);
        let mut bytes = encode_signed(&envelope);
        let last = bytes.len() - 1;
        bytes[last] ^= 1;

        assert!(decode_signed(&bytes)
            .expect_err("tampered signature must fail")
            .contains("signature verification failed"));
    }
}

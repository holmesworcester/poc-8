//! Codec for signed reaction events.
//!
//! Reactions point at a target message via a fixed-width id. The signed
//! envelope mirrors the signed message envelope so admission and projection
//! follow the same authority rule: the signer must be a workspace endpoint
//! membership and the named author must be a workspace member.

use crate::core::crypto::{
    self, Ed25519PrivateKey, ED25519_SIGNATURE_BYTES, XCHACHA20_POLY1305_NONCE_BYTES,
};
use crate::protocol::event_modules::types::{EventId, EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};
use crate::protocol::wire_schema::{Field, WireSchema};

use super::types::{
    ReactionCiphertext, ReactionEvent, SignedReactionEnvelope, REACTION_CIPHERTEXT_BYTES,
    REACTION_EMOJI_BYTES,
};

pub const TYPE_REACTION: u8 = 7;
pub const TYPE_SIGNED_REACTION: u8 = 8;
pub const REACTION_ENCRYPTION_PURPOSE: &[u8] = b"topo reaction emoji v2";

pub const SCHEMA: WireSchema = WireSchema::new(
    "reaction",
    TYPE_REACTION,
    &[
        Field::id("workspace_id"),
        Field::u64("created_at_ms"),
        Field::id("target_message_id"),
        Field::id("author_user_id"),
        Field::id("removal_frontier_id"),
        Field::id("local_history_node_secret_id"),
        Field::bytes("nonce", XCHACHA20_POLY1305_NONCE_BYTES),
        Field::bytes("ciphertext", REACTION_CIPHERTEXT_BYTES),
    ],
);

pub const REACTION_WIRE_SIZE: usize = SCHEMA.wire_size();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReactionMetadata {
    workspace_id: EventId,
    created_at_ms: u64,
    target_message_id: EventId,
    author_user_id: EventId,
    removal_frontier_id: EventId,
    local_history_node_secret_id: EventId,
}

pub fn encode(event: &ReactionEvent) -> Vec<u8> {
    SCHEMA
        .encoder()
        .id(&event.workspace_id)
        .u64(event.created_at_ms)
        .id(&event.target_message_id)
        .id(&event.author_user_id)
        .id(&event.removal_frontier_id)
        .id(&event.local_history_node_secret_id)
        .bytes(&event.nonce)
        .bytes(&event.ciphertext)
        .finish()
}

pub fn decode(bytes: &[u8]) -> Result<ReactionEvent, String> {
    let v = SCHEMA.parse(bytes)?;
    let event = ReactionEvent {
        workspace_id: v.id("workspace_id")?,
        created_at_ms: v.u64("created_at_ms")?,
        target_message_id: v.id("target_message_id")?,
        author_user_id: v.id("author_user_id")?,
        removal_frontier_id: v.id("removal_frontier_id")?,
        local_history_node_secret_id: v.id("local_history_node_secret_id")?,
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
) -> SignedReactionEnvelope {
    let mut envelope = SignedReactionEnvelope {
        signer_endpoint_shared_id,
        signer_public_key: crypto::ed25519_public_key(signer_private_key),
        payload,
        signature: [0; ED25519_SIGNATURE_BYTES],
    };
    envelope.signature = crypto::ed25519_sign(signer_private_key, &signing_bytes(&envelope));
    envelope
}

pub fn encode_signed(event: &SignedReactionEnvelope) -> Vec<u8> {
    let mut out = Writer::with_capacity(signing_len(event.payload.len()) + ED25519_SIGNATURE_BYTES);
    write_signing_fields(&mut out, event);
    out.raw(&event.signature);
    out.finish()
}

pub fn decode_signed(bytes: &[u8]) -> Result<SignedReactionEnvelope, String> {
    let mut reader = Reader::new(bytes, "signed reaction envelope");
    let tag = reader.u8()?;
    if tag != TYPE_SIGNED_REACTION {
        return Err("expected signed reaction envelope".to_string());
    }
    let signer_endpoint_shared_id = reader.id()?;
    let signer_public_key = reader.id()?;
    let payload = reader.sized_bytes()?;
    let signature_bytes = reader.bytes(ED25519_SIGNATURE_BYTES)?;
    reader.finish()?;

    let signature = fixed_signature(signature_bytes)?;
    let event = SignedReactionEnvelope {
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
        return Err("signed reaction signature verification failed".to_string());
    }
    Ok(event)
}

pub fn signing_bytes(event: &SignedReactionEnvelope) -> Vec<u8> {
    let mut out = Writer::with_capacity(signing_len(event.payload.len()));
    write_signing_fields(&mut out, event);
    out.finish()
}

pub fn signed_record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let envelope = decode_signed(&bytes)?;
    let metadata = metadata(&envelope.payload)?;
    let mut dependencies = Vec::with_capacity(6);
    push_unique(&mut dependencies, envelope.signer_endpoint_shared_id);
    push_unique(&mut dependencies, metadata.workspace_id);
    push_unique(&mut dependencies, metadata.author_user_id);
    push_unique(&mut dependencies, metadata.target_message_id);
    push_unique(&mut dependencies, metadata.removal_frontier_id);
    push_unique(&mut dependencies, metadata.local_history_node_secret_id);
    Ok(EventRecord {
        timestamp: metadata.created_at_ms,
        body_len: REACTION_WIRE_SIZE - 1,
        canonical_bytes: bytes,
        dependencies,
        workspace_id: Some(metadata.workspace_id),
        scope: EventScope::Shared,
    })
}

fn metadata(bytes: &[u8]) -> Result<ReactionMetadata, String> {
    let mut reader = Reader::new(bytes, "reaction event");
    let tag = reader.u8()?;
    if tag != TYPE_REACTION {
        return Err("expected reaction event".to_string());
    }
    let workspace_id = reader.id()?;
    let created_at_ms = reader.u64()?;
    let target_message_id = reader.id()?;
    let author_user_id = reader.id()?;
    let removal_frontier_id = reader.id()?;
    let local_history_node_secret_id = reader.id()?;
    let _nonce = reader.bytes(XCHACHA20_POLY1305_NONCE_BYTES)?;
    let _ciphertext = reader.bytes(REACTION_CIPHERTEXT_BYTES)?;
    reader.finish()?;
    let metadata = ReactionMetadata {
        workspace_id,
        created_at_ms,
        target_message_id,
        author_user_id,
        removal_frontier_id,
        local_history_node_secret_id,
    };
    validate_id("reaction workspace", &metadata.workspace_id)?;
    validate_id("reaction target_message_id", &metadata.target_message_id)?;
    validate_id("reaction author_user_id", &metadata.author_user_id)?;
    validate_id(
        "reaction removal_frontier_id",
        &metadata.removal_frontier_id,
    )?;
    validate_id(
        "reaction local_history_node_secret_id",
        &metadata.local_history_node_secret_id,
    )?;
    Ok(metadata)
}

pub fn associated_data(event: &ReactionEvent, signer_endpoint_shared_id: EventId) -> Vec<u8> {
    let mut out = Writer::with_capacity(1 + 8 + (32 * 6) + XCHACHA20_POLY1305_NONCE_BYTES);
    out.u8(TYPE_REACTION);
    out.id(&event.workspace_id);
    out.u64(event.created_at_ms);
    out.id(&event.target_message_id);
    out.id(&event.author_user_id);
    out.id(&event.removal_frontier_id);
    out.id(&event.local_history_node_secret_id);
    out.raw(&event.nonce);
    out.id(&signer_endpoint_shared_id);
    out.finish()
}

fn validate_signed_payload(event: &SignedReactionEnvelope) -> Result<(), String> {
    let Some(actual_type) = event.payload.first().copied() else {
        return Err("signed reaction payload is empty".to_string());
    };
    if actual_type != TYPE_REACTION {
        return Err("signed reaction payload is not a reaction event".to_string());
    }
    metadata(&event.payload).map(|_| ())
}

fn write_signing_fields(out: &mut Writer, event: &SignedReactionEnvelope) {
    out.u8(TYPE_SIGNED_REACTION);
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
        .map_err(|_| "signed reaction signature length mismatch".to_string())
}

fn fixed_nonce(bytes: Vec<u8>) -> Result<[u8; XCHACHA20_POLY1305_NONCE_BYTES], String> {
    bytes
        .try_into()
        .map_err(|_| "reaction nonce length mismatch".to_string())
}

fn fixed_ciphertext(bytes: Vec<u8>) -> Result<ReactionCiphertext, String> {
    bytes
        .try_into()
        .map_err(|_| "reaction ciphertext length mismatch".to_string())
}

fn validate_event(event: &ReactionEvent) -> Result<(), String> {
    validate_id("reaction workspace", &event.workspace_id)?;
    validate_id("reaction target_message_id", &event.target_message_id)?;
    validate_id("reaction author_user_id", &event.author_user_id)?;
    validate_id("reaction removal_frontier_id", &event.removal_frontier_id)?;
    validate_id(
        "reaction local_history_node_secret_id",
        &event.local_history_node_secret_id,
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

pub(crate) fn encode_emoji_slot(emoji: &str) -> Result<[u8; REACTION_EMOJI_BYTES], String> {
    let bytes = emoji.as_bytes();
    if bytes.is_empty() {
        return Err("reaction emoji must not be empty".to_string());
    }
    if bytes.len() > REACTION_EMOJI_BYTES {
        return Err("reaction emoji is too long".to_string());
    }
    if bytes.contains(&0) {
        return Err("reaction emoji cannot contain NUL".to_string());
    }
    let mut out = [0; REACTION_EMOJI_BYTES];
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(out)
}

pub(crate) fn decode_emoji_slot(bytes: &[u8]) -> Result<String, String> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if end == 0 {
        return Err("reaction emoji must not be empty".to_string());
    }
    if bytes[end..].iter().any(|byte| *byte != 0) {
        return Err("reaction emoji has non-canonical padding".to_string());
    }
    std::str::from_utf8(&bytes[..end])
        .map_err(|_| "reaction emoji is not valid utf-8".to_string())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> ReactionEvent {
        ReactionEvent {
            workspace_id: [1; 32],
            created_at_ms: 99,
            target_message_id: [2; 32],
            author_user_id: [3; 32],
            removal_frontier_id: [4; 32],
            local_history_node_secret_id: [5; 32],
            nonce: [6; XCHACHA20_POLY1305_NONCE_BYTES],
            ciphertext: [7; REACTION_CIPHERTEXT_BYTES],
        }
    }

    #[test]
    fn roundtrips_inner_reaction_event() {
        let bytes = encode(&event());
        assert_eq!(bytes.len(), REACTION_WIRE_SIZE);
        assert_eq!(decode(&bytes).expect("decode"), event());
    }

    #[test]
    fn signed_envelope_record_dependencies_are_unique() {
        let payload = encode(&event());
        let envelope = sign([9; 32], &[5; 32], payload);
        let bytes = encode_signed(&envelope);
        let record = signed_record_from_bytes(bytes.clone()).expect("record");

        assert_eq!(
            record.dependencies,
            vec![[9; 32], [1; 32], [3; 32], [2; 32], [4; 32], [5; 32]]
        );
        assert_eq!(record.timestamp, 99);
        assert_eq!(record.scope, EventScope::Shared);
    }

    #[test]
    fn rejects_empty_emoji_and_nul() {
        assert_eq!(
            encode_emoji_slot("").expect_err("empty emoji must fail"),
            "reaction emoji must not be empty"
        );
        assert_eq!(
            encode_emoji_slot("bad\0").expect_err("nul emoji must fail"),
            "reaction emoji cannot contain NUL"
        );
    }
}

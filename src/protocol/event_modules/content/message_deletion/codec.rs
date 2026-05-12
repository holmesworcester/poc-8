//! Codec for signed message deletions.
//!
//! The canonical payload names only workspace, timestamp, target message, and
//! author. Authority is intentionally outside the payload and inside the signed
//! envelope plus dependency graph: projection verifies that the signer endpoint
//! belongs to the named author. This codec does not delete rows or infer target
//! existence.

use crate::core::crypto::{self, Ed25519PrivateKey, ED25519_SIGNATURE_BYTES};
use crate::protocol::event_modules::types::{EventId, EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};
use crate::protocol::wire_schema::{Field, WireSchema};

use super::types::{MessageDeletionEvent, SignedMessageDeletionEnvelope};

pub const TYPE_MESSAGE_DELETION: u8 = 11;
pub const TYPE_SIGNED_MESSAGE_DELETION: u8 = 12;

pub const SCHEMA: WireSchema = WireSchema::new(
    "message_deletion",
    TYPE_MESSAGE_DELETION,
    &[
        Field::id("workspace_id"),
        Field::u64("created_at_ms"),
        Field::id("target_message_id"),
        Field::id("author_user_id"),
    ],
);

pub const MESSAGE_DELETION_WIRE_SIZE: usize = SCHEMA.wire_size();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeletionMetadata {
    workspace_id: EventId,
    created_at_ms: u64,
    target_message_id: EventId,
    author_user_id: EventId,
}

pub fn encode(event: &MessageDeletionEvent) -> Vec<u8> {
    SCHEMA
        .encoder()
        .id(&event.workspace_id)
        .u64(event.created_at_ms)
        .id(&event.target_message_id)
        .id(&event.author_user_id)
        .finish()
}

pub fn decode(bytes: &[u8]) -> Result<MessageDeletionEvent, String> {
    let v = SCHEMA.parse(bytes)?;
    Ok(MessageDeletionEvent {
        workspace_id: v.id("workspace_id")?,
        created_at_ms: v.u64("created_at_ms")?,
        target_message_id: v.id("target_message_id")?,
        author_user_id: v.id("author_user_id")?,
    })
}

pub fn sign(
    signer_endpoint_shared_id: EventId,
    signer_private_key: &Ed25519PrivateKey,
    payload: Vec<u8>,
) -> SignedMessageDeletionEnvelope {
    let mut envelope = SignedMessageDeletionEnvelope {
        signer_endpoint_shared_id,
        signer_public_key: crypto::ed25519_public_key(signer_private_key),
        payload,
        signature: [0; ED25519_SIGNATURE_BYTES],
    };
    envelope.signature = crypto::ed25519_sign(signer_private_key, &signing_bytes(&envelope));
    envelope
}

pub fn encode_signed(event: &SignedMessageDeletionEnvelope) -> Vec<u8> {
    let mut out = Writer::with_capacity(signing_len(event.payload.len()) + ED25519_SIGNATURE_BYTES);
    write_signing_fields(&mut out, event);
    out.raw(&event.signature);
    out.finish()
}

pub fn decode_signed(bytes: &[u8]) -> Result<SignedMessageDeletionEnvelope, String> {
    let mut reader = Reader::new(bytes, "signed message deletion envelope");
    let tag = reader.u8()?;
    if tag != TYPE_SIGNED_MESSAGE_DELETION {
        return Err("expected signed message deletion envelope".to_string());
    }
    let signer_endpoint_shared_id = reader.id()?;
    let signer_public_key = reader.id()?;
    let payload = reader.sized_bytes()?;
    let signature_bytes = reader.bytes(ED25519_SIGNATURE_BYTES)?;
    reader.finish()?;

    let signature = fixed_signature(signature_bytes)?;
    let event = SignedMessageDeletionEnvelope {
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
        return Err("signed message deletion signature verification failed".to_string());
    }
    Ok(event)
}

pub fn signing_bytes(event: &SignedMessageDeletionEnvelope) -> Vec<u8> {
    let mut out = Writer::with_capacity(signing_len(event.payload.len()));
    write_signing_fields(&mut out, event);
    out.finish()
}

pub fn signed_record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let envelope = decode_signed(&bytes)?;
    let metadata = metadata(&envelope.payload)?;
    // The target message id is intentionally not a dependency: deletion is
    // expressed as a label on that id, and the message projector consults the
    // label at project time. This keeps delete-before-create convergent.
    let mut dependencies = Vec::with_capacity(3);
    push_unique(&mut dependencies, envelope.signer_endpoint_shared_id);
    push_unique(&mut dependencies, metadata.workspace_id);
    push_unique(&mut dependencies, metadata.author_user_id);
    Ok(EventRecord {
        timestamp: metadata.created_at_ms,
        body_len: MESSAGE_DELETION_WIRE_SIZE - 1,
        canonical_bytes: bytes,
        dependencies,
        workspace_id: Some(metadata.workspace_id),
        scope: EventScope::Shared,
    })
}

fn metadata(bytes: &[u8]) -> Result<DeletionMetadata, String> {
    let mut reader = Reader::new(bytes, "message deletion event");
    let tag = reader.u8()?;
    if tag != TYPE_MESSAGE_DELETION {
        return Err("expected message deletion event".to_string());
    }
    let workspace_id = reader.id()?;
    let created_at_ms = reader.u64()?;
    let target_message_id = reader.id()?;
    let author_user_id = reader.id()?;
    reader.finish()?;
    Ok(DeletionMetadata {
        workspace_id,
        created_at_ms,
        target_message_id,
        author_user_id,
    })
}

fn validate_signed_payload(event: &SignedMessageDeletionEnvelope) -> Result<(), String> {
    let Some(actual_type) = event.payload.first().copied() else {
        return Err("signed message deletion payload is empty".to_string());
    };
    if actual_type != TYPE_MESSAGE_DELETION {
        return Err("signed message deletion payload is not a deletion event".to_string());
    }
    metadata(&event.payload).map(|_| ())
}

fn write_signing_fields(out: &mut Writer, event: &SignedMessageDeletionEnvelope) {
    out.u8(TYPE_SIGNED_MESSAGE_DELETION);
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
        .map_err(|_| "signed message deletion signature length mismatch".to_string())
}

fn push_unique(out: &mut Vec<EventId>, id: EventId) {
    if !out.iter().any(|candidate| candidate == &id) {
        out.push(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> MessageDeletionEvent {
        MessageDeletionEvent {
            workspace_id: [1; 32],
            created_at_ms: 9,
            target_message_id: [2; 32],
            author_user_id: [3; 32],
        }
    }

    #[test]
    fn roundtrips_inner_deletion_event() {
        let bytes = encode(&event());
        assert_eq!(bytes.len(), MESSAGE_DELETION_WIRE_SIZE);
        assert_eq!(decode(&bytes).expect("decode"), event());
    }

    #[test]
    fn signed_envelope_dependencies_omit_the_target_message() {
        let payload = encode(&event());
        let envelope = sign([4; 32], &[5; 32], payload);
        let bytes = encode_signed(&envelope);
        let record = signed_record_from_bytes(bytes).expect("record");
        assert_eq!(record.dependencies, vec![[4; 32], [1; 32], [3; 32]]);
    }
}

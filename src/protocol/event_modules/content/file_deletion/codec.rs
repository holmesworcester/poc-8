//! Codec for signed file deletions.
//!
//! Layout mirrors `message_deletion`. The canonical payload names only
//! workspace, timestamp, target file event, and author. The signed envelope
//! plus dependency graph carry authority: projection verifies the signer
//! endpoint belongs to the named author. This codec does not delete rows
//! or infer target existence.

use crate::core::crypto::{self, Ed25519PrivateKey, ED25519_SIGNATURE_BYTES};
use crate::protocol::event_modules::types::{EventId, EventRecord, EventScope};
use crate::protocol::wire_schema::{Field, WireSchema};

use super::types::{FileDeletionEvent, SignedFileDeletionEnvelope};

pub const TYPE_FILE_DELETION: u8 = 26;
pub const TYPE_SIGNED_FILE_DELETION: u8 = 27;

pub const SCHEMA: WireSchema = WireSchema::new(
    "file_deletion",
    TYPE_FILE_DELETION,
    &[
        Field::id("workspace_id"),
        Field::u64("created_at_ms"),
        Field::id("target_file_event_id"),
        Field::id("author_user_id"),
    ],
);

pub const FILE_DELETION_WIRE_SIZE: usize = SCHEMA.wire_size();

pub const SIGNED_SCHEMA: WireSchema = WireSchema::new(
    "signed file_deletion",
    TYPE_SIGNED_FILE_DELETION,
    &[
        Field::id("signer_endpoint_shared_id"),
        Field::id("signer_public_key"),
        Field::bytes("payload", FILE_DELETION_WIRE_SIZE),
        Field::bytes("signature", ED25519_SIGNATURE_BYTES),
    ],
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DeletionMetadata {
    workspace_id: EventId,
    created_at_ms: u64,
    target_file_event_id: EventId,
    author_user_id: EventId,
}

pub fn encode(event: &FileDeletionEvent) -> Vec<u8> {
    SCHEMA
        .encoder()
        .id(&event.workspace_id)
        .u64(event.created_at_ms)
        .id(&event.target_file_event_id)
        .id(&event.author_user_id)
        .finish()
}

pub fn decode(bytes: &[u8]) -> Result<FileDeletionEvent, String> {
    let v = SCHEMA.parse(bytes)?;
    Ok(FileDeletionEvent {
        workspace_id: v.id("workspace_id")?,
        created_at_ms: v.u64("created_at_ms")?,
        target_file_event_id: v.id("target_file_event_id")?,
        author_user_id: v.id("author_user_id")?,
    })
}

pub fn sign(
    signer_endpoint_shared_id: EventId,
    signer_private_key: &Ed25519PrivateKey,
    payload: Vec<u8>,
) -> SignedFileDeletionEnvelope {
    let mut envelope = SignedFileDeletionEnvelope {
        signer_endpoint_shared_id,
        signer_public_key: crypto::ed25519_public_key(signer_private_key),
        payload,
        signature: [0; ED25519_SIGNATURE_BYTES],
    };
    envelope.signature = crypto::ed25519_sign(signer_private_key, &signing_bytes(&envelope));
    envelope
}

pub fn encode_signed(event: &SignedFileDeletionEnvelope) -> Vec<u8> {
    SIGNED_SCHEMA
        .encoder()
        .id(&event.signer_endpoint_shared_id)
        .id(&event.signer_public_key)
        .bytes(&event.payload)
        .bytes(&event.signature)
        .finish()
}

pub fn decode_signed(bytes: &[u8]) -> Result<SignedFileDeletionEnvelope, String> {
    let v = SIGNED_SCHEMA.parse(bytes)?;
    let signature = fixed_signature(v.raw("signature")?.to_vec())?;
    let event = SignedFileDeletionEnvelope {
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
        return Err("signed file deletion signature verification failed".to_string());
    }
    Ok(event)
}

pub fn signing_bytes(event: &SignedFileDeletionEnvelope) -> Vec<u8> {
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
    // The target file event id is intentionally not a dependency: deletion
    // is expressed as a label on that id, and the file projector / purge
    // worker consult the label at project time. This keeps
    // delete-before-create convergent.
    let mut dependencies = Vec::with_capacity(3);
    push_unique(&mut dependencies, envelope.signer_endpoint_shared_id);
    push_unique(&mut dependencies, metadata.workspace_id);
    push_unique(&mut dependencies, metadata.author_user_id);
    Ok(EventRecord {
        timestamp: metadata.created_at_ms,
        body_len: FILE_DELETION_WIRE_SIZE - 1,
        canonical_bytes: bytes,
        dependencies,
        workspace_id: Some(metadata.workspace_id),
        scope: EventScope::Shared,
    })
}

fn metadata(bytes: &[u8]) -> Result<DeletionMetadata, String> {
    let event = decode(bytes)?;
    Ok(DeletionMetadata {
        workspace_id: event.workspace_id,
        created_at_ms: event.created_at_ms,
        target_file_event_id: event.target_file_event_id,
        author_user_id: event.author_user_id,
    })
}

fn validate_signed_payload(event: &SignedFileDeletionEnvelope) -> Result<(), String> {
    let Some(actual_type) = event.payload.first().copied() else {
        return Err("signed file deletion payload is empty".to_string());
    };
    if actual_type != TYPE_FILE_DELETION {
        return Err("signed file deletion payload is not a deletion event".to_string());
    }
    metadata(&event.payload).map(|_| ())
}

fn fixed_signature(bytes: Vec<u8>) -> Result<[u8; ED25519_SIGNATURE_BYTES], String> {
    bytes
        .try_into()
        .map_err(|_| "signed file deletion signature length mismatch".to_string())
}

fn push_unique(out: &mut Vec<EventId>, id: EventId) {
    if !out.iter().any(|candidate| candidate == &id) {
        out.push(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> FileDeletionEvent {
        FileDeletionEvent {
            workspace_id: [1; 32],
            created_at_ms: 9,
            target_file_event_id: [2; 32],
            author_user_id: [3; 32],
        }
    }

    #[test]
    fn roundtrips_inner_deletion_event() {
        let bytes = encode(&event());
        assert_eq!(bytes.len(), FILE_DELETION_WIRE_SIZE);
        assert_eq!(decode(&bytes).expect("decode"), event());
    }

    #[test]
    fn signed_envelope_dependencies_omit_the_target_file_event() {
        let payload = encode(&event());
        let envelope = sign([4; 32], &[5; 32], payload);
        let bytes = encode_signed(&envelope);
        let record = signed_record_from_bytes(bytes).expect("record");
        assert_eq!(record.dependencies, vec![[4; 32], [1; 32], [3; 32]]);
    }
}

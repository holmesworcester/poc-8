//! Codec for signed file slice events.
//!
//! The slice carries a self-contained BAO proof for `[slice_start, slice_len)`
//! that the projector verifies against the descriptor's `root_hash`. The proof
//! slot is fixed-width with a leading length prefix; the descriptor is named
//! by `file_id` and pulled into the projector's dependency context. The slice
//! event also depends on the file descriptor event id so the worker holds the
//! slice until its descriptor applies, then projects against a real root hash.

use crate::core::crypto::{self, Ed25519PrivateKey, ED25519_SIGNATURE_BYTES};
use crate::protocol::event_modules::types::{EventId, EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::types::{
    BuildSlice, FileSliceEvent, SignedFileSliceEnvelope, FILE_SLICE_PROOF_BYTES,
};

pub const TYPE_FILE_SLICE: u8 = 16;
pub const TYPE_SIGNED_FILE_SLICE: u8 = 17;

/// Inner wire size: tag(1) + workspace(32) + ts(8) + file_id(32) + file_event_id(32)
/// + slice#(4) + proof_len(4) + proof slot.
pub const FILE_SLICE_WIRE_SIZE: usize = 1 + 32 + 8 + 32 + 32 + 4 + 4 + FILE_SLICE_PROOF_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileSliceMetadata {
    workspace_id: EventId,
    created_at_ms: u64,
    file_id: EventId,
    file_event_id: EventId,
    slice_number: u32,
    proof_len: u32,
}

/// Construct a file slice from a descriptor's root hash + outboard.
///
/// The caller has the full plaintext and outboard available and uses the
/// descriptor's `slice_bytes` budget to pick the byte range. The result is a
/// `FileSliceEvent` whose proof is self-verifying against the descriptor.
pub fn build_slice(input: BuildSlice<'_>) -> Result<FileSliceEvent, String> {
    let proof = crypto::bao_extract_slice(
        input.plaintext,
        input.outboard,
        input.slice_start,
        input.slice_len,
    )?;
    Ok(FileSliceEvent {
        workspace_id: input.workspace_id,
        created_at_ms: input.created_at_ms,
        file_id: input.file_id,
        slice_number: input.slice_number,
        proof,
    })
}

pub fn encode(event: &FileSliceEvent, file_event_id: &EventId) -> Result<Vec<u8>, String> {
    if event.proof.len() > FILE_SLICE_PROOF_BYTES {
        return Err("file slice proof exceeds slot capacity".to_string());
    }
    let mut out = Writer::with_capacity(FILE_SLICE_WIRE_SIZE);
    out.u8(TYPE_FILE_SLICE);
    out.id(&event.workspace_id);
    out.u64(event.created_at_ms);
    out.id(&event.file_id);
    out.id(file_event_id);
    out.u32(event.slice_number as usize);
    out.u32(event.proof.len());
    out.raw(&event.proof);
    out.raw(&vec![0u8; FILE_SLICE_PROOF_BYTES - event.proof.len()]);
    Ok(out.finish())
}

pub fn decode(bytes: &[u8]) -> Result<(FileSliceEvent, EventId), String> {
    let mut reader = Reader::new(bytes, "file slice event");
    let tag = reader.u8()?;
    if tag != TYPE_FILE_SLICE {
        return Err("expected file slice event".to_string());
    }
    let workspace_id = reader.id()?;
    let created_at_ms = reader.u64()?;
    let file_id = reader.id()?;
    let file_event_id = reader.id()?;
    let slice_number = reader.u32()?;
    let proof_len = reader.u32()? as usize;
    if proof_len > FILE_SLICE_PROOF_BYTES {
        return Err("file slice declares more proof than the slot holds".to_string());
    }
    let slot = reader.slice(FILE_SLICE_PROOF_BYTES)?;
    reader.finish()?;

    let proof = slot[..proof_len].to_vec();
    if slot[proof_len..].iter().any(|byte| *byte != 0) {
        return Err("file slice slot has non-canonical padding".to_string());
    }
    Ok((
        FileSliceEvent {
            workspace_id,
            created_at_ms,
            file_id,
            slice_number,
            proof,
        },
        file_event_id,
    ))
}

pub fn sign(
    signer_endpoint_shared_id: EventId,
    signer_private_key: &Ed25519PrivateKey,
    payload: Vec<u8>,
) -> SignedFileSliceEnvelope {
    let mut envelope = SignedFileSliceEnvelope {
        signer_endpoint_shared_id,
        signer_public_key: crypto::ed25519_public_key(signer_private_key),
        payload,
        signature: [0; ED25519_SIGNATURE_BYTES],
    };
    envelope.signature = crypto::ed25519_sign(signer_private_key, &signing_bytes(&envelope));
    envelope
}

pub fn encode_signed(event: &SignedFileSliceEnvelope) -> Vec<u8> {
    let mut out = Writer::with_capacity(signing_len(event.payload.len()) + ED25519_SIGNATURE_BYTES);
    write_signing_fields(&mut out, event);
    out.raw(&event.signature);
    out.finish()
}

pub fn decode_signed(bytes: &[u8]) -> Result<SignedFileSliceEnvelope, String> {
    let mut reader = Reader::new(bytes, "signed file slice envelope");
    let tag = reader.u8()?;
    if tag != TYPE_SIGNED_FILE_SLICE {
        return Err("expected signed file slice envelope".to_string());
    }
    let signer_endpoint_shared_id = reader.id()?;
    let signer_public_key = reader.id()?;
    let payload = reader.sized_bytes()?;
    let signature_bytes = reader.bytes(ED25519_SIGNATURE_BYTES)?;
    reader.finish()?;

    let signature = fixed_signature(signature_bytes)?;
    let event = SignedFileSliceEnvelope {
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
        return Err("signed file slice signature verification failed".to_string());
    }
    Ok(event)
}

pub fn signing_bytes(event: &SignedFileSliceEnvelope) -> Vec<u8> {
    let mut out = Writer::with_capacity(signing_len(event.payload.len()));
    write_signing_fields(&mut out, event);
    out.finish()
}

pub fn signed_record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let envelope = decode_signed(&bytes)?;
    let metadata = metadata(&envelope.payload)?;
    let mut dependencies = Vec::with_capacity(3);
    push_unique(&mut dependencies, envelope.signer_endpoint_shared_id);
    push_unique(&mut dependencies, metadata.workspace_id);
    push_unique(&mut dependencies, metadata.file_event_id);
    Ok(EventRecord {
        timestamp: metadata.created_at_ms,
        body_len: FILE_SLICE_WIRE_SIZE - 1,
        canonical_bytes: bytes,
        dependencies,
        workspace_id: Some(metadata.workspace_id),
        scope: EventScope::Shared,
    })
}

fn metadata(bytes: &[u8]) -> Result<FileSliceMetadata, String> {
    let mut reader = Reader::new(bytes, "file slice event");
    let tag = reader.u8()?;
    if tag != TYPE_FILE_SLICE {
        return Err("expected file slice event".to_string());
    }
    let workspace_id = reader.id()?;
    let created_at_ms = reader.u64()?;
    let file_id = reader.id()?;
    let file_event_id = reader.id()?;
    let slice_number = reader.u32()?;
    let proof_len = reader.u32()?;
    if (proof_len as usize) > FILE_SLICE_PROOF_BYTES {
        return Err("file slice declares more proof than the slot holds".to_string());
    }
    let _slot = reader.slice(FILE_SLICE_PROOF_BYTES)?;
    reader.finish()?;
    Ok(FileSliceMetadata {
        workspace_id,
        created_at_ms,
        file_id,
        file_event_id,
        slice_number,
        proof_len,
    })
}

fn validate_signed_payload(event: &SignedFileSliceEnvelope) -> Result<(), String> {
    let Some(actual_type) = event.payload.first().copied() else {
        return Err("signed file slice payload is empty".to_string());
    };
    if actual_type != TYPE_FILE_SLICE {
        return Err("signed file slice payload is not a file slice event".to_string());
    }
    metadata(&event.payload).map(|_| ())
}

fn write_signing_fields(out: &mut Writer, event: &SignedFileSliceEnvelope) {
    out.u8(TYPE_SIGNED_FILE_SLICE);
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
        .map_err(|_| "signed file slice signature length mismatch".to_string())
}

fn push_unique(out: &mut Vec<EventId>, id: EventId) {
    if !out.iter().any(|candidate| candidate == &id) {
        out.push(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slice_event(file_event_id: &EventId) -> (FileSliceEvent, Vec<u8>) {
        let plaintext: Vec<u8> = (0..super::super::types::FILE_SLICE_DATA_BYTES as u32)
            .map(|byte| byte as u8)
            .collect();
        let (root_hash, outboard) = crypto::bao_outboard(&plaintext).expect("outboard");
        let event = build_slice(BuildSlice {
            workspace_id: [1; 32],
            created_at_ms: 11,
            file_id: [2; 32],
            slice_number: 0,
            plaintext: &plaintext,
            outboard: &outboard,
            slice_start: 0,
            slice_len: plaintext.len() as u64,
        })
        .expect("build slice");
        let _ = file_event_id;
        (event, root_hash.to_vec())
    }

    #[test]
    fn roundtrips_inner_file_slice_event() {
        let file_event_id = [9; 32];
        let (event, _) = slice_event(&file_event_id);
        let bytes = encode(&event, &file_event_id).expect("encode");
        assert_eq!(bytes.len(), FILE_SLICE_WIRE_SIZE);
        let (decoded, decoded_file_event_id) = decode(&bytes).expect("decode");
        assert_eq!(decoded, event);
        assert_eq!(decoded_file_event_id, file_event_id);
    }

    #[test]
    fn rejects_oversize_proof() {
        let event = FileSliceEvent {
            workspace_id: [1; 32],
            created_at_ms: 1,
            file_id: [2; 32],
            slice_number: 0,
            proof: vec![0; FILE_SLICE_PROOF_BYTES + 1],
        };
        assert!(encode(&event, &[3; 32]).is_err());
    }

    #[test]
    fn signed_envelope_dependencies_are_signer_workspace_and_file_event_id() {
        let file_event_id = [9; 32];
        let (event, _) = slice_event(&file_event_id);
        let payload = encode(&event, &file_event_id).expect("encode");
        let envelope = sign([4; 32], &[5; 32], payload);
        let bytes = encode_signed(&envelope);
        let record = signed_record_from_bytes(bytes).expect("record");
        assert_eq!(record.dependencies, vec![[4; 32], [1; 32], file_event_id]);
        assert_eq!(record.scope, EventScope::Shared);
    }
}

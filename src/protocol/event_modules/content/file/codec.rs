//! Codec for signed file descriptor events.
//!
//! The descriptor names the file_id (random, fixed 32 bytes), total size, and
//! the per-slice budget. Every slice carries the file_id and slice_number, so
//! the descriptor is the gluing record that lets workers stream and verify
//! slice arrival.

use crate::core::crypto::{self, Ed25519PrivateKey, ED25519_SIGNATURE_BYTES};
use crate::protocol::event_modules::types::{EventId, EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::types::{FileEvent, SignedFileEnvelope, FILE_MIME_BYTES, FILE_NAME_BYTES, MAX_FILE_BYTES};

pub const TYPE_FILE: u8 = 13;
pub const TYPE_SIGNED_FILE: u8 = 15;
/// tag(1) + workspace(32) + ts(8) + message_id(32) + author(32) + file_id(32)
/// + blob_bytes(8) + total_slices(4) + slice_bytes(4) + root_hash(32) + name + mime
pub const FILE_WIRE_SIZE: usize =
    1 + 32 + 8 + 32 + 32 + 32 + 8 + 4 + 4 + 32 + FILE_NAME_BYTES + FILE_MIME_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileMetadata {
    workspace_id: EventId,
    created_at_ms: u64,
    message_id: EventId,
    author_user_id: EventId,
    file_id: EventId,
}

pub fn encode(event: &FileEvent) -> Result<Vec<u8>, String> {
    validate(event)?;
    let filename = encode_text_slot(&event.filename, FILE_NAME_BYTES, "file filename")?;
    let mime_type = encode_text_slot(&event.mime_type, FILE_MIME_BYTES, "file mime type")?;
    let mut out = Writer::with_capacity(FILE_WIRE_SIZE);
    out.u8(TYPE_FILE);
    out.id(&event.workspace_id);
    out.u64(event.created_at_ms);
    out.id(&event.message_id);
    out.id(&event.author_user_id);
    out.id(&event.file_id);
    out.u64(event.blob_bytes);
    out.u32(event.total_slices as usize);
    out.u32(event.slice_bytes as usize);
    out.id(&event.root_hash);
    out.raw(&filename);
    out.raw(&mime_type);
    Ok(out.finish())
}

pub fn decode(bytes: &[u8]) -> Result<FileEvent, String> {
    let mut reader = Reader::new(bytes, "file event");
    let tag = reader.u8()?;
    if tag != TYPE_FILE {
        return Err("expected file event".to_string());
    }
    let workspace_id = reader.id()?;
    let created_at_ms = reader.u64()?;
    let message_id = reader.id()?;
    let author_user_id = reader.id()?;
    let file_id = reader.id()?;
    let blob_bytes = reader.u64()?;
    let total_slices = reader.u32()?;
    let slice_bytes = reader.u32()?;
    let root_hash = reader.id()?;
    let filename = decode_text_slot(reader.slice(FILE_NAME_BYTES)?, "file filename")?;
    let mime_type = decode_text_slot(reader.slice(FILE_MIME_BYTES)?, "file mime type")?;
    reader.finish()?;
    let event = FileEvent {
        workspace_id,
        created_at_ms,
        message_id,
        author_user_id,
        file_id,
        blob_bytes,
        total_slices,
        slice_bytes,
        root_hash,
        filename,
        mime_type,
    };
    validate(&event)?;
    Ok(event)
}

pub fn sign(
    signer_endpoint_shared_id: EventId,
    signer_private_key: &Ed25519PrivateKey,
    payload: Vec<u8>,
) -> SignedFileEnvelope {
    let mut envelope = SignedFileEnvelope {
        signer_endpoint_shared_id,
        signer_public_key: crypto::ed25519_public_key(signer_private_key),
        payload,
        signature: [0; ED25519_SIGNATURE_BYTES],
    };
    envelope.signature = crypto::ed25519_sign(signer_private_key, &signing_bytes(&envelope));
    envelope
}

pub fn encode_signed(event: &SignedFileEnvelope) -> Vec<u8> {
    let mut out = Writer::with_capacity(signing_len(event.payload.len()) + ED25519_SIGNATURE_BYTES);
    write_signing_fields(&mut out, event);
    out.raw(&event.signature);
    out.finish()
}

pub fn decode_signed(bytes: &[u8]) -> Result<SignedFileEnvelope, String> {
    let mut reader = Reader::new(bytes, "signed file envelope");
    let tag = reader.u8()?;
    if tag != TYPE_SIGNED_FILE {
        return Err("expected signed file envelope".to_string());
    }
    let signer_endpoint_shared_id = reader.id()?;
    let signer_public_key = reader.id()?;
    let payload = reader.sized_bytes()?;
    let signature_bytes = reader.bytes(ED25519_SIGNATURE_BYTES)?;
    reader.finish()?;

    let signature = fixed_signature(signature_bytes)?;
    let event = SignedFileEnvelope {
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
        return Err("signed file signature verification failed".to_string());
    }
    Ok(event)
}

pub fn signing_bytes(event: &SignedFileEnvelope) -> Vec<u8> {
    let mut out = Writer::with_capacity(signing_len(event.payload.len()));
    write_signing_fields(&mut out, event);
    out.finish()
}

pub fn signed_record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let envelope = decode_signed(&bytes)?;
    let metadata = metadata(&envelope.payload)?;
    let mut dependencies = Vec::with_capacity(4);
    push_unique(&mut dependencies, envelope.signer_endpoint_shared_id);
    push_unique(&mut dependencies, metadata.workspace_id);
    push_unique(&mut dependencies, metadata.author_user_id);
    push_unique(&mut dependencies, metadata.message_id);
    Ok(EventRecord {
        timestamp: metadata.created_at_ms,
        body_len: FILE_WIRE_SIZE - 1,
        canonical_bytes: bytes,
        dependencies,
        workspace_id: Some(metadata.workspace_id),
        scope: EventScope::Shared,
    })
}

pub fn file_id(payload: &[u8]) -> Result<EventId, String> {
    metadata(payload).map(|metadata| metadata.file_id)
}

fn metadata(bytes: &[u8]) -> Result<FileMetadata, String> {
    let event = decode(bytes)?;
    Ok(FileMetadata {
        workspace_id: event.workspace_id,
        created_at_ms: event.created_at_ms,
        message_id: event.message_id,
        author_user_id: event.author_user_id,
        file_id: event.file_id,
    })
}

fn validate(event: &FileEvent) -> Result<(), String> {
    if event.blob_bytes > MAX_FILE_BYTES {
        return Err("file size exceeds the 10 GiB limit".to_string());
    }
    if event.blob_bytes == 0 {
        if event.total_slices != 0 {
            return Err("zero-byte file must declare zero slices".to_string());
        }
        return Ok(());
    }
    if event.total_slices == 0 {
        return Err("non-empty file must declare at least one slice".to_string());
    }
    if event.slice_bytes == 0 {
        return Err("non-empty file must declare a slice budget".to_string());
    }
    let expected = expected_slice_count(event.blob_bytes, event.slice_bytes as u64)?;
    if expected != event.total_slices {
        return Err(format!(
            "total_slices {} does not match blob_bytes / slice_bytes ceiling {}",
            event.total_slices, expected
        ));
    }
    Ok(())
}

fn expected_slice_count(blob_bytes: u64, slice_bytes: u64) -> Result<u32, String> {
    if slice_bytes == 0 {
        return Err("slice_bytes must be non-zero".to_string());
    }
    let count = blob_bytes.div_ceil(slice_bytes);
    u32::try_from(count).map_err(|_| "slice count overflows u32".to_string())
}

fn validate_signed_payload(event: &SignedFileEnvelope) -> Result<(), String> {
    let Some(actual_type) = event.payload.first().copied() else {
        return Err("signed file payload is empty".to_string());
    };
    if actual_type != TYPE_FILE {
        return Err("signed file payload is not a file event".to_string());
    }
    metadata(&event.payload).map(|_| ())
}

fn write_signing_fields(out: &mut Writer, event: &SignedFileEnvelope) {
    out.u8(TYPE_SIGNED_FILE);
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
        .map_err(|_| "signed file signature length mismatch".to_string())
}

fn push_unique(out: &mut Vec<EventId>, id: EventId) {
    if !out.iter().any(|candidate| candidate == &id) {
        out.push(id);
    }
}

pub(crate) fn encode_text_slot(
    text: &str,
    capacity: usize,
    label: &str,
) -> Result<Vec<u8>, String> {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if bytes.len() > capacity {
        return Err(format!("{label} is too long"));
    }
    if bytes.contains(&0) {
        return Err(format!("{label} cannot contain NUL"));
    }
    let mut out = vec![0; capacity];
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(out)
}

pub(crate) fn decode_text_slot(bytes: &[u8], label: &str) -> Result<String, String> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if end == 0 {
        return Err(format!("{label} must not be empty"));
    }
    if bytes[end..].iter().any(|byte| *byte != 0) {
        return Err(format!("{label} has non-canonical padding"));
    }
    std::str::from_utf8(&bytes[..end])
        .map_err(|_| format!("{label} is not valid utf-8"))
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> FileEvent {
        FileEvent {
            workspace_id: [1; 32],
            created_at_ms: 99,
            message_id: [2; 32],
            author_user_id: [3; 32],
            file_id: [4; 32],
            blob_bytes: 1024,
            total_slices: 1,
            slice_bytes: 1024,
            root_hash: [5; 32],
            filename: "photo.jpg".to_string(),
            mime_type: "image/jpeg".to_string(),
        }
    }

    #[test]
    fn roundtrips_inner_file_event() {
        let bytes = encode(&event()).expect("encode");
        assert_eq!(bytes.len(), FILE_WIRE_SIZE);
        assert_eq!(decode(&bytes).expect("decode"), event());
    }

    #[test]
    fn rejects_invalid_slice_arithmetic() {
        assert!(encode(&FileEvent {
            blob_bytes: 1024,
            total_slices: 0,
            slice_bytes: 1024,
            ..event()
        })
        .is_err());
        assert!(encode(&FileEvent {
            blob_bytes: 1024,
            total_slices: 1,
            slice_bytes: 0,
            ..event()
        })
        .is_err());
        assert!(encode(&FileEvent {
            blob_bytes: 1024,
            total_slices: 2,
            slice_bytes: 1024,
            ..event()
        })
        .is_err());
    }

    #[test]
    fn signed_envelope_dependencies_are_unique() {
        let payload = encode(&event()).expect("encode");
        let envelope = sign([6; 32], &[7; 32], payload);
        let bytes = encode_signed(&envelope);
        let record = signed_record_from_bytes(bytes).expect("record");
        assert_eq!(record.dependencies, vec![[6; 32], [1; 32], [3; 32], [2; 32]]);
        assert_eq!(record.scope, EventScope::Shared);
    }
}

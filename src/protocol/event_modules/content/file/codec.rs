//! Codec for signed file descriptor events.
//!
//! The descriptor names the file_id (random, fixed 32 bytes), total size, the
//! per-slice byte budget, the parent message it is attached to, and the BAO
//! `root_hash` of the encrypted blob. Filename and mime ride in an
//! authenticated ciphertext slot keyed by the parent message's content key
//! (`(removal_frontier_id, local_history_node_secret_id)`) so canonical bytes never
//! leak the plaintext name or mime type. The slot is fixed-width so wire
//! bytes stay deterministic per event type. Slice events depend on this
//! descriptor's event id and on the same `local_history_node_secret_id`, so AEAD
//! decryption can run at read time without a separate blocking system.

use crate::core::crypto::{
    self, Ed25519PrivateKey, XChaCha20Poly1305Key, XChaCha20Poly1305Nonce,
    ED25519_SIGNATURE_BYTES, XCHACHA20_POLY1305_NONCE_BYTES,
};
use crate::protocol::event_modules::types::{EventId, EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::types::{
    FileDescriptorCiphertext, FileDescriptorPlaintext, FileEvent, SignedFileEnvelope,
    FILE_DESCRIPTOR_CIPHERTEXT_BYTES, FILE_DESCRIPTOR_PLAINTEXT_BYTES, FILE_MIME_BYTES,
    FILE_NAME_BYTES, MAX_FILE_BYTES,
};

pub const TYPE_FILE: u8 = 13;
pub const TYPE_SIGNED_FILE: u8 = 15;
/// Domain-separated AAD prefix for the descriptor's sealed slot.
pub const FILE_DESCRIPTOR_ENCRYPTION_PURPOSE: &[u8] = b"topo file descriptor v2";

/// Inner wire size: tag(1) + workspace(32) + ts(8) + message_id(32) +
/// author(32) + file_id(32) + blob_bytes(8) + total_slices(4) + slice_bytes(4)
/// + root_hash(32) + removal_frontier(32) + local_history_node_secret(32)
/// + nonce + sealed slot.
pub const FILE_WIRE_SIZE: usize = 1
    + 32
    + 8
    + 32
    + 32
    + 32
    + 8
    + 4
    + 4
    + 32
    + 32
    + 32
    + XCHACHA20_POLY1305_NONCE_BYTES
    + FILE_DESCRIPTOR_CIPHERTEXT_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileMetadata {
    workspace_id: EventId,
    created_at_ms: u64,
    message_id: EventId,
    author_user_id: EventId,
    file_id: EventId,
    local_history_node_secret_id: EventId,
}

pub fn encode(event: &FileEvent) -> Result<Vec<u8>, String> {
    validate(event)?;
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
    out.id(&event.removal_frontier_id);
    out.id(&event.local_history_node_secret_id);
    out.raw(&event.nonce);
    out.raw(&event.ciphertext);
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
    let removal_frontier_id = reader.id()?;
    let local_history_node_secret_id = reader.id()?;
    let nonce = fixed_nonce(reader.bytes(XCHACHA20_POLY1305_NONCE_BYTES)?)?;
    let ciphertext = fixed_ciphertext(reader.bytes(FILE_DESCRIPTOR_CIPHERTEXT_BYTES)?)?;
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
        removal_frontier_id,
        local_history_node_secret_id,
        nonce,
        ciphertext,
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
    let mut dependencies = Vec::with_capacity(5);
    push_unique(&mut dependencies, envelope.signer_endpoint_shared_id);
    push_unique(&mut dependencies, metadata.workspace_id);
    push_unique(&mut dependencies, metadata.author_user_id);
    push_unique(&mut dependencies, metadata.message_id);
    push_unique(&mut dependencies, metadata.local_history_node_secret_id);
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
        local_history_node_secret_id: event.local_history_node_secret_id,
    })
}

fn validate(event: &FileEvent) -> Result<(), String> {
    if event.blob_bytes > MAX_FILE_BYTES {
        return Err("file size exceeds the 10 GiB limit".to_string());
    }
    validate_id("file workspace", &event.workspace_id)?;
    validate_id("file message_id", &event.message_id)?;
    validate_id("file author_user_id", &event.author_user_id)?;
    validate_id("file file_id", &event.file_id)?;
    validate_id("file removal_frontier_id", &event.removal_frontier_id)?;
    validate_id("file local_history_node_secret_id", &event.local_history_node_secret_id)?;
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

fn fixed_nonce(bytes: Vec<u8>) -> Result<XChaCha20Poly1305Nonce, String> {
    bytes
        .try_into()
        .map_err(|_| "file descriptor nonce length mismatch".to_string())
}

fn fixed_ciphertext(bytes: Vec<u8>) -> Result<FileDescriptorCiphertext, String> {
    bytes
        .try_into()
        .map_err(|_| "file descriptor ciphertext length mismatch".to_string())
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

/// Domain-separated associated data binding the descriptor's sealed slot to
/// every clear-text field plus the signer endpoint membership. AAD must match
/// at seal and open time; rebinding any of these fields on the wire flips a
/// byte in the AAD and AEAD verification fails.
pub fn descriptor_associated_data(
    event: &FileEvent,
    signer_endpoint_shared_id: EventId,
) -> Vec<u8> {
    let mut out = Writer::with_capacity(
        FILE_DESCRIPTOR_ENCRYPTION_PURPOSE.len()
            + 1
            + 32
            + 8
            + 32
            + 32
            + 32
            + 8
            + 4
            + 4
            + 32
            + 32
            + 32
            + XCHACHA20_POLY1305_NONCE_BYTES
            + 32,
    );
    out.raw(FILE_DESCRIPTOR_ENCRYPTION_PURPOSE);
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
    out.id(&event.removal_frontier_id);
    out.id(&event.local_history_node_secret_id);
    out.raw(&event.nonce);
    out.id(&signer_endpoint_shared_id);
    out.finish()
}

/// Pack `(filename, mime)` into the fixed-width descriptor plaintext slot.
pub fn pack_descriptor_plaintext(
    plaintext: &FileDescriptorPlaintext,
) -> Result<[u8; FILE_DESCRIPTOR_PLAINTEXT_BYTES], String> {
    let filename = encode_text_slot(&plaintext.filename, FILE_NAME_BYTES, "file filename")?;
    let mime = encode_text_slot(&plaintext.mime_type, FILE_MIME_BYTES, "file mime type")?;
    let mut out = [0u8; FILE_DESCRIPTOR_PLAINTEXT_BYTES];
    out[..FILE_NAME_BYTES].copy_from_slice(&filename);
    out[FILE_NAME_BYTES..FILE_NAME_BYTES + FILE_MIME_BYTES].copy_from_slice(&mime);
    Ok(out)
}

/// Unpack a fixed-width descriptor plaintext slot into `(filename, mime)`.
pub fn unpack_descriptor_plaintext(bytes: &[u8]) -> Result<FileDescriptorPlaintext, String> {
    if bytes.len() != FILE_DESCRIPTOR_PLAINTEXT_BYTES {
        return Err("file descriptor plaintext length mismatch".to_string());
    }
    let filename = decode_text_slot(&bytes[..FILE_NAME_BYTES], "file filename")?;
    let mime_type = decode_text_slot(
        &bytes[FILE_NAME_BYTES..FILE_NAME_BYTES + FILE_MIME_BYTES],
        "file mime type",
    )?;
    Ok(FileDescriptorPlaintext {
        filename,
        mime_type,
    })
}

/// Seal the descriptor's sensitive fields (filename, mime) into the
/// fixed-width ciphertext slot using XChaCha20-Poly1305 with the parent
/// message's content key.
pub fn seal_descriptor_slot(
    key: &XChaCha20Poly1305Key,
    nonce: &XChaCha20Poly1305Nonce,
    associated_data: &[u8],
    plaintext: &FileDescriptorPlaintext,
) -> Result<FileDescriptorCiphertext, String> {
    let packed = pack_descriptor_plaintext(plaintext)?;
    let bytes = crypto::xchacha20poly1305_encrypt(key, associated_data, nonce, &packed)?;
    bytes
        .try_into()
        .map_err(|_| "file descriptor ciphertext length mismatch".to_string())
}

/// Reveal the descriptor's sensitive fields from the sealed ciphertext slot.
/// Returns an error if the AEAD tag, AAD, key, or nonce do not match.
pub fn open_descriptor_slot(
    key: &XChaCha20Poly1305Key,
    nonce: &XChaCha20Poly1305Nonce,
    associated_data: &[u8],
    ciphertext: &FileDescriptorCiphertext,
) -> Result<FileDescriptorPlaintext, String> {
    let plaintext = crypto::xchacha20poly1305_decrypt(key, associated_data, nonce, ciphertext)?;
    unpack_descriptor_plaintext(&plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor_plaintext() -> FileDescriptorPlaintext {
        FileDescriptorPlaintext {
            filename: "photo.jpg".to_string(),
            mime_type: "image/jpeg".to_string(),
        }
    }

    fn event() -> FileEvent {
        let key: XChaCha20Poly1305Key = [9; 32];
        let nonce: XChaCha20Poly1305Nonce = [1; XCHACHA20_POLY1305_NONCE_BYTES];
        let mut event = FileEvent {
            workspace_id: [1; 32],
            created_at_ms: 99,
            message_id: [2; 32],
            author_user_id: [3; 32],
            file_id: [4; 32],
            blob_bytes: 1024,
            total_slices: 1,
            slice_bytes: 1024,
            root_hash: [5; 32],
            removal_frontier_id: [6; 32],
            local_history_node_secret_id: [7; 32],
            nonce,
            ciphertext: [0; FILE_DESCRIPTOR_CIPHERTEXT_BYTES],
        };
        let aad = descriptor_associated_data(&event, [8; 32]);
        event.ciphertext = seal_descriptor_slot(&key, &nonce, &aad, &descriptor_plaintext())
            .expect("seal descriptor");
        event
    }

    #[test]
    fn roundtrips_inner_file_event() {
        let bytes = encode(&event()).expect("encode");
        assert_eq!(bytes.len(), FILE_WIRE_SIZE);
        assert_eq!(decode(&bytes).expect("decode"), event());
    }

    #[test]
    fn descriptor_slot_roundtrips_with_matching_key_aad_and_nonce() {
        let key: XChaCha20Poly1305Key = [9; 32];
        let nonce: XChaCha20Poly1305Nonce = [1; XCHACHA20_POLY1305_NONCE_BYTES];
        let event = event();
        let aad = descriptor_associated_data(&event, [8; 32]);
        let recovered =
            open_descriptor_slot(&key, &nonce, &aad, &event.ciphertext).expect("open slot");
        assert_eq!(recovered, descriptor_plaintext());
    }

    #[test]
    fn descriptor_slot_rejects_wrong_key() {
        let nonce: XChaCha20Poly1305Nonce = [1; XCHACHA20_POLY1305_NONCE_BYTES];
        let event = event();
        let aad = descriptor_associated_data(&event, [8; 32]);
        assert!(open_descriptor_slot(&[10; 32], &nonce, &aad, &event.ciphertext).is_err());
    }

    #[test]
    fn descriptor_slot_rejects_wrong_aad_signer_binding() {
        let key: XChaCha20Poly1305Key = [9; 32];
        let nonce: XChaCha20Poly1305Nonce = [1; XCHACHA20_POLY1305_NONCE_BYTES];
        let event = event();
        let aad_other_signer = descriptor_associated_data(&event, [99; 32]);
        assert!(open_descriptor_slot(&key, &nonce, &aad_other_signer, &event.ciphertext).is_err());
    }

    #[test]
    fn descriptor_slot_rejects_ciphertext_tamper() {
        let key: XChaCha20Poly1305Key = [9; 32];
        let nonce: XChaCha20Poly1305Nonce = [1; XCHACHA20_POLY1305_NONCE_BYTES];
        let mut event = event();
        let aad = descriptor_associated_data(&event, [8; 32]);
        event.ciphertext[0] ^= 1;
        assert!(open_descriptor_slot(&key, &nonce, &aad, &event.ciphertext).is_err());
    }

    #[test]
    fn rejects_invalid_slice_arithmetic() {
        let bad_count = FileEvent {
            total_slices: 0,
            ..event()
        };
        assert!(encode(&bad_count).is_err());

        let bad_budget = FileEvent {
            slice_bytes: 0,
            total_slices: 1,
            ..event()
        };
        assert!(encode(&bad_budget).is_err());

        let bad_ceiling = FileEvent {
            blob_bytes: 1024,
            total_slices: 2,
            slice_bytes: 1024,
            ..event()
        };
        assert!(encode(&bad_ceiling).is_err());
    }

    #[test]
    fn signed_envelope_dependencies_include_local_history_node_secret_id() {
        let payload = encode(&event()).expect("encode");
        let envelope = sign([6; 32], &[7; 32], payload);
        let bytes = encode_signed(&envelope);
        let record = signed_record_from_bytes(bytes).expect("record");
        // signer, workspace, author, message_id, local_history_node_secret_id
        assert_eq!(
            record.dependencies,
            vec![[6; 32], [1; 32], [3; 32], [2; 32], [7; 32]]
        );
        assert_eq!(record.scope, EventScope::Shared);
    }

    #[test]
    fn descriptor_canonical_bytes_do_not_carry_filename_or_mime_in_clear() {
        let bytes = encode(&event()).expect("encode");
        assert!(!bytes.windows("photo.jpg".len()).any(|w| w == b"photo.jpg"));
        assert!(!bytes
            .windows("image/jpeg".len())
            .any(|w| w == b"image/jpeg"));
    }
}

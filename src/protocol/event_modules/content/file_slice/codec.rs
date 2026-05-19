//! Codec for signed file slice events.
//!
//! The slice carries a self-contained BAO proof for the per-slice ciphertext
//! bytes that the projector verifies against the descriptor's encrypted-blob
//! `root_hash`. The proof slot is fixed-width with a leading length prefix;
//! the descriptor is named by `file_id` and pulled into the projector's
//! dependency context. The slice event also depends on the file descriptor
//! event id so the worker holds the slice until its descriptor applies, and
//! on the parent message's `local_history_node_secret_id` so AEAD decryption can run
//! at read time without a separate blocking system.
//!
//! Encryption shape: each plaintext slice is encrypted independently with
//! XChaCha20-Poly1305 under the parent message's content key. The per-slice
//! nonce is derived deterministically from
//! `("topo file slice nonce v1", file_id, slice_number)` so the same plaintext
//! yields the same ciphertext on resend; AAD binds the slice to its file_id,
//! slice_number, plaintext length, and signer endpoint membership. The
//! concatenation of all per-slice ciphertexts is the BAO input, so the
//! descriptor's `root_hash` hashes ciphertext, not plaintext.

use crate::core::crypto::{
    self, Ed25519PrivateKey, Hash, XChaCha20Poly1305Key, XChaCha20Poly1305Nonce,
    ED25519_SIGNATURE_BYTES, XCHACHA20_POLY1305_NONCE_BYTES,
};
use crate::protocol::event_modules::types::{EventId, EventRecord, EventScope};
use crate::protocol::wire::Writer;
use crate::protocol::wire_schema::{Field, WireSchema};

use super::types::{BuildSlice, FileSliceEvent, SignedFileSliceEnvelope, FILE_SLICE_PROOF_BYTES};

pub const TYPE_FILE_SLICE: u8 = 16;
pub const TYPE_SIGNED_FILE_SLICE: u8 = 17;
pub const FILE_SLICE_NONCE_PURPOSE: &[u8] = b"topo file slice nonce v1";
pub const FILE_SLICE_ENCRYPTION_PURPOSE: &[u8] = b"topo file slice payload v1";

pub const SCHEMA: WireSchema = WireSchema::new(
    "file_slice",
    TYPE_FILE_SLICE,
    &[
        Field::id("workspace_id"),
        Field::u64("created_at_ms"),
        Field::id("file_id"),
        Field::id("file_event_id"),
        Field::u32("slice_number"),
        Field::id("local_history_node_secret_id"),
        Field::u32("plaintext_len"),
        Field::u32("proof_len"),
        Field::bytes("proof_slot", FILE_SLICE_PROOF_BYTES),
    ],
);

pub const FILE_SLICE_WIRE_SIZE: usize = SCHEMA.wire_size();

pub const SIGNED_SCHEMA: WireSchema = WireSchema::new(
    "signed file_slice",
    TYPE_SIGNED_FILE_SLICE,
    &[
        Field::id("signer_endpoint_shared_id"),
        Field::id("signer_public_key"),
        Field::bytes("payload", FILE_SLICE_WIRE_SIZE),
        Field::bytes("signature", ED25519_SIGNATURE_BYTES),
    ],
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileSliceMetadata {
    workspace_id: EventId,
    created_at_ms: u64,
    file_id: EventId,
    file_event_id: EventId,
    slice_number: u32,
    local_history_node_secret_id: EventId,
    plaintext_len: u32,
}

/// Derive the deterministic per-slice nonce. Combining the static purpose
/// string with `file_id` and `slice_number` ensures every (file, slice) pair
/// has a unique nonce, which is the AEAD invariant the cipher requires.
pub fn derive_slice_nonce(file_id: &EventId, slice_number: u32) -> XChaCha20Poly1305Nonce {
    let mut input = Vec::with_capacity(FILE_SLICE_NONCE_PURPOSE.len() + 1 + file_id.len() + 4);
    input.extend_from_slice(FILE_SLICE_NONCE_PURPOSE);
    input.push(0);
    input.extend_from_slice(file_id);
    input.extend_from_slice(&slice_number.to_be_bytes());
    let hash = crypto::hash(&input);
    let mut nonce = [0u8; XCHACHA20_POLY1305_NONCE_BYTES];
    nonce.copy_from_slice(&hash[..XCHACHA20_POLY1305_NONCE_BYTES]);
    nonce
}

/// Domain-separated AAD binding the slice's ciphertext to file_id,
/// slice_number, plaintext length, and signer endpoint membership. AAD
/// intentionally does NOT include the descriptor's `file_event_id`: that id
/// is fixed by the descriptor's BLAKE3 over canonical bytes, which include
/// `root_hash`, which depends on the ciphertexts we're sealing here. Binding
/// AAD to `file_event_id` would create a chicken-and-egg loop. The
/// dependency edge from slice → descriptor in the slice's canonical bytes
/// already binds the slice to one specific descriptor at projection time.
pub fn slice_associated_data(
    workspace_id: &EventId,
    file_id: &EventId,
    slice_number: u32,
    plaintext_len: u32,
    signer_endpoint_shared_id: &EventId,
) -> Vec<u8> {
    let mut out = Writer::with_capacity(FILE_SLICE_ENCRYPTION_PURPOSE.len() + 32 + 32 + 4 + 4 + 32);
    out.raw(FILE_SLICE_ENCRYPTION_PURPOSE);
    out.id(workspace_id);
    out.id(file_id);
    out.u32(slice_number as usize);
    out.u32(plaintext_len as usize);
    out.id(signer_endpoint_shared_id);
    out.finish()
}

/// Encrypt one plaintext slice into its on-wire ciphertext. The receiver
/// derives the same nonce from `(file_id, slice_number)` and decrypts using
/// the parent message's local key-secret.
pub fn seal_slice(
    key: &XChaCha20Poly1305Key,
    workspace_id: &EventId,
    file_id: &EventId,
    slice_number: u32,
    signer_endpoint_shared_id: &EventId,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let plaintext_len = u32::try_from(plaintext.len())
        .map_err(|_| "file slice plaintext length overflows u32".to_string())?;
    let aad = slice_associated_data(
        workspace_id,
        file_id,
        slice_number,
        plaintext_len,
        signer_endpoint_shared_id,
    );
    let nonce = derive_slice_nonce(file_id, slice_number);
    crypto::xchacha20poly1305_encrypt(key, &aad, &nonce, plaintext)
}

/// Decrypt one BAO-verified slice ciphertext to its plaintext.
pub fn open_slice(
    key: &XChaCha20Poly1305Key,
    workspace_id: &EventId,
    file_id: &EventId,
    slice_number: u32,
    plaintext_len: u32,
    signer_endpoint_shared_id: &EventId,
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let aad = slice_associated_data(
        workspace_id,
        file_id,
        slice_number,
        plaintext_len,
        signer_endpoint_shared_id,
    );
    let nonce = derive_slice_nonce(file_id, slice_number);
    crypto::xchacha20poly1305_decrypt(key, &aad, &nonce, ciphertext)
}

/// Construct a file slice from a descriptor's root hash + outboard.
///
/// The caller has the full encrypted blob and outboard available and uses the
/// descriptor's `slice_bytes` budget to pick the byte range. The result is a
/// `FileSliceEvent` whose proof is self-verifying against the descriptor.
pub fn build_slice(input: BuildSlice<'_>) -> Result<FileSliceEvent, String> {
    let proof = crypto::bao_extract_slice(
        input.ciphertext,
        input.outboard,
        input.slice_start,
        input.slice_len,
    )?;
    Ok(FileSliceEvent {
        workspace_id: input.workspace_id,
        created_at_ms: input.created_at_ms,
        file_id: input.file_id,
        slice_number: input.slice_number,
        local_history_node_secret_id: input.local_history_node_secret_id,
        plaintext_len: input.plaintext_len,
        proof,
    })
}

pub fn verify_slice_proof(
    root_hash: &Hash,
    proof: &[u8],
    slice_start: u64,
    slice_len: u64,
) -> Result<Vec<u8>, String> {
    crypto::bao_verify_slice(root_hash, proof, slice_start, slice_len)
}

pub fn encode(event: &FileSliceEvent, file_event_id: &EventId) -> Result<Vec<u8>, String> {
    if event.proof.len() > FILE_SLICE_PROOF_BYTES {
        return Err("file slice proof exceeds slot capacity".to_string());
    }
    let proof_len = u32::try_from(event.proof.len())
        .map_err(|_| "file slice proof_len overflow".to_string())?;
    let mut slot = vec![0u8; FILE_SLICE_PROOF_BYTES];
    slot[..event.proof.len()].copy_from_slice(&event.proof);
    Ok(SCHEMA
        .encoder()
        .id(&event.workspace_id)
        .u64(event.created_at_ms)
        .id(&event.file_id)
        .id(file_event_id)
        .u32(event.slice_number)
        .id(&event.local_history_node_secret_id)
        .u32(event.plaintext_len)
        .u32(proof_len)
        .bytes(&slot)
        .finish())
}

pub fn decode(bytes: &[u8]) -> Result<(FileSliceEvent, EventId), String> {
    let v = SCHEMA.parse(bytes)?;
    let proof_len = v.u32("proof_len")? as usize;
    if proof_len > FILE_SLICE_PROOF_BYTES {
        return Err("file slice declares more proof than the slot holds".to_string());
    }
    let slot = v.raw("proof_slot")?;
    let proof = slot[..proof_len].to_vec();
    if slot[proof_len..].iter().any(|byte| *byte != 0) {
        return Err("file slice slot has non-canonical padding".to_string());
    }
    Ok((
        FileSliceEvent {
            workspace_id: v.id("workspace_id")?,
            created_at_ms: v.u64("created_at_ms")?,
            file_id: v.id("file_id")?,
            slice_number: v.u32("slice_number")?,
            local_history_node_secret_id: v.id("local_history_node_secret_id")?,
            plaintext_len: v.u32("plaintext_len")?,
            proof,
        },
        v.id("file_event_id")?,
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
    SIGNED_SCHEMA
        .encoder()
        .id(&event.signer_endpoint_shared_id)
        .id(&event.signer_public_key)
        .bytes(&event.payload)
        .bytes(&event.signature)
        .finish()
}

pub fn decode_signed(bytes: &[u8]) -> Result<SignedFileSliceEnvelope, String> {
    let v = SIGNED_SCHEMA.parse(bytes)?;
    let signature = fixed_signature(v.raw("signature")?.to_vec())?;
    let event = SignedFileSliceEnvelope {
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
        return Err("signed file slice signature verification failed".to_string());
    }
    Ok(event)
}

pub fn signing_bytes(event: &SignedFileSliceEnvelope) -> Vec<u8> {
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
    let mut dependencies = Vec::with_capacity(4);
    push_unique(&mut dependencies, envelope.signer_endpoint_shared_id);
    push_unique(&mut dependencies, metadata.workspace_id);
    push_unique(&mut dependencies, metadata.file_event_id);
    push_unique(&mut dependencies, metadata.local_history_node_secret_id);
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
    let (event, file_event_id) = decode(bytes)?;
    Ok(FileSliceMetadata {
        workspace_id: event.workspace_id,
        created_at_ms: event.created_at_ms,
        file_id: event.file_id,
        file_event_id,
        slice_number: event.slice_number,
        local_history_node_secret_id: event.local_history_node_secret_id,
        plaintext_len: event.plaintext_len,
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
    use crate::core::crypto::XCHACHA20_POLY1305_TAG_BYTES;

    use super::super::types::{FILE_SLICE_CIPHERTEXT_BYTES, FILE_SLICE_DATA_BYTES};
    use super::*;

    fn slice_event(_file_event_id: &EventId) -> (FileSliceEvent, [u8; 32]) {
        let plaintext: Vec<u8> = (0..FILE_SLICE_DATA_BYTES as u32)
            .map(|byte| byte as u8)
            .collect();
        let key: XChaCha20Poly1305Key = [42; 32];
        let workspace_id: EventId = [1; 32];
        let file_id: EventId = [2; 32];
        let signer: EventId = [3; 32];
        let ciphertext =
            seal_slice(&key, &workspace_id, &file_id, 0, &signer, &plaintext).expect("seal slice");
        let (root_hash, outboard) = crypto::bao_outboard(&ciphertext).expect("outboard");
        let event = build_slice(BuildSlice {
            workspace_id,
            created_at_ms: 11,
            file_id,
            slice_number: 0,
            local_history_node_secret_id: [4; 32],
            plaintext_len: plaintext.len() as u32,
            ciphertext: &ciphertext,
            outboard: &outboard,
            slice_start: 0,
            slice_len: ciphertext.len() as u64,
        })
        .expect("build slice");
        (event, root_hash)
    }

    /// Invariant: a multi-slice encrypted file stream keeps every full slice
    /// on the fixed ciphertext boundary, so each BAO proof fits the canonical
    /// file-slice proof slot and verifies back to the expected ciphertext.
    #[test]
    fn proof_slot_budget_covers_multislice_encrypted_streams() {
        let key: XChaCha20Poly1305Key = [77; 32];
        let workspace_id: EventId = [1; 32];
        let file_id: EventId = [2; 32];
        let signer: EventId = [3; 32];
        let local_history_node_secret_id: EventId = [4; 32];
        let plaintext_total_len = FILE_SLICE_DATA_BYTES * 4 + 123;
        let plaintext: Vec<u8> = (0..plaintext_total_len)
            .map(|idx| (idx as u8).wrapping_mul(31).rotate_left((idx % 7) as u32))
            .collect();
        let total_slices = plaintext.len().div_ceil(FILE_SLICE_DATA_BYTES);

        let mut ciphertext_total =
            Vec::with_capacity(plaintext.len() + total_slices * XCHACHA20_POLY1305_TAG_BYTES);
        for slice_number in 0..total_slices {
            let start = slice_number * FILE_SLICE_DATA_BYTES;
            let end = (start + FILE_SLICE_DATA_BYTES).min(plaintext.len());
            let ciphertext = seal_slice(
                &key,
                &workspace_id,
                &file_id,
                slice_number as u32,
                &signer,
                &plaintext[start..end],
            )
            .expect("seal slice");
            if slice_number + 1 < total_slices {
                assert_eq!(ciphertext.len(), FILE_SLICE_CIPHERTEXT_BYTES);
            }
            ciphertext_total.extend_from_slice(&ciphertext);
        }
        let (root_hash, outboard) = crypto::bao_outboard(&ciphertext_total).expect("outboard");

        for slice_number in 0..total_slices {
            let plaintext_start = slice_number * FILE_SLICE_DATA_BYTES;
            let plaintext_len = (plaintext.len() - plaintext_start).min(FILE_SLICE_DATA_BYTES);
            let slice_start = slice_number as u64 * FILE_SLICE_CIPHERTEXT_BYTES as u64;
            let slice_len = plaintext_len as u64 + XCHACHA20_POLY1305_TAG_BYTES as u64;
            let event = build_slice(BuildSlice {
                workspace_id,
                created_at_ms: 11 + slice_number as u64,
                file_id,
                slice_number: slice_number as u32,
                local_history_node_secret_id,
                plaintext_len: plaintext_len as u32,
                ciphertext: &ciphertext_total,
                outboard: &outboard,
                slice_start,
                slice_len,
            })
            .expect("build slice");
            // Invariant: every full encrypted slice is aligned at 256 KiB, so
            // its self-contained BAO proof fits the fixed canonical slot.
            assert!(event.proof.len() <= FILE_SLICE_PROOF_BYTES);
            encode(&event, &[9; 32]).expect("proof fits file slice slot");

            let verified = verify_slice_proof(&root_hash, &event.proof, slice_start, slice_len)
                .expect("verify slice proof");
            let expected_start = slice_start as usize;
            let expected_end = expected_start + slice_len as usize;
            assert_eq!(verified, ciphertext_total[expected_start..expected_end]);
        }
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
            local_history_node_secret_id: [4; 32],
            plaintext_len: 0,
            proof: vec![0; FILE_SLICE_PROOF_BYTES + 1],
        };
        assert!(encode(&event, &[3; 32]).is_err());
    }

    #[test]
    fn signed_envelope_dependencies_include_local_history_node_secret_id() {
        let file_event_id = [9; 32];
        let (event, _) = slice_event(&file_event_id);
        let payload = encode(&event, &file_event_id).expect("encode");
        let envelope = sign([5; 32], &[6; 32], payload);
        let bytes = encode_signed(&envelope);
        let record = signed_record_from_bytes(bytes).expect("record");
        // signer, workspace, file_event_id, local_history_node_secret_id
        assert_eq!(
            record.dependencies,
            vec![[5; 32], [1; 32], file_event_id, [4; 32]]
        );
        assert_eq!(record.scope, EventScope::Shared);
    }

    #[test]
    fn slice_seal_open_roundtrips_and_rejects_wrong_key_aad_or_nonce() {
        let key: XChaCha20Poly1305Key = [11; 32];
        let workspace_id: EventId = [1; 32];
        let file_id: EventId = [2; 32];
        let signer: EventId = [4; 32];
        let plaintext = b"the quick brown fox jumps over the lazy dog".to_vec();
        let ciphertext =
            seal_slice(&key, &workspace_id, &file_id, 7, &signer, &plaintext).expect("seal");
        let recovered = open_slice(
            &key,
            &workspace_id,
            &file_id,
            7,
            plaintext.len() as u32,
            &signer,
            &ciphertext,
        )
        .expect("open");
        assert_eq!(recovered, plaintext);

        // Wrong key.
        assert!(open_slice(
            &[99; 32],
            &workspace_id,
            &file_id,
            7,
            plaintext.len() as u32,
            &signer,
            &ciphertext,
        )
        .is_err());

        // AAD mismatch on signer.
        assert!(open_slice(
            &key,
            &workspace_id,
            &file_id,
            7,
            plaintext.len() as u32,
            &[88; 32],
            &ciphertext,
        )
        .is_err());

        // Nonce mismatch via slice_number drift.
        assert!(open_slice(
            &key,
            &workspace_id,
            &file_id,
            8,
            plaintext.len() as u32,
            &signer,
            &ciphertext,
        )
        .is_err());
    }

    #[test]
    fn derived_nonces_are_unique_per_slice_number_for_one_file() {
        let file_id: EventId = [42; 32];
        let nonce0 = derive_slice_nonce(&file_id, 0);
        let nonce1 = derive_slice_nonce(&file_id, 1);
        let nonce_other_file = derive_slice_nonce(&[43; 32], 0);
        assert_ne!(nonce0, nonce1);
        assert_ne!(nonce0, nonce_other_file);
    }
}

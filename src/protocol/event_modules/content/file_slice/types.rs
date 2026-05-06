//! File slice event types.
//!
//! A file slice carries one BAO-verified chunk of a larger file. The encrypted
//! blob — the concatenation of per-slice XChaCha20-Poly1305 ciphertexts — is
//! the byte stream BAO is computed over, so each slice's self-contained proof
//! verifies the slice's ciphertext bytes against the descriptor's
//! `root_hash`. Verified ciphertext is stored in the slice row; the read path
//! decrypts each slice using the local key-secret resolved from the
//! descriptor's `local_key_secret_id` to recover plaintext. The slice's
//! per-slice nonce is derived deterministically from
//! `(file_id, slice_number)` so the AEAD construction is reproducible across
//! sender, receiver, and replay. The on-wire `proof` field is fixed-width so
//! canonical bytes stay deterministic per event type; the actual proof length
//! is carried as a leading prefix and the trailing slot is zero-padded.

use crate::core::crypto::{
    Ed25519PublicKey, Ed25519Signature, XCHACHA20_POLY1305_TAG_BYTES,
};
use crate::protocol::event_modules::types::EventId;

/// Plaintext budget per slice. Slices may be shorter at the file tail.
pub const FILE_SLICE_DATA_BYTES: usize = 256 * 1024;

/// Ciphertext budget per slice: per-slice plaintext budget + AEAD tag.
pub const FILE_SLICE_CIPHERTEXT_BYTES: usize =
    FILE_SLICE_DATA_BYTES + XCHACHA20_POLY1305_TAG_BYTES;

/// BAO encoding overhead budget. The slice proof = ciphertext + tree nodes
/// embedded at the front of the BAO encoding. The slot is fixed so canonical
/// bytes stay deterministic.
///
/// poc-8 computes BAO over the ciphertext stream and slices it on
/// `FILE_SLICE_DATA_BYTES + AEAD tag` boundaries. The tag offset breaks
/// alignment with BAO's 1 KiB chunk boundaries, which in turn forces every
/// non-tail slice's proof to span an extra chunk. Empirically the worst-case
/// proof size for a 256 KiB+tag slice in a 10 GiB file is ~281 KiB, so the
/// slop has to comfortably exceed `FILE_SLICE_DATA_BYTES + tag` plus the
/// extra-chunk overhead. 25 KiB clears every measured proof for files up to
/// `MAX_FILE_BYTES` with margin to spare. Reducing the budget below this
/// fails any multi-slice send with `"file slice proof exceeds slot capacity"`.
pub const FILE_SLICE_PROOF_BYTES: usize = FILE_SLICE_CIPHERTEXT_BYTES + 25 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSliceEvent {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub file_id: EventId,
    pub slice_number: u32,
    pub local_key_secret_id: EventId,
    /// Plaintext byte length of this slice. Ciphertext length is
    /// `plaintext_len + AEAD tag`, and the BAO proof verifies that range
    /// inside the encrypted blob.
    pub plaintext_len: u32,
    /// BAO slice proof for the ciphertext bytes that decrypt to this slice's
    /// plaintext.
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedFileSliceEnvelope {
    pub signer_endpoint_shared_id: EventId,
    pub signer_public_key: Ed25519PublicKey,
    pub payload: Vec<u8>,
    pub signature: Ed25519Signature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildSlice<'a> {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub file_id: EventId,
    pub slice_number: u32,
    pub local_key_secret_id: EventId,
    pub plaintext_len: u32,
    pub ciphertext: &'a [u8],
    pub outboard: &'a [u8],
    pub slice_start: u64,
    pub slice_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSliceRow {
    pub workspace_id: EventId,
    pub file_id: EventId,
    pub slice_number: u32,
    pub slice_event_id: EventId,
    pub created_at_ms: u64,
    pub signer_endpoint_shared_id: EventId,
    pub local_key_secret_id: EventId,
    pub plaintext_len: u32,
    /// BAO-verified ciphertext bytes for this slice. Stored only after the
    /// slice's proof checked against the descriptor's root hash; the read
    /// path decrypts using the local key-secret named by
    /// `local_key_secret_id`.
    pub ciphertext: Vec<u8>,
}

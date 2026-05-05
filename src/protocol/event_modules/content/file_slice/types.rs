//! File slice event types.
//!
//! A file slice carries one BAO-verified chunk of a larger file plus a
//! self-contained slice proof. Verification runs against the descriptor's
//! `root_hash`, so any one slice can be projected as soon as both the slice
//! and the descriptor are present, in any order. The on-wire `proof` field is
//! fixed-width so canonical bytes stay deterministic per event type; the
//! actual proof length is carried as a leading prefix and the trailing slot
//! is zero-padded.

use crate::core::crypto::{Ed25519PublicKey, Ed25519Signature};
use crate::protocol::event_modules::types::EventId;

/// Plaintext budget per slice. Slices may be shorter at the file tail.
pub const FILE_SLICE_DATA_BYTES: usize = 256 * 1024;

/// BAO encoding overhead budget. The slice proof = plaintext + tree nodes
/// embedded at the front of the BAO encoding. Real BAO proofs for this
/// chunk size land well under this budget; the slot is fixed so canonical
/// bytes stay deterministic.
pub const FILE_SLICE_PROOF_BYTES: usize = FILE_SLICE_DATA_BYTES + 17 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSliceEvent {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub file_id: EventId,
    pub slice_number: u32,
    /// BAO slice proof for `[slice_number * slice_bytes .. + slice_len)`.
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
    pub plaintext: &'a [u8],
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
    /// Verified plaintext. Stored only after the slice's BAO proof checked
    /// against the descriptor's root hash.
    pub data: Vec<u8>,
}

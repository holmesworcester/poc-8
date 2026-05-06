//! File descriptor event types.
//!
//! A file descriptor is a workspace-scoped, message-attached metadata event
//! that names a file: its random `file_id`, total byte size, slice count,
//! per-slice byte budget, BAO root hash, filename, and mime type. The actual
//! bytes live in sibling `file_slice` events. Slices carry self-contained BAO
//! proofs that are verified against the descriptor's `root_hash`, so progress
//! and assembly are simple counts and concatenation against a single stable
//! hash.

use crate::core::crypto::{Ed25519PublicKey, Ed25519Signature, Hash};
use crate::protocol::event_modules::types::EventId;

pub const FILE_NAME_BYTES: usize = 255;
pub const FILE_MIME_BYTES: usize = 128;

/// Hard cap on the number of bytes one file can carry.
///
/// poc-8 is the same 10 GiB upper bound as poc-7. Tests size well below this;
/// the limit only protects projection/validation against absurd inputs.
pub const MAX_FILE_BYTES: u64 = 10 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEvent {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub message_id: EventId,
    pub author_user_id: EventId,
    pub file_id: EventId,
    pub blob_bytes: u64,
    pub total_slices: u32,
    pub slice_bytes: u32,
    pub root_hash: Hash,
    pub filename: String,
    pub mime_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedFileEnvelope {
    pub signer_endpoint_shared_id: EventId,
    pub signer_public_key: Ed25519PublicKey,
    pub payload: Vec<u8>,
    pub signature: Ed25519Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRow {
    pub workspace_id: EventId,
    pub file_event_id: EventId,
    pub message_id: EventId,
    pub file_id: EventId,
    pub author_user_id: EventId,
    pub signer_endpoint_shared_id: EventId,
    pub created_at_ms: u64,
    pub blob_bytes: u64,
    pub total_slices: u32,
    pub slice_bytes: u32,
    pub root_hash: Hash,
    pub filename: String,
    pub mime_type: String,
}

impl FileRow {
    /// Format the user-facing summary used by `messages` and `files` listings.
    pub fn summary(&self) -> String {
        format!(
            "{filename} ({size} bytes, {mime}, {slices} slices, id={file})",
            filename = self.filename,
            size = self.blob_bytes,
            mime = self.mime_type,
            slices = self.total_slices,
            file = super::super::message::cli::hex_id(self.file_event_id)
        )
    }
}

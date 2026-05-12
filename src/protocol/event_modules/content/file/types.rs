//! File descriptor event types.
//!
//! A file descriptor is a workspace-scoped, message-attached metadata event
//! that names a file. The descriptor binds the file to its parent message and
//! carries the byte length, slice count, per-slice byte budget, and the
//! BAO root hash of the encrypted blob — all of which sync through the
//! ordinary event pipeline. Sensitive descriptor fields — `filename` and
//! `mime` — live inside an authenticated ciphertext slot sealed under the
//! file's **own** per-event leaf key, so canonical bytes never leak the
//! plaintext name. The actual file bytes live in sibling `file_slice`
//! events whose BAO proofs verify against the encrypted blob's root hash.
//!
//! Each file authors its own leaf chain under the per-minute coarse cover.
//! The leaf coordinate is deterministic from the file's identifying
//! canonical fields so two clients who independently author the same file
//! land on the same leaf and admission collapses the duplicate. Deleting a
//! file retires its own leaf without disturbing the parent message's leaf.
//!
//! `FileEvent` is the canonical wire shape. `SealedFileRow` is the
//! post-projection shape exposed to read queries; the read-side CLI opens
//! the sealed slot using the file's own leaf node secret resolved from
//! `local_history_node_secret_id` to display the filename and mime.
//! `FileRow` is the plaintext shape returned by the read path after that
//! AEAD opening.

use crate::core::crypto::{
    self, Ed25519PublicKey, Ed25519Signature, Hash, XChaCha20Poly1305Nonce,
    XCHACHA20_POLY1305_TAG_BYTES,
};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::Writer;

pub const FILE_NAME_BYTES: usize = 255;
pub const FILE_MIME_BYTES: usize = 128;

/// Plaintext for the descriptor's sealed slot: filename slot + mime slot.
/// Fixed-width so canonical bytes stay deterministic per event type.
pub const FILE_DESCRIPTOR_PLAINTEXT_BYTES: usize = FILE_NAME_BYTES + FILE_MIME_BYTES;
pub const FILE_DESCRIPTOR_CIPHERTEXT_BYTES: usize =
    FILE_DESCRIPTOR_PLAINTEXT_BYTES + XCHACHA20_POLY1305_TAG_BYTES;
pub type FileDescriptorCiphertext = [u8; FILE_DESCRIPTOR_CIPHERTEXT_BYTES];

/// Hard cap on the number of bytes one file can carry.
///
/// poc-8 is the same 10 GiB upper bound as poc-7. Tests size well below this;
/// the limit only protects projection/validation against absurd inputs.
pub const MAX_FILE_BYTES: u64 = 10 * 1024 * 1024 * 1024;

/// Domain-separation tag for the file leaf-coord derivation.
pub const FILE_LEAF_COORD_DOMAIN: &[u8] = b"topo file leaf coord v1";

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
    pub removal_frontier_id: EventId,
    /// Names the file's **own** leaf event. Slices and the descriptor's
    /// sealed filename/mime slot are sealed under this leaf's `node_secret`.
    pub local_history_node_secret_id: EventId,
    pub nonce: XChaCha20Poly1305Nonce,
    pub ciphertext: FileDescriptorCiphertext,
}

impl FileEvent {
    /// Re-derive the file's leaf coordinate from canonical fields. Two
    /// clients independently authoring the same file (same workspace,
    /// author, parent message, file_id, frontier, timestamp) land on the
    /// same leaf coord by BLAKE3-keyed-hash determinism.
    pub fn event_id_in_minute_derived(&self) -> EventId {
        file_event_id_in_minute(
            &self.workspace_id,
            &self.author_user_id,
            &self.message_id,
            &self.file_id,
            &self.removal_frontier_id,
            self.created_at_ms,
        )
    }
}

/// Deterministic leaf coordinate for a file descriptor.
pub fn file_event_id_in_minute(
    workspace_id: &EventId,
    author_user_id: &EventId,
    message_id: &EventId,
    file_id: &EventId,
    removal_frontier_id: &EventId,
    created_at_ms: u64,
) -> EventId {
    let mut info = Writer::with_capacity(32 + 32 + 32 + 32 + 32 + 8);
    info.id(workspace_id);
    info.id(author_user_id);
    info.id(message_id);
    info.id(file_id);
    info.id(removal_frontier_id);
    info.u64(created_at_ms);
    let info_bytes = info.finish();
    crypto::blake3_keyed_hash(workspace_id, FILE_LEAF_COORD_DOMAIN, &info_bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDescriptorPlaintext {
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

/// Sealed projection row carrying everything needed to render a file listing
/// after the file's leaf has been resolved at read time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedFileRow {
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
    pub removal_frontier_id: EventId,
    pub local_history_node_secret_id: EventId,
    pub nonce: XChaCha20Poly1305Nonce,
    pub ciphertext: FileDescriptorCiphertext,
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
    pub removal_frontier_id: EventId,
    pub local_history_node_secret_id: EventId,
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

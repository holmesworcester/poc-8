//! File deletion event types.
//!
//! A deletion is a workspace-scoped, signer-bound declaration that the named
//! `author_user_id` wants the file event identified by `target_file_event_id`
//! removed. Deletion is expressed as a generic event label attached to the
//! target file event id, not as a separate tombstone row table. The label
//! payload encodes the deletion author so the file projector — and the
//! content purge worker that follows up — can authorize the purge against
//! the file's own `author_user_id`.

use crate::core::crypto::{Ed25519PublicKey, Ed25519Signature};
use crate::protocol::event_modules::types::EventId;

/// Label prefix written under the target file event id by the deletion
/// projector.
///
/// The full label is `DELETED_LABEL_PREFIX || author_user_id` (16 + 32 = 48
/// bytes). The content-purge worker treats the label as authoritative iff
/// the trailing 32 bytes equal the file's own `author_user_id`.
pub const DELETED_LABEL_PREFIX: &[u8; 16] = b"content.fdelete:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDeletionEvent {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub target_file_event_id: EventId,
    pub author_user_id: EventId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedFileDeletionEnvelope {
    pub signer_endpoint_shared_id: EventId,
    pub signer_public_key: Ed25519PublicKey,
    pub payload: Vec<u8>,
    pub signature: Ed25519Signature,
}

/// Build the file deletion label bytes for the given author.
pub fn deletion_label(author_user_id: &EventId) -> Vec<u8> {
    let mut label = Vec::with_capacity(DELETED_LABEL_PREFIX.len() + author_user_id.len());
    label.extend_from_slice(DELETED_LABEL_PREFIX);
    label.extend_from_slice(author_user_id);
    label
}

/// Extract the author from a file deletion label, returning `None` if the
/// bytes are not a file deletion label.
pub fn deletion_label_author(label: &[u8]) -> Option<EventId> {
    if label.len() != DELETED_LABEL_PREFIX.len() + 32 {
        return None;
    }
    if &label[..DELETED_LABEL_PREFIX.len()] != DELETED_LABEL_PREFIX {
        return None;
    }
    let mut author = [0; 32];
    author.copy_from_slice(&label[DELETED_LABEL_PREFIX.len()..]);
    Some(author)
}

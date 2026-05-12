//! Content domain.
//!
//! Content events are signed workspace-scoped payload events. Each leaf module
//! owns its own outer signed-envelope tag plus an inner content tag, and
//! projection enforces the shared-event auth rule: signers must be endpoint
//! memberships in the workspace.

pub mod cli;
pub mod content_event;
pub mod file;
pub mod file_deletion;
pub mod file_slice;
pub mod message;
pub mod message_deletion;
pub mod reaction;

use crate::core::store::Store;
use crate::protocol::event_modules::types::EventRecord;
use crate::protocol::event_modules::worker::{AdmitDecision, EventWithContext, ProjectionOutput};

pub fn project_record(event: &EventWithContext<'_>) -> Result<Option<ProjectionOutput>, String> {
    let bytes = &event.record.canonical_bytes;
    match bytes.first().copied() {
        Some(content_event::codec::TYPE_SIGNED_CONTENT) => {
            Ok(Some(content_event::projector::project(event)?))
        }
        Some(message::codec::TYPE_SIGNED_MESSAGE) => Ok(Some(message::projector::project(event)?)),
        Some(reaction::codec::TYPE_SIGNED_REACTION) => {
            Ok(Some(reaction::projector::project(event)?))
        }
        Some(message_deletion::codec::TYPE_SIGNED_MESSAGE_DELETION) => {
            Ok(Some(message_deletion::projector::project(event)?))
        }
        Some(file::codec::TYPE_SIGNED_FILE) => Ok(Some(file::projector::project(event)?)),
        Some(file_slice::codec::TYPE_SIGNED_FILE_SLICE) => {
            Ok(Some(file_slice::projector::project(event)?))
        }
        Some(file_deletion::codec::TYPE_SIGNED_FILE_DELETION) => {
            Ok(Some(file_deletion::projector::project(event)?))
        }
        _ => Ok(None),
    }
}

/// Receive-side admission gate for content events. Dispatches by tag to the
/// leaf module's projector-owned `admit_check_received`, which decides
/// whether to admit, drop silently, or drop with a tombstone-row write.
/// The projector is the right home for the gate: it sits alongside the
/// pure `project()` transform and owns both per-event validation paths.
pub fn admit_check_received(
    store: &Store,
    record: &EventRecord,
) -> Result<AdmitDecision, String> {
    let bytes = &record.canonical_bytes;
    match bytes.first().copied() {
        Some(message::codec::TYPE_SIGNED_MESSAGE) => {
            message::projector::admit_check_received(store, bytes)
        }
        Some(reaction::codec::TYPE_SIGNED_REACTION) => {
            reaction::projector::admit_check_received(store, bytes)
        }
        Some(file::codec::TYPE_SIGNED_FILE) => file::projector::admit_check_received(store, bytes),
        Some(file_slice::codec::TYPE_SIGNED_FILE_SLICE) => {
            file_slice::projector::admit_check_received(store, bytes)
        }
        _ => Ok(AdmitDecision::Admit),
    }
}

/// Tags owned by this domain. Used by the top-level dispatcher to route
/// ordinary tag-leading event bytes to `event_from_bytes`.
pub fn is_content_tag(tag: u8) -> bool {
    matches!(
        tag,
        content_event::codec::TYPE_CONTENT
            | content_event::codec::TYPE_SIGNED_CONTENT
            | message::codec::TYPE_MESSAGE
            | message::codec::TYPE_SIGNED_MESSAGE
            | reaction::codec::TYPE_REACTION
            | reaction::codec::TYPE_SIGNED_REACTION
            | message_deletion::codec::TYPE_MESSAGE_DELETION
            | message_deletion::codec::TYPE_SIGNED_MESSAGE_DELETION
            | file::codec::TYPE_FILE
            | file::codec::TYPE_SIGNED_FILE
            | file_slice::codec::TYPE_FILE_SLICE
            | file_slice::codec::TYPE_SIGNED_FILE_SLICE
            | file_deletion::codec::TYPE_FILE_DELETION
            | file_deletion::codec::TYPE_SIGNED_FILE_DELETION
    )
}

/// Decode a tag-leading content event into an `EventRecord`. Unsigned
/// content tags are rejected: every content event must arrive in its signed
/// envelope form.
pub fn event_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let tag = bytes
        .first()
        .ok_or_else(|| "empty content event bytes".to_string())?;
    match *tag {
        content_event::codec::TYPE_CONTENT => Err("content must be signed".to_string()),
        content_event::codec::TYPE_SIGNED_CONTENT => {
            content_event::codec::signed_record_from_bytes(bytes)
        }
        message::codec::TYPE_MESSAGE => Err("message must be signed".to_string()),
        message::codec::TYPE_SIGNED_MESSAGE => message::codec::signed_record_from_bytes(bytes),
        reaction::codec::TYPE_REACTION => Err("reaction must be signed".to_string()),
        reaction::codec::TYPE_SIGNED_REACTION => reaction::codec::signed_record_from_bytes(bytes),
        message_deletion::codec::TYPE_MESSAGE_DELETION => {
            Err("message deletion must be signed".to_string())
        }
        message_deletion::codec::TYPE_SIGNED_MESSAGE_DELETION => {
            message_deletion::codec::signed_record_from_bytes(bytes)
        }
        file::codec::TYPE_FILE => Err("file must be signed".to_string()),
        file::codec::TYPE_SIGNED_FILE => file::codec::signed_record_from_bytes(bytes),
        file_slice::codec::TYPE_FILE_SLICE => Err("file slice must be signed".to_string()),
        file_slice::codec::TYPE_SIGNED_FILE_SLICE => {
            file_slice::codec::signed_record_from_bytes(bytes)
        }
        file_deletion::codec::TYPE_FILE_DELETION => Err("file deletion must be signed".to_string()),
        file_deletion::codec::TYPE_SIGNED_FILE_DELETION => {
            file_deletion::codec::signed_record_from_bytes(bytes)
        }
        other => Err(format!("unknown content event type {other}")),
    }
}

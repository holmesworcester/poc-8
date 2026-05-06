//! Encryption domain.
//!
//! This domain owns content-key availability facts and local key material. The
//! module root stays as registry plumbing: child modules own their event syntax,
//! commands, projection rows, and tests.

pub mod local_recipient_key;
pub mod recipient_key;

use crate::protocol::event_modules::types::EventRecord;
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

pub fn project_record(event: &EventWithContext<'_>) -> Result<Option<ProjectionOutput>, String> {
    let bytes = &event.record.canonical_bytes;
    match bytes.first().copied() {
        Some(local_recipient_key::codec::TYPE_LOCAL_RECIPIENT_KEY) => {
            Ok(Some(local_recipient_key::projector::project(bytes)?))
        }
        Some(recipient_key::codec::TYPE_SIGNED_RECIPIENT_KEY) => {
            Ok(Some(recipient_key::projector::project(event)?))
        }
        _ => Ok(None),
    }
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let tag = bytes
        .first()
        .ok_or_else(|| "empty encryption event bytes".to_string())?;
    match *tag {
        local_recipient_key::codec::TYPE_LOCAL_RECIPIENT_KEY => {
            local_recipient_key::codec::record_from_bytes(bytes)
        }
        recipient_key::codec::TYPE_SIGNED_RECIPIENT_KEY => {
            recipient_key::codec::signed_record_from_bytes(bytes)
        }
        other => Err(format!("unknown encryption event type {other}")),
    }
}

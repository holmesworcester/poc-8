//! Encryption domain.
//!
//! This domain owns content-key availability facts and local key material. The
//! module root stays as registry plumbing: child modules own their event syntax,
//! commands, projection rows, and tests.

pub mod cli;
pub mod key_wrap;
pub mod local_history_node_secret;
pub mod local_key_secret;
pub mod local_recipient_key;
pub mod recipient_key;
pub mod recipient_key_tombstone;
pub mod removal_frontier;
pub use crate::workers::encryption as worker;

use crate::protocol::event_modules::types::EventRecord;
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

pub fn project_record(event: &EventWithContext<'_>) -> Result<Option<ProjectionOutput>, String> {
    let bytes = &event.record.canonical_bytes;
    match bytes.first().copied() {
        Some(local_recipient_key::codec::TYPE_LOCAL_RECIPIENT_KEY) => {
            Ok(Some(local_recipient_key::projector::project(bytes)?))
        }
        Some(local_key_secret::codec::TYPE_LOCAL_KEY_SECRET) => {
            Ok(Some(local_key_secret::projector::project(event)?))
        }
        Some(local_history_node_secret::codec::TYPE_LOCAL_HISTORY_NODE_SECRET) => {
            Ok(Some(local_history_node_secret::projector::project(event)?))
        }
        Some(recipient_key::codec::TYPE_SIGNED_RECIPIENT_KEY) => {
            Ok(Some(recipient_key::projector::project(event)?))
        }
        Some(recipient_key_tombstone::codec::TYPE_SIGNED_RECIPIENT_KEY_TOMBSTONE) => {
            Ok(Some(recipient_key_tombstone::projector::project(event)?))
        }
        Some(removal_frontier::codec::TYPE_SIGNED_REMOVAL_FRONTIER) => {
            Ok(Some(removal_frontier::projector::project(event)?))
        }
        Some(key_wrap::codec::TYPE_SIGNED_KEY_WRAP) => {
            Ok(Some(key_wrap::projector::project(event)?))
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
        local_key_secret::codec::TYPE_LOCAL_KEY_SECRET => {
            local_key_secret::codec::record_from_bytes(bytes)
        }
        local_history_node_secret::codec::TYPE_LOCAL_HISTORY_NODE_SECRET => {
            local_history_node_secret::codec::record_from_bytes(bytes)
        }
        recipient_key::codec::TYPE_SIGNED_RECIPIENT_KEY => {
            recipient_key::codec::signed_record_from_bytes(bytes)
        }
        recipient_key_tombstone::codec::TYPE_SIGNED_RECIPIENT_KEY_TOMBSTONE => {
            recipient_key_tombstone::codec::signed_record_from_bytes(bytes)
        }
        removal_frontier::codec::TYPE_SIGNED_REMOVAL_FRONTIER => {
            removal_frontier::codec::signed_record_from_bytes(bytes)
        }
        key_wrap::codec::TYPE_SIGNED_KEY_WRAP => key_wrap::codec::signed_record_from_bytes(bytes),
        other => Err(format!("unknown encryption event type {other}")),
    }
}

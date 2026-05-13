//! Encryption domain.
//!
//! This domain owns content-key availability facts and local key material. The
//! module root stays as registry plumbing: child modules own their event syntax,
//! commands, projection rows, and tests.

pub mod cli;
pub mod disappearing_messages_setting;
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
        Some(disappearing_messages_setting::codec::TYPE_SIGNED_DISAPPEARING_MESSAGES_SETTING) => {
            Ok(Some(disappearing_messages_setting::projector::project(event)?))
        }
        _ => Ok(None),
    }
}

/// Tags owned by this domain. Used by the top-level dispatcher to route
/// ordinary tag-leading event bytes to `event_from_bytes`.
pub fn is_encryption_tag(tag: u8) -> bool {
    matches!(
        tag,
        local_recipient_key::codec::TYPE_LOCAL_RECIPIENT_KEY
            | local_key_secret::codec::TYPE_LOCAL_KEY_SECRET
            | local_history_node_secret::codec::TYPE_LOCAL_HISTORY_NODE_SECRET
            | recipient_key::codec::TYPE_RECIPIENT_KEY
            | recipient_key::codec::TYPE_SIGNED_RECIPIENT_KEY
            | recipient_key_tombstone::codec::TYPE_RECIPIENT_KEY_TOMBSTONE
            | recipient_key_tombstone::codec::TYPE_SIGNED_RECIPIENT_KEY_TOMBSTONE
            | removal_frontier::codec::TYPE_REMOVAL_FRONTIER
            | removal_frontier::codec::TYPE_SIGNED_REMOVAL_FRONTIER
            | key_wrap::codec::TYPE_KEY_WRAP
            | key_wrap::codec::TYPE_SIGNED_KEY_WRAP
            | disappearing_messages_setting::codec::TYPE_DISAPPEARING_MESSAGES_SETTING
            | disappearing_messages_setting::codec::TYPE_SIGNED_DISAPPEARING_MESSAGES_SETTING
    )
}

/// Decode a tag-leading encryption event into an `EventRecord`. Unsigned
/// outer tags (recipient_key, key_wrap, etc.) are rejected at this layer:
/// they must arrive in their signed envelope form.
pub fn event_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
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
        recipient_key::codec::TYPE_RECIPIENT_KEY => Err("recipient_key must be signed".to_string()),
        recipient_key::codec::TYPE_SIGNED_RECIPIENT_KEY => {
            recipient_key::codec::signed_record_from_bytes(bytes)
        }
        recipient_key_tombstone::codec::TYPE_RECIPIENT_KEY_TOMBSTONE => {
            Err("recipient_key_tombstone must be signed".to_string())
        }
        recipient_key_tombstone::codec::TYPE_SIGNED_RECIPIENT_KEY_TOMBSTONE => {
            recipient_key_tombstone::codec::signed_record_from_bytes(bytes)
        }
        removal_frontier::codec::TYPE_REMOVAL_FRONTIER => {
            Err("removal_frontier must be signed".to_string())
        }
        removal_frontier::codec::TYPE_SIGNED_REMOVAL_FRONTIER => {
            removal_frontier::codec::signed_record_from_bytes(bytes)
        }
        key_wrap::codec::TYPE_KEY_WRAP => Err("key_wrap must be signed".to_string()),
        key_wrap::codec::TYPE_SIGNED_KEY_WRAP => key_wrap::codec::signed_record_from_bytes(bytes),
        disappearing_messages_setting::codec::TYPE_DISAPPEARING_MESSAGES_SETTING => {
            Err("disappearing_messages_setting must be signed".to_string())
        }
        disappearing_messages_setting::codec::TYPE_SIGNED_DISAPPEARING_MESSAGES_SETTING => {
            disappearing_messages_setting::codec::signed_record_from_bytes(bytes)
        }
        other => Err(format!("unknown encryption event type {other}")),
    }
}

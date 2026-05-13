//! Top-level event decode dispatcher.
//!
//! This is the single entrypoint that turns opaque canonical bytes into a
//! typed `EventRecord` without the caller naming a domain. Routing decisions
//! live here; each branch hands off to a domain's own `event_from_bytes` so
//! per-event syntax stays inside the owning module.
//!
//! Routing order matters:
//!   1. Connection bootstrap records use a magic prefix, not a single
//!      leading type tag. They are checked first so the byte at offset 0
//!      is not misread as a tag.
//!   2. Sync events carry connection scope; the sync domain decides what
//!      counts as a connection-scoped event.
//!   3. Everything else uses a single leading type tag; per-domain
//!      predicates select which domain owns that tag.
//!
//! Adding a new domain is one branch here plus one `pub fn event_from_bytes`
//! in that domain's `mod.rs`.
//!
//! Per-event `codec::record_from_bytes` helpers stay in their owning leaf
//! modules and are reached only via this dispatcher or that module's tests.

use super::{connection, content, encryption, identity, sync, test_events};
use crate::protocol::event_modules::types::EventRecord;

pub fn event_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    if connection::is_connection_bytes(&bytes) {
        return connection::event_from_bytes(bytes);
    }
    if sync::is_connection_scoped_event(&bytes) {
        return sync::event_from_bytes(bytes);
    }
    let tag = *bytes
        .first()
        .ok_or_else(|| "empty event bytes".to_string())?;
    if identity::is_identity_tag(tag) {
        return identity::event_from_bytes(bytes);
    }
    if content::is_content_tag(tag) {
        return content::event_from_bytes(bytes);
    }
    if encryption::is_encryption_tag(tag) {
        return encryption::event_from_bytes(bytes);
    }
    if test_events::is_test_event_tag(tag) {
        return test_events::event_from_bytes(bytes);
    }
    Err(format!("unknown event type {tag}"))
}

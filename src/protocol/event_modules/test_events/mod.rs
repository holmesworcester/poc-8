//! Test-only event modules.
//!
//! These modules exist to exercise protocol mechanics with real events. They
//! should stay honest: no fake harness writes, no bypassing the common worker,
//! and no assumptions that would not hold for a production event module.

pub mod event_with_deps;

use crate::protocol::event_modules::types::EventRecord;
use crate::protocol::event_modules::worker::ProjectionOutput;

pub fn project_record(bytes: &[u8]) -> Result<Option<ProjectionOutput>, String> {
    match bytes.first().copied() {
        Some(
            event_with_deps::codec::TYPE_EVENT_WITH_DEPS
            | event_with_deps::codec::TYPE_STAGED_EVENT_WITH_DEPS,
        ) => Ok(Some(event_with_deps::projector::project(bytes)?)),
        _ => Ok(None),
    }
}

/// Tags owned by this domain. Used by the top-level dispatcher to route
/// ordinary tag-leading event bytes to `event_from_bytes`.
pub fn is_test_event_tag(tag: u8) -> bool {
    matches!(
        tag,
        event_with_deps::codec::TYPE_EVENT_WITH_DEPS
            | event_with_deps::codec::TYPE_STAGED_EVENT_WITH_DEPS
    )
}

/// Decode a tag-leading test event into an `EventRecord`.
pub fn event_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let tag = bytes
        .first()
        .ok_or_else(|| "empty test event bytes".to_string())?;
    match *tag {
        event_with_deps::codec::TYPE_EVENT_WITH_DEPS => {
            event_with_deps::codec::record_from_bytes(bytes)
        }
        event_with_deps::codec::TYPE_STAGED_EVENT_WITH_DEPS => {
            event_with_deps::codec::staged_record_from_bytes(bytes)
        }
        other => Err(format!("unknown test event type {other}")),
    }
}

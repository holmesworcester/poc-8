//! Codec for shared admin grant events.
//!
//! The format is fixed-width:
//!
//! ```text
//! type(1) || created_at_ms(8) || workspace_id(32) || public_key(32)
//!         || authority_event_id(32) || user_event_id(32)
//! ```
//!
//! `authority_event_id` is either the workspace root for bootstrap grants or a
//! prior admin event for ongoing grants.

use crate::protocol::event_modules::types::{EventId, EventRecord, EventScope};
use crate::protocol::wire_schema::{Field, WireSchema};

use super::types::AdminEvent;

pub const TYPE_ADMIN: u8 = 139;

pub const SCHEMA: WireSchema = WireSchema::new(
    "admin",
    TYPE_ADMIN,
    &[
        Field::u64("created_at_ms"),
        Field::id("workspace_id"),
        Field::id("public_key"),
        Field::id("authority_event_id"),
        Field::id("user_event_id"),
    ],
);

pub const ADMIN_WIRE_SIZE: usize = SCHEMA.wire_size();

pub fn encode(event: &AdminEvent) -> Vec<u8> {
    SCHEMA
        .encoder()
        .u64(event.created_at_ms)
        .id(&event.workspace_id)
        .id(&event.public_key)
        .id(&event.authority_event_id)
        .id(&event.user_event_id)
        .finish()
}

pub fn decode(bytes: &[u8]) -> Result<AdminEvent, String> {
    let v = SCHEMA.parse(bytes)?;
    Ok(AdminEvent {
        created_at_ms: v.u64("created_at_ms")?,
        workspace_id: v.id("workspace_id")?,
        public_key: v.id("public_key")?,
        authority_event_id: v.id("authority_event_id")?,
        user_event_id: v.id("user_event_id")?,
    })
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let event = decode(&bytes)?;
    Ok(EventRecord {
        timestamp: event.created_at_ms,
        body_len: ADMIN_WIRE_SIZE - 1,
        canonical_bytes: bytes,
        dependencies: dependencies(&event),
        workspace_id: Some(event.workspace_id),
        scope: EventScope::Shared,
    })
}

pub fn dependencies(event: &AdminEvent) -> Vec<EventId> {
    let mut out = Vec::with_capacity(3);
    push_unique(&mut out, event.workspace_id);
    push_unique(&mut out, event.authority_event_id);
    push_unique(&mut out, event.user_event_id);
    out
}

fn push_unique(out: &mut Vec<EventId>, id: EventId) {
    if !out.iter().any(|candidate| candidate == &id) {
        out.push(id);
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::types::EventScope;

    use super::*;

    fn event() -> AdminEvent {
        AdminEvent {
            created_at_ms: 55,
            workspace_id: [1; 32],
            public_key: [2; 32],
            authority_event_id: [3; 32],
            user_event_id: [4; 32],
        }
    }

    #[test]
    fn roundtrips_fixed_width_admin_event() {
        let encoded = encode(&event());

        assert_eq!(encoded.len(), ADMIN_WIRE_SIZE);
        assert_eq!(decode(&encoded).expect("decode admin"), event());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut encoded = encode(&event());
        encoded.push(0);

        let err = decode(&encoded).expect_err("trailing byte must fail");

        assert!(err.contains("expected"), "{err}");
    }

    #[test]
    fn record_is_shared_and_exposes_unique_workspace_authority_user_deps() {
        let encoded = encode(&event());
        let record = record_from_bytes(encoded.clone()).expect("admin record");

        assert_eq!(record.timestamp, 55);
        assert_eq!(record.body_len, ADMIN_WIRE_SIZE - 1);
        assert_eq!(record.canonical_bytes, encoded);
        assert_eq!(record.scope, EventScope::Shared);
        assert_eq!(record.dependencies, vec![[1; 32], [3; 32], [4; 32]]);
    }

    #[test]
    fn bootstrap_record_deduplicates_workspace_authority_and_root_user() {
        let event = AdminEvent {
            created_at_ms: 55,
            workspace_id: [1; 32],
            public_key: [2; 32],
            authority_event_id: [1; 32],
            user_event_id: [1; 32],
        };

        assert_eq!(dependencies(&event), vec![[1; 32]]);
    }
}

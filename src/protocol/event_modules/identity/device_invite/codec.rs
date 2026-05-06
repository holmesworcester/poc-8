//! Codec for signed device-invite payloads.
//!
//! The fixed-width format is:
//!
//! ```text
//! type(1) || created_at_ms(8) || workspace_id(32)
//! || user_authority_event_id(32) || user_invite_event_id_or_zero(32)
//! || invite_public_key(32)
//! ```

use crate::protocol::event_modules::identity::signed;
use crate::protocol::event_modules::types::{EventId, EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::types::DeviceInviteEvent;

pub const TYPE_DEVICE_INVITE: u8 = 134;
pub const DEVICE_INVITE_WIRE_SIZE: usize = 1 + 8 + 32 + 32 + 32 + 32;

pub fn encode(event: &DeviceInviteEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(DEVICE_INVITE_WIRE_SIZE);
    out.u8(TYPE_DEVICE_INVITE);
    out.u64(event.created_at_ms);
    out.id(&event.workspace_id);
    out.id(&event.user_authority_event_id);
    out.id(&event.user_invite_event_id.unwrap_or([0; 32]));
    out.id(&event.public_key);
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<DeviceInviteEvent, String> {
    let mut reader = Reader::new(bytes, "device invite");
    let tag = reader.u8()?;
    if tag != TYPE_DEVICE_INVITE {
        return Err("expected device invite".to_string());
    }
    let event = DeviceInviteEvent {
        created_at_ms: reader.u64()?,
        workspace_id: reader.id()?,
        user_authority_event_id: reader.id()?,
        user_invite_event_id: optional_event_id(reader.id()?),
        public_key: reader.id()?,
    };
    reader.finish()?;
    Ok(event)
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let event = decode(&bytes)?;
    Ok(EventRecord {
        timestamp: event.created_at_ms,
        body_len: DEVICE_INVITE_WIRE_SIZE - 1,
        canonical_bytes: bytes,
        dependencies: dependencies(&event),
        workspace_id: Some(event.workspace_id),
        scope: EventScope::Shared,
    })
}

pub fn record_from_signed_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let envelope = signed::codec::decode(&bytes)?;
    if envelope.inner_type != TYPE_DEVICE_INVITE {
        return Err("expected signed device_invite".to_string());
    }
    let event = decode(&envelope.payload)?;
    let mut deps = Vec::new();
    push_unique(&mut deps, envelope.signer_event_id);
    for dependency in dependencies(&event) {
        push_unique(&mut deps, dependency);
    }
    Ok(EventRecord {
        timestamp: event.created_at_ms,
        body_len: envelope.payload.len(),
        canonical_bytes: bytes,
        dependencies: deps,
        workspace_id: Some(event.workspace_id),
        scope: EventScope::Shared,
    })
}

pub fn dependencies(event: &DeviceInviteEvent) -> Vec<EventId> {
    let mut out = Vec::with_capacity(3);
    push_unique(&mut out, event.workspace_id);
    push_unique(&mut out, event.user_authority_event_id);
    if let Some(user_invite_event_id) = event.user_invite_event_id {
        push_unique(&mut out, user_invite_event_id);
    }
    out
}

fn optional_event_id(id: EventId) -> Option<EventId> {
    if id.iter().all(|byte| *byte == 0) {
        None
    } else {
        Some(id)
    }
}

fn push_unique(out: &mut Vec<EventId>, id: EventId) {
    if !out.iter().any(|candidate| candidate == &id) {
        out.push(id);
    }
}

#[cfg(test)]
mod tests {
    use crate::core::crypto;
    use crate::protocol::event_modules::identity::signed;
    use crate::protocol::event_modules::types::EventScope;

    use super::*;

    fn event() -> DeviceInviteEvent {
        DeviceInviteEvent {
            created_at_ms: 11,
            workspace_id: [1; 32],
            user_authority_event_id: [2; 32],
            user_invite_event_id: Some([4; 32]),
            public_key: [3; 32],
        }
    }

    // Invariant: roundtrips fixed width device invite event.
    #[test]
    fn roundtrips_fixed_width_device_invite_event() {
        let encoded = encode(&event());

        assert_eq!(encoded.len(), DEVICE_INVITE_WIRE_SIZE);
        assert_eq!(decode(&encoded).expect("decode device invite"), event());
    }

    // Invariant: rejects wrong type and trailing bytes.
    #[test]
    fn rejects_wrong_type_and_trailing_bytes() {
        let mut encoded = encode(&event());
        encoded[0] = 0xff;
        assert_eq!(
            decode(&encoded).expect_err("wrong type must fail"),
            "expected device invite"
        );

        let mut encoded = encode(&event());
        encoded.push(0);
        let err = decode(&encoded).expect_err("trailing byte must fail");
        assert!(err.starts_with("trailing "), "{err}");
    }

    // Invariant: record is shared and depends on workspace user and user invite.
    #[test]
    fn record_is_shared_and_depends_on_workspace_user_and_user_invite() {
        let encoded = encode(&event());
        let record = record_from_bytes(encoded.clone()).expect("record");

        assert_eq!(record.timestamp, 11);
        assert_eq!(record.body_len, DEVICE_INVITE_WIRE_SIZE - 1);
        assert_eq!(record.canonical_bytes, encoded);
        assert_eq!(record.dependencies, vec![[1; 32], [2; 32], [4; 32]]);
        assert_eq!(record.scope, EventScope::Shared);
    }

    // Invariant: signed record exposes signer and semantic dependencies.
    #[test]
    fn signed_record_exposes_signer_and_semantic_dependencies() {
        let private_key = [9; crypto::ED25519_PRIVATE_KEY_BYTES];
        let signed =
            signed::commands::sign_payload([2; 32], &private_key, encode(&event())).expect("sign");
        let bytes = signed::codec::encode(&signed.value);
        let record = record_from_signed_bytes(bytes.clone()).expect("signed record");

        assert_eq!(record.timestamp, 11);
        assert_eq!(record.body_len, DEVICE_INVITE_WIRE_SIZE);
        assert_eq!(record.canonical_bytes, bytes);
        assert_eq!(record.dependencies, vec![[2; 32], [1; 32], [4; 32]]);
        assert_eq!(record.scope, EventScope::Shared);
    }

    // Invariant: zero user invite dependency roundtrips as none.
    #[test]
    fn zero_user_invite_dependency_roundtrips_as_none() {
        let event = DeviceInviteEvent {
            user_invite_event_id: None,
            ..event()
        };
        let encoded = encode(&event);

        assert_eq!(decode(&encoded).expect("decode").user_invite_event_id, None);
        assert_eq!(
            record_from_bytes(encoded).expect("record").dependencies,
            vec![[1; 32], [2; 32]]
        );
    }
}

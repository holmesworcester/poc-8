//! Codec for the `disappearing_messages_setting` event.
//!
//! Layout (inner, fixed-width):
//!
//! ```text
//! type(1) || created_at_ms(8) || workspace_id(32) || ttl_minutes(4)
//!         || authority_admin_event_id(32) || effective_at_minute(8)
//!         || expires_at_or_before_minute(8) || previous_setting_id(32)
//! ```
//!
//! `previous_setting_id` is the canonical 32-byte event id of the
//! predecessor setting whose floor this setting must not regress, or
//! `[0; 32]` as a sentinel meaning "no predecessor" (only legal when no
//! setting has yet been admitted for the workspace).
//!
//! Raw inner bytes are not admissible; admission goes through the signed
//! envelope. The envelope's signer must be the workspace admin event
//! identified by `authority_admin_event_id`.

use crate::core::crypto::{self, Ed25519PrivateKey, ED25519_SIGNATURE_BYTES};
use crate::protocol::event_modules::types::{EventId, EventRecord, EventScope};
use crate::protocol::wire_schema::{Field, WireSchema};

use super::types::{DisappearingMessagesSettingEvent, SignedDisappearingMessagesSettingEnvelope};

pub const TYPE_DISAPPEARING_MESSAGES_SETTING: u8 = 147;
pub const TYPE_SIGNED_DISAPPEARING_MESSAGES_SETTING: u8 = 148;

pub const SCHEMA: WireSchema = WireSchema::new(
    "disappearing_messages_setting",
    TYPE_DISAPPEARING_MESSAGES_SETTING,
    &[
        Field::u64("created_at_ms"),
        Field::id("workspace_id"),
        Field::u32("ttl_minutes"),
        Field::id("authority_admin_event_id"),
        Field::u64("effective_at_minute"),
        Field::u64("expires_at_or_before_minute"),
        Field::id("previous_setting_id"),
    ],
);

pub const DISAPPEARING_MESSAGES_SETTING_WIRE_SIZE: usize = SCHEMA.wire_size();

pub const SIGNED_SCHEMA: WireSchema = WireSchema::new(
    "signed disappearing_messages_setting",
    TYPE_SIGNED_DISAPPEARING_MESSAGES_SETTING,
    &[
        Field::id("authority_admin_event_id"),
        Field::id("signer_public_key"),
        Field::bytes("payload", DISAPPEARING_MESSAGES_SETTING_WIRE_SIZE),
        Field::bytes("signature", ED25519_SIGNATURE_BYTES),
    ],
);

/// Sentinel `previous_setting_id` meaning "no predecessor." Only legal
/// when no setting has yet been admitted for the workspace; the projector
/// rejects it otherwise.
pub const NO_PREVIOUS_SETTING_ID: [u8; 32] = [0; 32];

pub fn encode(event: &DisappearingMessagesSettingEvent) -> Vec<u8> {
    SCHEMA
        .encoder()
        .u64(event.created_at_ms)
        .id(&event.workspace_id)
        .u32(event.ttl_minutes)
        .id(&event.authority_admin_event_id)
        .u64(event.effective_at_minute)
        .u64(event.expires_at_or_before_minute)
        .id(&event.previous_setting_id.unwrap_or(NO_PREVIOUS_SETTING_ID))
        .finish()
}

pub fn decode(bytes: &[u8]) -> Result<DisappearingMessagesSettingEvent, String> {
    let v = SCHEMA.parse(bytes)?;
    let previous_raw = v.id("previous_setting_id")?;
    let previous_setting_id = if previous_raw == NO_PREVIOUS_SETTING_ID {
        None
    } else {
        Some(previous_raw)
    };
    let event = DisappearingMessagesSettingEvent {
        created_at_ms: v.u64("created_at_ms")?,
        workspace_id: v.id("workspace_id")?,
        ttl_minutes: v.u32("ttl_minutes")?,
        authority_admin_event_id: v.id("authority_admin_event_id")?,
        effective_at_minute: v.u64("effective_at_minute")?,
        expires_at_or_before_minute: v.u64("expires_at_or_before_minute")?,
        previous_setting_id,
    };
    let expected = event.created_at_ms / 60_000;
    if event.effective_at_minute != expected {
        return Err(
            "disappearing_messages_setting effective_at_minute disagrees with created_at_ms"
                .to_string(),
        );
    }
    Ok(event)
}

pub fn sign(
    authority_admin_event_id: EventId,
    signer_private_key: &Ed25519PrivateKey,
    payload: Vec<u8>,
) -> SignedDisappearingMessagesSettingEnvelope {
    let mut envelope = SignedDisappearingMessagesSettingEnvelope {
        authority_admin_event_id,
        signer_public_key: crypto::ed25519_public_key(signer_private_key),
        payload,
        signature: [0; ED25519_SIGNATURE_BYTES],
    };
    envelope.signature = crypto::ed25519_sign(signer_private_key, &signing_bytes(&envelope));
    envelope
}

pub fn encode_signed(event: &SignedDisappearingMessagesSettingEnvelope) -> Vec<u8> {
    SIGNED_SCHEMA
        .encoder()
        .id(&event.authority_admin_event_id)
        .id(&event.signer_public_key)
        .bytes(&event.payload)
        .bytes(&event.signature)
        .finish()
}

pub fn decode_signed(bytes: &[u8]) -> Result<SignedDisappearingMessagesSettingEnvelope, String> {
    let v = SIGNED_SCHEMA.parse(bytes)?;
    let signature = v
        .raw("signature")?
        .to_vec()
        .try_into()
        .map_err(|_| "signature length mismatch".to_string())?;
    let event = SignedDisappearingMessagesSettingEnvelope {
        authority_admin_event_id: v.id("authority_admin_event_id")?,
        signer_public_key: v.id("signer_public_key")?,
        payload: v.raw("payload")?.to_vec(),
        signature,
    };
    validate_signed_payload(&event)?;
    if !crypto::ed25519_verify(
        &event.signer_public_key,
        &signing_bytes(&event),
        &event.signature,
    ) {
        return Err(
            "signed disappearing_messages_setting signature verification failed".to_string(),
        );
    }
    Ok(event)
}

pub fn signing_bytes(event: &SignedDisappearingMessagesSettingEnvelope) -> Vec<u8> {
    SIGNED_SCHEMA
        .encoder()
        .id(&event.authority_admin_event_id)
        .id(&event.signer_public_key)
        .bytes(&event.payload)
        .finish_without_trailing_fields(1)
}

pub fn signed_record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let envelope = decode_signed(&bytes)?;
    let inner = decode(&envelope.payload)?;
    if envelope.authority_admin_event_id != inner.authority_admin_event_id {
        return Err(
            "disappearing_messages_setting envelope signer does not match payload authority"
                .to_string(),
        );
    }
    let mut dependencies = Vec::with_capacity(3);
    push_unique(&mut dependencies, inner.authority_admin_event_id);
    push_unique(&mut dependencies, inner.workspace_id);
    if let Some(previous_setting_id) = inner.previous_setting_id {
        push_unique(&mut dependencies, previous_setting_id);
    }
    Ok(EventRecord {
        timestamp: inner.created_at_ms,
        body_len: DISAPPEARING_MESSAGES_SETTING_WIRE_SIZE - 1,
        canonical_bytes: bytes,
        dependencies,
        workspace_id: Some(inner.workspace_id),
        scope: EventScope::Shared,
    })
}

fn validate_signed_payload(
    event: &SignedDisappearingMessagesSettingEnvelope,
) -> Result<(), String> {
    let Some(actual_type) = event.payload.first().copied() else {
        return Err("signed disappearing_messages_setting payload is empty".to_string());
    };
    if actual_type != TYPE_DISAPPEARING_MESSAGES_SETTING {
        return Err(
            "signed disappearing_messages_setting payload is not a setting event".to_string(),
        );
    }
    decode(&event.payload).map(|_| ())
}

fn push_unique(out: &mut Vec<EventId>, id: EventId) {
    if !out.iter().any(|candidate| candidate == &id) {
        out.push(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> DisappearingMessagesSettingEvent {
        DisappearingMessagesSettingEvent {
            created_at_ms: 6_000_000,
            workspace_id: [1; 32],
            ttl_minutes: 5,
            authority_admin_event_id: [2; 32],
            effective_at_minute: 100,
            expires_at_or_before_minute: 0,
            previous_setting_id: None,
        }
    }

    #[test]
    fn roundtrips_inner_setting_event() {
        let bytes = encode(&event());
        assert_eq!(bytes.len(), DISAPPEARING_MESSAGES_SETTING_WIRE_SIZE);
        assert_eq!(decode(&bytes).expect("decode"), event());
    }

    #[test]
    fn rejects_inconsistent_effective_at_minute() {
        let mut bad = event();
        bad.effective_at_minute = 999;
        let bytes = encode(&bad);
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn signed_envelope_roundtrips_and_verifies() {
        let private_key = [9; crate::core::crypto::ED25519_PRIVATE_KEY_BYTES];
        let payload = encode(&event());
        let envelope = sign([2; 32], &private_key, payload);
        let bytes = encode_signed(&envelope);
        let decoded = decode_signed(&bytes).expect("verify and decode");
        assert_eq!(decoded.authority_admin_event_id, [2; 32]);
        assert_eq!(decoded.payload, encode(&event()));
    }

    #[test]
    fn signed_record_dependencies_include_admin_and_workspace() {
        let private_key = [9; crate::core::crypto::ED25519_PRIVATE_KEY_BYTES];
        let bytes = encode_signed(&sign([2; 32], &private_key, encode(&event())));
        let record = signed_record_from_bytes(bytes).expect("record");
        assert_eq!(record.dependencies, vec![[2; 32], [1; 32]]);
        assert_eq!(record.workspace_id, Some([1; 32]));
        assert_eq!(record.timestamp, 6_000_000);
    }

    #[test]
    fn roundtrips_floor_and_previous_setting_id() {
        let mut e = event();
        e.expires_at_or_before_minute = 50;
        e.previous_setting_id = Some([42; 32]);
        let bytes = encode(&e);
        assert_eq!(bytes.len(), DISAPPEARING_MESSAGES_SETTING_WIRE_SIZE);
        let decoded = decode(&bytes).expect("decode");
        assert_eq!(decoded.expires_at_or_before_minute, 50);
        assert_eq!(decoded.previous_setting_id, Some([42; 32]));
    }

    #[test]
    fn signed_record_dependencies_include_previous_setting_when_set() {
        let private_key = [9; crate::core::crypto::ED25519_PRIVATE_KEY_BYTES];
        let mut e = event();
        e.previous_setting_id = Some([42; 32]);
        let bytes = encode_signed(&sign([2; 32], &private_key, encode(&e)));
        let record = signed_record_from_bytes(bytes).expect("record");
        assert_eq!(record.dependencies, vec![[2; 32], [1; 32], [42; 32]]);
    }
}

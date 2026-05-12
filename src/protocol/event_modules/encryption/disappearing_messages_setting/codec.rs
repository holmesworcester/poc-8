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
use crate::protocol::wire::{Reader, Writer};

use super::types::{DisappearingMessagesSettingEvent, SignedDisappearingMessagesSettingEnvelope};

pub const TYPE_DISAPPEARING_MESSAGES_SETTING: u8 = 147;
pub const TYPE_SIGNED_DISAPPEARING_MESSAGES_SETTING: u8 = 148;
pub const DISAPPEARING_MESSAGES_SETTING_WIRE_SIZE: usize = 1 + 8 + 32 + 4 + 32 + 8 + 8 + 32;

/// Sentinel `previous_setting_id` meaning "no predecessor." Only legal
/// when no setting has yet been admitted for the workspace; the projector
/// rejects it otherwise.
pub const NO_PREVIOUS_SETTING_ID: [u8; 32] = [0; 32];

pub fn encode(event: &DisappearingMessagesSettingEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(DISAPPEARING_MESSAGES_SETTING_WIRE_SIZE);
    out.u8(TYPE_DISAPPEARING_MESSAGES_SETTING);
    out.u64(event.created_at_ms);
    out.id(&event.workspace_id);
    out.u32(event.ttl_minutes as usize);
    out.id(&event.authority_admin_event_id);
    out.u64(event.effective_at_minute);
    out.u64(event.expires_at_or_before_minute);
    out.id(&event.previous_setting_id.unwrap_or(NO_PREVIOUS_SETTING_ID));
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<DisappearingMessagesSettingEvent, String> {
    let mut reader = Reader::new(bytes, "disappearing_messages_setting");
    let tag = reader.u8()?;
    if tag != TYPE_DISAPPEARING_MESSAGES_SETTING {
        return Err("expected disappearing_messages_setting".to_string());
    }
    let created_at_ms = reader.u64()?;
    let workspace_id = reader.id()?;
    let ttl_minutes = reader.u32()?;
    let authority_admin_event_id = reader.id()?;
    let effective_at_minute = reader.u64()?;
    let expires_at_or_before_minute = reader.u64()?;
    let previous_raw = reader.id()?;
    reader.finish()?;
    let previous_setting_id = if previous_raw == NO_PREVIOUS_SETTING_ID {
        None
    } else {
        Some(previous_raw)
    };
    let event = DisappearingMessagesSettingEvent {
        created_at_ms,
        workspace_id,
        ttl_minutes,
        authority_admin_event_id,
        effective_at_minute,
        expires_at_or_before_minute,
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
    let mut out = Writer::with_capacity(signing_len(event.payload.len()) + ED25519_SIGNATURE_BYTES);
    write_signing_fields(&mut out, event);
    out.raw(&event.signature);
    out.finish()
}

pub fn decode_signed(bytes: &[u8]) -> Result<SignedDisappearingMessagesSettingEnvelope, String> {
    let mut reader = Reader::new(bytes, "signed disappearing_messages_setting envelope");
    let tag = reader.u8()?;
    if tag != TYPE_SIGNED_DISAPPEARING_MESSAGES_SETTING {
        return Err("expected signed disappearing_messages_setting envelope".to_string());
    }
    let authority_admin_event_id = reader.id()?;
    let signer_public_key = reader.id()?;
    let payload = reader.sized_bytes()?;
    let signature_bytes = reader.bytes(ED25519_SIGNATURE_BYTES)?;
    reader.finish()?;
    let signature = signature_bytes
        .try_into()
        .map_err(|_| "signature length mismatch".to_string())?;
    let event = SignedDisappearingMessagesSettingEnvelope {
        authority_admin_event_id,
        signer_public_key,
        payload,
        signature,
    };
    validate_signed_payload(&event)?;
    if !crypto::ed25519_verify(
        &event.signer_public_key,
        &signing_bytes(&event),
        &event.signature,
    ) {
        return Err("signed disappearing_messages_setting signature verification failed".to_string());
    }
    Ok(event)
}

pub fn signing_bytes(event: &SignedDisappearingMessagesSettingEnvelope) -> Vec<u8> {
    let mut out = Writer::with_capacity(signing_len(event.payload.len()));
    write_signing_fields(&mut out, event);
    out.finish()
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

fn write_signing_fields(out: &mut Writer, event: &SignedDisappearingMessagesSettingEnvelope) {
    out.u8(TYPE_SIGNED_DISAPPEARING_MESSAGES_SETTING);
    out.id(&event.authority_admin_event_id);
    out.id(&event.signer_public_key);
    out.sized_bytes(&event.payload);
}

fn signing_len(payload_len: usize) -> usize {
    1 + 32 + 32 + 4 + payload_len
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

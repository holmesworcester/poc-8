//! Codec for signed removal frontier events.
//!
//! Each frontier carries at most `MAX_REMOVAL_FRONTIER_REFS` sorted refs and
//! always encodes to the same byte length by zero-filling unused slots. Commands
//! build additional frontier nodes when the logical removal boundary needs more
//! fan-in, so decoders can reject variable-size history lists while the protocol
//! can still cover unusual concurrent removal bursts. The dependency closure,
//! not the encoded ref count, is the invariant that must carry removal history.

use crate::core::crypto::{self, Ed25519PrivateKey, ED25519_SIGNATURE_BYTES};
use crate::protocol::event_modules::types::{EventId, EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};
use crate::protocol::wire_schema::{Field, WireSchema};

use super::types::{
    RemovalFrontierEvent, SignedRemovalFrontierEnvelope, MAX_REMOVAL_FRONTIER_REFS,
};

pub const TYPE_REMOVAL_FRONTIER: u8 = 20;
pub const TYPE_SIGNED_REMOVAL_FRONTIER: u8 = 21;

const REMOVAL_SLOT_BYTES: usize = 32 * MAX_REMOVAL_FRONTIER_REFS;

pub const SCHEMA: WireSchema = WireSchema::new(
    "removal_frontier",
    TYPE_REMOVAL_FRONTIER,
    &[
        Field::id("workspace_id"),
        Field::u64("created_at_ms"),
        Field::id("authority_admin_id"),
        Field::u8("removal_count"),
        Field::bytes("removal_slot", REMOVAL_SLOT_BYTES),
    ],
);

pub const REMOVAL_FRONTIER_WIRE_SIZE: usize = SCHEMA.wire_size();

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemovalFrontierMetadata {
    workspace_id: EventId,
    created_at_ms: u64,
    authority_admin_id: EventId,
    removal_event_ids: Vec<EventId>,
}

pub fn encode(event: &RemovalFrontierEvent) -> Result<Vec<u8>, String> {
    validate_event(event)?;
    let count = u8::try_from(event.removal_event_ids.len())
        .map_err(|_| "removal frontier has too many refs".to_string())?;
    let mut slot = [0u8; REMOVAL_SLOT_BYTES];
    for (i, id) in event.removal_event_ids.iter().enumerate() {
        slot[i * 32..(i + 1) * 32].copy_from_slice(id);
    }
    Ok(SCHEMA
        .encoder()
        .id(&event.workspace_id)
        .u64(event.created_at_ms)
        .id(&event.authority_admin_id)
        .u8(count)
        .bytes(&slot)
        .finish())
}

pub fn decode(bytes: &[u8]) -> Result<RemovalFrontierEvent, String> {
    let v = SCHEMA.parse(bytes)?;
    let count = usize::from(v.u8("removal_count")?);
    if count > MAX_REMOVAL_FRONTIER_REFS {
        return Err("removal frontier has too many refs".to_string());
    }
    let slot = v.raw("removal_slot")?;
    let used = count * 32;
    if slot[used..].iter().any(|b| *b != 0) {
        return Err("removal frontier unused ref slots must be empty".to_string());
    }
    let mut removal_event_ids = Vec::with_capacity(count);
    for i in 0..count {
        let mut id = [0u8; 32];
        id.copy_from_slice(&slot[i * 32..(i + 1) * 32]);
        removal_event_ids.push(id);
    }
    let event = RemovalFrontierEvent {
        workspace_id: v.id("workspace_id")?,
        created_at_ms: v.u64("created_at_ms")?,
        authority_admin_id: v.id("authority_admin_id")?,
        removal_event_ids,
    };
    validate_event(&event)?;
    Ok(event)
}

pub fn sign(
    signer_endpoint_shared_id: EventId,
    signer_private_key: &Ed25519PrivateKey,
    payload: Vec<u8>,
) -> SignedRemovalFrontierEnvelope {
    let mut envelope = SignedRemovalFrontierEnvelope {
        signer_endpoint_shared_id,
        signer_public_key: crypto::ed25519_public_key(signer_private_key),
        payload,
        signature: [0; ED25519_SIGNATURE_BYTES],
    };
    envelope.signature = crypto::ed25519_sign(signer_private_key, &signing_bytes(&envelope));
    envelope
}

pub fn encode_signed(event: &SignedRemovalFrontierEnvelope) -> Vec<u8> {
    let mut out = Writer::with_capacity(signing_len(event.payload.len()) + ED25519_SIGNATURE_BYTES);
    write_signing_fields(&mut out, event);
    out.raw(&event.signature);
    out.finish()
}

pub fn decode_signed(bytes: &[u8]) -> Result<SignedRemovalFrontierEnvelope, String> {
    let mut reader = Reader::new(bytes, "signed removal frontier envelope");
    let tag = reader.u8()?;
    if tag != TYPE_SIGNED_REMOVAL_FRONTIER {
        return Err("expected signed removal frontier envelope".to_string());
    }
    let signer_endpoint_shared_id = reader.id()?;
    let signer_public_key = reader.id()?;
    let payload = reader.sized_bytes()?;
    let signature_bytes = reader.bytes(ED25519_SIGNATURE_BYTES)?;
    reader.finish()?;

    let signature = fixed_signature(signature_bytes)?;
    let event = SignedRemovalFrontierEnvelope {
        signer_endpoint_shared_id,
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
        return Err("signed removal frontier signature verification failed".to_string());
    }
    Ok(event)
}

pub fn signing_bytes(event: &SignedRemovalFrontierEnvelope) -> Vec<u8> {
    let mut out = Writer::with_capacity(signing_len(event.payload.len()));
    write_signing_fields(&mut out, event);
    out.finish()
}

pub fn signed_record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let envelope = decode_signed(&bytes)?;
    let metadata = metadata(&envelope.payload)?;
    let mut dependencies = Vec::with_capacity(3 + metadata.removal_event_ids.len());
    push_unique(&mut dependencies, envelope.signer_endpoint_shared_id);
    push_unique(&mut dependencies, metadata.workspace_id);
    push_unique(&mut dependencies, metadata.authority_admin_id);
    for removal_event_id in metadata.removal_event_ids {
        push_unique(&mut dependencies, removal_event_id);
    }
    Ok(EventRecord {
        timestamp: metadata.created_at_ms,
        body_len: REMOVAL_FRONTIER_WIRE_SIZE - 1,
        canonical_bytes: bytes,
        dependencies,
        workspace_id: Some(metadata.workspace_id),
        scope: EventScope::Shared,
    })
}

fn metadata(bytes: &[u8]) -> Result<RemovalFrontierMetadata, String> {
    let event = decode(bytes)?;
    Ok(RemovalFrontierMetadata {
        workspace_id: event.workspace_id,
        created_at_ms: event.created_at_ms,
        authority_admin_id: event.authority_admin_id,
        removal_event_ids: event.removal_event_ids,
    })
}

fn validate_signed_payload(event: &SignedRemovalFrontierEnvelope) -> Result<(), String> {
    let Some(actual_type) = event.payload.first().copied() else {
        return Err("signed removal frontier payload is empty".to_string());
    };
    if actual_type != TYPE_REMOVAL_FRONTIER {
        return Err("signed removal frontier payload is not a removal frontier".to_string());
    }
    metadata(&event.payload).map(|_| ())
}

fn validate_event(event: &RemovalFrontierEvent) -> Result<(), String> {
    if is_zero(&event.workspace_id) {
        return Err("removal frontier workspace cannot be empty".to_string());
    }
    if is_zero(&event.authority_admin_id) {
        return Err("removal frontier authority_admin_id cannot be empty".to_string());
    }
    if event.removal_event_ids.len() > MAX_REMOVAL_FRONTIER_REFS {
        return Err("removal frontier has too many refs".to_string());
    }
    for id in &event.removal_event_ids {
        if is_zero(id) {
            return Err("removal frontier ref cannot be empty".to_string());
        }
    }
    let mut sorted = event.removal_event_ids.clone();
    sorted.sort();
    sorted.dedup();
    if sorted != event.removal_event_ids {
        return Err("removal frontier refs must be sorted and unique".to_string());
    }
    Ok(())
}

fn write_signing_fields(out: &mut Writer, event: &SignedRemovalFrontierEnvelope) {
    out.u8(TYPE_SIGNED_REMOVAL_FRONTIER);
    out.id(&event.signer_endpoint_shared_id);
    out.id(&event.signer_public_key);
    out.sized_bytes(&event.payload);
}

fn signing_len(payload_len: usize) -> usize {
    1 + 32 + 32 + 4 + payload_len
}

fn fixed_signature(bytes: Vec<u8>) -> Result<[u8; ED25519_SIGNATURE_BYTES], String> {
    bytes
        .try_into()
        .map_err(|_| "signed removal frontier signature length mismatch".to_string())
}

fn push_unique(out: &mut Vec<EventId>, id: EventId) {
    if !out.iter().any(|candidate| candidate == &id) {
        out.push(id);
    }
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use crate::core::crypto::ED25519_PRIVATE_KEY_BYTES;
    use crate::protocol::event_modules::types::EventScope;

    use super::*;

    fn event() -> RemovalFrontierEvent {
        RemovalFrontierEvent {
            workspace_id: [1; 32],
            created_at_ms: 1234,
            authority_admin_id: [2; 32],
            removal_event_ids: vec![[3; 32], [4; 32]],
        }
    }

    fn signed_event() -> Vec<u8> {
        let payload = encode(&event()).expect("encode");
        let envelope = sign([5; 32], &[9; ED25519_PRIVATE_KEY_BYTES], payload);
        encode_signed(&envelope)
    }

    #[test]
    fn roundtrips_fixed_width_frontier_refs() {
        let event = event();
        let bytes = encode(&event).expect("encode");

        assert_eq!(bytes.len(), REMOVAL_FRONTIER_WIRE_SIZE);
        assert_eq!(decode(&bytes).expect("decode"), event);
    }

    #[test]
    fn signed_record_exposes_workspace_authority_signer_and_ref_dependencies() {
        let record = signed_record_from_bytes(signed_event()).expect("record");

        assert_eq!(record.scope, EventScope::Shared);
        assert_eq!(record.workspace_id, Some([1; 32]));
        assert_eq!(record.timestamp, 1234);
        assert_eq!(
            record.dependencies,
            vec![[5; 32], [1; 32], [2; 32], [3; 32], [4; 32]]
        );
    }

    #[test]
    fn rejects_non_canonical_refs_and_tampered_signature() {
        let bad = RemovalFrontierEvent {
            removal_event_ids: vec![[4; 32], [3; 32]],
            ..event()
        };
        assert_eq!(
            encode(&bad).expect_err("unsorted refs must fail"),
            "removal frontier refs must be sorted and unique"
        );

        let mut bytes = signed_event();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert_eq!(
            decode_signed(&bytes).expect_err("tamper must fail"),
            "signed removal frontier signature verification failed"
        );
    }
}

//! Codec for signed shared envelopes.
//!
//! The signature covers the canonical envelope prefix:
//! `type || signer_event_id || signer_public_key || inner_type || payload_len || payload`.
//! The signature itself is the final fixed-width field.

use crate::core::crypto::{self, ED25519_SIGNATURE_BYTES};
use crate::protocol::event_modules::types::{EventId, EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::super::{admin, device_invite, endpoint_shared, invite_server, user, user_invite};
use super::types::SignedEnvelope;

pub const TYPE_SIGNED: u8 = 130;

pub fn encode(event: &SignedEnvelope) -> Vec<u8> {
    let mut out = Writer::with_capacity(signing_len(event.payload.len()) + ED25519_SIGNATURE_BYTES);
    write_signing_fields(&mut out, event);
    out.raw(&event.signature);
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<SignedEnvelope, String> {
    let mut reader = Reader::new(bytes, "signed envelope");
    let tag = reader.u8()?;
    if tag != TYPE_SIGNED {
        return Err("expected signed envelope".to_string());
    }
    let signer_event_id = reader.id()?;
    let signer_public_key = reader.id()?;
    let inner_type = reader.u8()?;
    let payload = reader.sized_bytes()?;
    let signature_bytes = reader.bytes(ED25519_SIGNATURE_BYTES)?;
    reader.finish()?;

    let signature = fixed_signature(signature_bytes)?;
    let event = SignedEnvelope {
        signer_event_id,
        signer_public_key,
        inner_type,
        payload,
        signature,
    };
    validate_payload(&event)?;
    if !crypto::ed25519_verify(
        &event.signer_public_key,
        &signing_bytes(&event),
        &event.signature,
    ) {
        return Err("signed envelope signature verification failed".to_string());
    }
    Ok(event)
}

pub fn signing_bytes(event: &SignedEnvelope) -> Vec<u8> {
    let mut out = Writer::with_capacity(signing_len(event.payload.len()));
    write_signing_fields(&mut out, event);
    out.finish()
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let decoded = decode(&bytes)?;
    let metadata = inner_metadata(&decoded)?;
    Ok(EventRecord {
        timestamp: metadata.timestamp,
        body_len: metadata.body_len,
        canonical_bytes: bytes,
        dependencies: metadata.dependencies,
        workspace_id: metadata.workspace_id,
        scope: EventScope::Shared,
    })
}

struct InnerMetadata {
    timestamp: u64,
    body_len: usize,
    dependencies: Vec<EventId>,
    workspace_id: Option<EventId>,
}

pub fn dependencies(event: &SignedEnvelope) -> Result<Vec<EventId>, String> {
    inner_metadata(event).map(|metadata| metadata.dependencies)
}

fn inner_metadata(event: &SignedEnvelope) -> Result<InnerMetadata, String> {
    let mut dependencies = Vec::new();
    push_unique(&mut dependencies, event.signer_event_id);

    let (timestamp, body_len, inner_dependencies, workspace_id) = match event.inner_type {
        user_invite::codec::TYPE_USER_INVITE => {
            let inner = user_invite::codec::decode(&event.payload)?;
            (
                inner.created_at_ms,
                user_invite::codec::USER_INVITE_WIRE_SIZE - 1,
                vec![inner.workspace_id, inner.authority_event_id],
                Some(inner.workspace_id),
            )
        }
        invite_server::codec::TYPE_INVITE_SERVER => {
            let inner = invite_server::codec::decode(&event.payload)?;
            (
                inner.created_at_ms,
                invite_server::codec::INVITE_SERVER_WIRE_SIZE - 1,
                vec![inner.workspace_id, inner.authority_event_id],
                Some(inner.workspace_id),
            )
        }
        user::codec::TYPE_USER => {
            let inner = user::codec::decode(&event.payload)?;
            (
                inner.created_at_ms,
                user::codec::USER_WIRE_SIZE - 1,
                vec![inner.workspace_id],
                Some(inner.workspace_id),
            )
        }
        device_invite::codec::TYPE_DEVICE_INVITE => {
            let inner = device_invite::codec::decode(&event.payload)?;
            (
                inner.created_at_ms,
                device_invite::codec::DEVICE_INVITE_WIRE_SIZE - 1,
                device_invite::codec::dependencies(&inner),
                Some(inner.workspace_id),
            )
        }
        endpoint_shared::codec::TYPE_ENDPOINT_SHARED => {
            let inner = endpoint_shared::codec::decode(&event.payload)?;
            (
                inner.created_at_ms,
                endpoint_shared::codec::ENDPOINT_SHARED_WIRE_SIZE - 1,
                vec![inner.workspace_id, inner.user_authority_event_id],
                Some(inner.workspace_id),
            )
        }
        admin::codec::TYPE_ADMIN => {
            let inner = admin::codec::decode(&event.payload)?;
            (
                inner.created_at_ms,
                admin::codec::ADMIN_WIRE_SIZE - 1,
                admin::codec::dependencies(&inner),
                Some(inner.workspace_id),
            )
        }
        _ => (0, event.payload.len(), Vec::new(), None),
    };

    for dependency in inner_dependencies {
        push_unique(&mut dependencies, dependency);
    }

    Ok(InnerMetadata {
        timestamp,
        body_len,
        dependencies,
        workspace_id,
    })
}

fn push_unique(out: &mut Vec<EventId>, id: EventId) {
    if !out.iter().any(|candidate| candidate == &id) {
        out.push(id);
    }
}

fn write_signing_fields(out: &mut Writer, event: &SignedEnvelope) {
    out.u8(TYPE_SIGNED);
    out.id(&event.signer_event_id);
    out.id(&event.signer_public_key);
    out.u8(event.inner_type);
    out.sized_bytes(&event.payload);
}

fn signing_len(payload_len: usize) -> usize {
    1 + 32 + 32 + 1 + 4 + payload_len
}

fn fixed_signature(bytes: Vec<u8>) -> Result<[u8; ED25519_SIGNATURE_BYTES], String> {
    bytes
        .try_into()
        .map_err(|_| "signed envelope signature length mismatch".to_string())
}

fn validate_payload(event: &SignedEnvelope) -> Result<(), String> {
    let Some(actual_type) = event.payload.first().copied() else {
        return Err("signed envelope payload is empty".to_string());
    };
    if actual_type != event.inner_type {
        return Err("signed envelope inner type does not match payload".to_string());
    }
    if actual_type == TYPE_SIGNED {
        return Err("nested signed envelopes are not allowed".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::core::crypto::{self, ED25519_PRIVATE_KEY_BYTES};
    use crate::protocol::event_modules::identity::{admin, endpoint_shared, user_invite};

    use super::*;
    use crate::protocol::event_modules::types::EventScope;

    fn fixture() -> SignedEnvelope {
        let signer_event_id = [3; 32];
        let private_key = [9; ED25519_PRIVATE_KEY_BYTES];
        super::super::commands::sign_payload(signer_event_id, &private_key, vec![1, 2, 3, 4])
            .expect("sign payload")
            .value
    }

    fn sign(signer_event_id: EventId, payload: Vec<u8>) -> SignedEnvelope {
        let private_key = [9; ED25519_PRIVATE_KEY_BYTES];
        super::super::commands::sign_payload(signer_event_id, &private_key, payload)
            .expect("sign payload")
            .value
    }

    #[test]
    fn signed_envelope_roundtrips_and_exposes_signer_dependency() {
        let envelope = fixture();
        let bytes = encode(&envelope);

        assert_eq!(decode(&bytes).unwrap(), envelope);
        let record = record_from_bytes(bytes.clone()).unwrap();
        assert_eq!(record.canonical_bytes, bytes);
        assert_eq!(record.dependencies, vec![[3; 32]]);
        assert_eq!(record.scope, EventScope::Shared);
        assert_eq!(record.body_len, 4);
    }

    #[test]
    fn signed_user_invite_uses_inner_timestamp_and_unique_dependencies() {
        let payload = user_invite::codec::encode(&user_invite::types::UserInviteEvent {
            created_at_ms: 1234,
            public_key: [4; 32],
            workspace_id: [1; 32],
            authority_event_id: [2; 32],
        });
        let bytes = encode(&sign([9; 32], payload));

        let record = record_from_bytes(bytes).expect("signed user_invite record");

        assert_eq!(record.timestamp, 1234);
        assert_eq!(
            record.body_len,
            user_invite::codec::USER_INVITE_WIRE_SIZE - 1
        );
        assert_eq!(record.dependencies, vec![[9; 32], [1; 32], [2; 32]]);
        assert_eq!(record.scope, EventScope::Shared);
    }

    #[test]
    fn signed_endpoint_shared_exposes_signer_workspace_and_user_authority_dependencies() {
        let payload =
            endpoint_shared::codec::encode(&endpoint_shared::types::EndpointSharedEvent {
                created_at_ms: 5678,
                workspace_id: [1; 32],
                user_authority_event_id: [2; 32],
                endpoint_id: [3; 32],
                signing_public_key: [4; 32],
                endpoint_role:
                    crate::protocol::event_modules::identity::endpoint::types::EndpointRole::Device,
                device_name: "laptop".to_string(),
            })
            .expect("encode endpoint_shared");
        let bytes = encode(&sign([8; 32], payload));

        let record = record_from_bytes(bytes).expect("signed endpoint_shared record");

        assert_eq!(record.timestamp, 5678);
        assert_eq!(
            record.body_len,
            endpoint_shared::codec::ENDPOINT_SHARED_WIRE_SIZE - 1
        );
        assert_eq!(record.dependencies, vec![[8; 32], [1; 32], [2; 32]]);
    }

    #[test]
    fn signed_admin_uses_inner_timestamp_and_unique_dependencies() {
        let payload = admin::codec::encode(&admin::types::AdminEvent {
            created_at_ms: 9012,
            workspace_id: [1; 32],
            public_key: [4; 32],
            authority_event_id: [2; 32],
            user_event_id: [3; 32],
        });
        let bytes = encode(&sign([7; 32], payload));

        let record = record_from_bytes(bytes).expect("signed admin record");

        assert_eq!(record.timestamp, 9012);
        assert_eq!(record.body_len, admin::codec::ADMIN_WIRE_SIZE - 1);
        assert_eq!(
            record.dependencies,
            vec![[7; 32], [1; 32], [2; 32], [3; 32]]
        );
    }

    #[test]
    fn signed_admin_metadata_deduplicates_signer_and_inner_dependencies() {
        let payload = admin::codec::encode(&admin::types::AdminEvent {
            created_at_ms: 9012,
            workspace_id: [1; 32],
            public_key: [4; 32],
            authority_event_id: [1; 32],
            user_event_id: [1; 32],
        });
        let bytes = encode(&sign([1; 32], payload));

        let record = record_from_bytes(bytes).expect("signed admin record");

        assert_eq!(record.dependencies, vec![[1; 32]]);
    }

    #[test]
    fn signed_envelope_rejects_trailing_bytes() {
        let mut bytes = encode(&fixture());
        bytes.push(0);

        assert!(decode(&bytes)
            .unwrap_err()
            .contains("trailing signed envelope bytes"));
    }

    #[test]
    fn signed_envelope_rejects_wrong_signature() {
        let mut bytes = encode(&fixture());
        let last = bytes.len() - 1;
        bytes[last] ^= 1;

        assert!(decode(&bytes)
            .unwrap_err()
            .contains("signature verification failed"));
    }

    #[test]
    fn signed_envelope_rejects_tampered_payload_before_metadata_extraction() {
        let payload = user_invite::codec::encode(&user_invite::types::UserInviteEvent {
            created_at_ms: 1234,
            public_key: [4; 32],
            workspace_id: [1; 32],
            authority_event_id: [2; 32],
        });
        let mut bytes = encode(&sign([9; 32], payload));
        bytes[signing_len(0) + 8] ^= 1;

        assert!(record_from_bytes(bytes)
            .unwrap_err()
            .contains("signature verification failed"));
    }

    #[test]
    fn signed_envelope_rejects_wrong_signer_event_id() {
        let mut bytes = encode(&fixture());
        bytes[1] ^= 1;

        assert!(decode(&bytes)
            .unwrap_err()
            .contains("signature verification failed"));
    }

    #[test]
    fn signed_envelope_rejects_wrong_signer_public_key() {
        let mut bytes = encode(&fixture());
        bytes[33] ^= 1;

        assert!(decode(&bytes)
            .unwrap_err()
            .contains("signature verification failed"));
    }

    #[test]
    fn signed_envelope_canonical_bytes_are_deterministic() {
        let signer_event_id = [4; 32];
        let private_key = [12; ED25519_PRIVATE_KEY_BYTES];
        let payload = vec![2, 8, 13, 21];
        let first =
            super::super::commands::sign_payload(signer_event_id, &private_key, payload.clone())
                .expect("sign first")
                .value;
        let second = super::super::commands::sign_payload(signer_event_id, &private_key, payload)
            .expect("sign second")
            .value;

        let bytes = encode(&first);
        assert_eq!(bytes, encode(&second));
        assert_eq!(bytes, encode(&decode(&bytes).unwrap()));

        let public_key = crypto::ed25519_public_key(&private_key);
        let mut expected_prefix = Vec::new();
        expected_prefix.push(TYPE_SIGNED);
        expected_prefix.extend_from_slice(&signer_event_id);
        expected_prefix.extend_from_slice(&public_key);
        expected_prefix.push(2);
        expected_prefix.extend_from_slice(&4u32.to_be_bytes());
        expected_prefix.extend_from_slice(&[2, 8, 13, 21]);
        assert_eq!(&bytes[..expected_prefix.len()], expected_prefix.as_slice());
    }
}

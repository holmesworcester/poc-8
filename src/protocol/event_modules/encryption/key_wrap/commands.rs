//! Commands for signed key-wrap events.
//!
//! Creation seals one existing local key-secret id for one recipient key under
//! one removal frontier, then returns a proposed shared event. The command owns
//! cryptographic construction of that event, but it does not publish recipient
//! keys, store rows, or run receiver-side derivation.

use crate::core::crypto::{self, Ed25519PrivateKey, X25519PublicKey};
use crate::protocol::event_modules::types::{event_id, EventId};
use crate::protocol::event_modules::worker::CommandOutput;

use super::super::local_key_secret;
use super::codec;
use super::types::KeyWrapEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateKeyWrap {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub signer_endpoint_shared_id: EventId,
    pub signer_private_key: Ed25519PrivateKey,
    pub removal_frontier_id: EventId,
    pub local_key_secret_id: EventId,
    pub key_secret: local_key_secret::types::KeySecret,
    pub recipient_key_id: EventId,
    pub recipient_key: X25519PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyWrapOutput {
    pub key_wrap_id: EventId,
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    pub local_key_secret_id: EventId,
    pub recipient_key_id: EventId,
}

pub fn create(input: CreateKeyWrap) -> Result<CommandOutput<KeyWrapOutput>, String> {
    validate_id("workspace_id", &input.workspace_id)?;
    validate_id(
        "signer_endpoint_shared_id",
        &input.signer_endpoint_shared_id,
    )?;
    validate_id("removal_frontier_id", &input.removal_frontier_id)?;
    validate_id("local_key_secret_id", &input.local_key_secret_id)?;
    validate_id("key_secret", &input.key_secret)?;
    validate_id("recipient_key_id", &input.recipient_key_id)?;
    validate_id("recipient_key", &input.recipient_key)?;
    validate_secret_commitment(&input)?;

    let sender_wrap_secret = crypto::random_x25519_private_key();
    let sender_wrap_public_key = crypto::x25519_public_key(&sender_wrap_secret);
    let nonce = crypto::random_xchacha20poly1305_nonce();
    let mut event = KeyWrapEvent {
        workspace_id: input.workspace_id,
        created_at_ms: input.created_at_ms,
        removal_frontier_id: input.removal_frontier_id,
        local_key_secret_id: input.local_key_secret_id,
        recipient_key_id: input.recipient_key_id,
        sender_wrap_public_key,
        nonce,
        ciphertext: [0; super::types::KEY_WRAP_CIPHERTEXT_BYTES],
    };
    let ciphertext = crypto::x25519_xchacha20poly1305_encrypt(
        &sender_wrap_secret,
        &input.recipient_key,
        codec::KEY_WRAP_PURPOSE,
        &codec::associated_data(&event, input.signer_endpoint_shared_id),
        &event.nonce,
        &input.key_secret,
    )?;
    event.ciphertext = ciphertext
        .try_into()
        .map_err(|_| "key wrap ciphertext length mismatch".to_string())?;

    let payload = codec::encode(&event);
    let envelope = codec::sign(
        input.signer_endpoint_shared_id,
        &input.signer_private_key,
        payload,
    );
    let bytes = codec::encode_signed(&envelope);
    let record = codec::signed_record_from_bytes(bytes)?;
    let value = KeyWrapOutput {
        key_wrap_id: event_id(&record.canonical_bytes),
        workspace_id: event.workspace_id,
        removal_frontier_id: event.removal_frontier_id,
        local_key_secret_id: event.local_key_secret_id,
        recipient_key_id: event.recipient_key_id,
    };
    Ok(CommandOutput::with_events(value, vec![record]))
}

fn validate_secret_commitment(input: &CreateKeyWrap) -> Result<(), String> {
    let output = local_key_secret::commands::from_key_secret(
        input.workspace_id,
        input.removal_frontier_id,
        input.key_secret,
    )?;
    if output.value.local_key_secret_id != input.local_key_secret_id {
        return Err("key wrap local_key_secret_id does not match key secret".to_string());
    }
    Ok(())
}

fn validate_id(name: &str, id: &EventId) -> Result<(), String> {
    if id.iter().all(|byte| *byte == 0) {
        return Err(format!("{name} cannot be empty"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::encryption::local_recipient_key;
    use crate::protocol::event_modules::types::EventScope;

    use super::*;

    #[test]
    fn create_proposes_signed_shared_key_wrap_without_local_secret_dep() {
        let local_secret = local_key_secret::commands::from_key_secret([1; 32], [2; 32], [7; 32])
            .expect("local")
            .value;
        let recipient = local_recipient_key::commands::create([1; 32])
            .expect("recipient")
            .value;
        let output = create(CreateKeyWrap {
            workspace_id: [1; 32],
            created_at_ms: 10,
            signer_endpoint_shared_id: [3; 32],
            signer_private_key: [9; 32],
            removal_frontier_id: [2; 32],
            local_key_secret_id: local_secret.local_key_secret_id,
            key_secret: local_secret.event.key_secret,
            recipient_key_id: [4; 32],
            recipient_key: recipient.recipient_key,
        })
        .expect("create wrap");

        assert_eq!(output.events.len(), 1);
        let record = output.events[0].record();
        assert_eq!(record.scope, EventScope::Shared);
        assert_eq!(record.workspace_id, Some([1; 32]));
        assert_eq!(
            record.dependencies,
            vec![[3; 32], [1; 32], [2; 32], [4; 32]]
        );
        assert!(!record
            .dependencies
            .contains(&local_secret.local_key_secret_id));
    }

    #[test]
    fn create_rejects_secret_commitment_mismatch() {
        let recipient = local_recipient_key::commands::create([1; 32])
            .expect("recipient")
            .value;
        let err = create(CreateKeyWrap {
            workspace_id: [1; 32],
            created_at_ms: 10,
            signer_endpoint_shared_id: [3; 32],
            signer_private_key: [9; 32],
            removal_frontier_id: [2; 32],
            local_key_secret_id: [8; 32],
            key_secret: [7; 32],
            recipient_key_id: [4; 32],
            recipient_key: recipient.recipient_key,
        })
        .expect_err("mismatch must fail");

        assert_eq!(
            err,
            "key wrap local_key_secret_id does not match key secret"
        );
    }
}

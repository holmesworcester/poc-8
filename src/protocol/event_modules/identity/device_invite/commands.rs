//! Commands for creating device-invite events.
//!
//! The shared payload carries the invite public key plus the workspace/user
//! authority it binds. It is signed by either the user identity or by an
//! existing endpoint-shared event for the same workspace/user. The invite
//! private key is returned to the caller as invite material so a later
//! endpoint-shared command can produce a real signed envelope.

use crate::core::crypto::{self, Ed25519PrivateKey};
use crate::protocol::event_modules::identity::signed;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::{CommandOutput, ProposedEvent};

use super::codec;
use super::types::{DeviceInviteEvent, DeviceInviteKeypair};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateDeviceInvite {
    pub created_at_ms: u64,
    pub workspace_id: EventId,
    pub user_authority_event_id: EventId,
    pub user_invite_event_id: Option<EventId>,
    pub signer_event_id: EventId,
    pub signer_private_key: Ed25519PrivateKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateDeviceInviteOutput {
    pub device_invite_id: EventId,
    pub keypair: DeviceInviteKeypair,
}

pub fn create(
    input: CreateDeviceInvite,
) -> Result<CommandOutput<CreateDeviceInviteOutput>, String> {
    create_with_private_key(input, random_private_key())
}

pub fn create_with_private_key(
    input: CreateDeviceInvite,
    private_key: Ed25519PrivateKey,
) -> Result<CommandOutput<CreateDeviceInviteOutput>, String> {
    validate_id("workspace_id", &input.workspace_id)?;
    validate_id("user_authority_event_id", &input.user_authority_event_id)?;
    validate_id("signer_event_id", &input.signer_event_id)?;
    if let Some(user_invite_event_id) = input.user_invite_event_id {
        validate_id("user_invite_event_id", &user_invite_event_id)?;
    }

    let public_key = crypto::ed25519_public_key(&private_key);
    let event = DeviceInviteEvent {
        created_at_ms: input.created_at_ms,
        workspace_id: input.workspace_id,
        user_authority_event_id: input.user_authority_event_id,
        user_invite_event_id: input.user_invite_event_id,
        public_key,
    };
    let signed = signed::commands::sign_payload(
        input.signer_event_id,
        &input.signer_private_key,
        codec::encode(&event),
    )?;
    let bytes = signed::codec::encode(&signed.value);
    let proposed = ProposedEvent::new(codec::record_from_signed_bytes(bytes)?);
    let device_invite_id = proposed.event_id();

    Ok(CommandOutput::with_proposed_events(
        CreateDeviceInviteOutput {
            device_invite_id,
            keypair: DeviceInviteKeypair {
                public_key,
                private_key,
            },
        },
        vec![proposed],
    ))
}

fn random_private_key() -> Ed25519PrivateKey {
    crypto::random_ed25519_private_key()
}

fn validate_id(name: &str, id: &EventId) -> Result<(), String> {
    if id.iter().all(|byte| *byte == 0) {
        return Err(format!("{name} cannot be empty"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::types::{event_id, EventScope};

    use super::*;

    fn input() -> CreateDeviceInvite {
        CreateDeviceInvite {
            created_at_ms: 55,
            workspace_id: [1; 32],
            user_authority_event_id: [2; 32],
            user_invite_event_id: Some([4; 32]),
            signer_event_id: [2; 32],
            signer_private_key: [8; crypto::ED25519_PRIVATE_KEY_BYTES],
        }
    }

    // Invariant: create returns invite keypair and signed shared event.
    #[test]
    fn create_returns_invite_keypair_and_signed_shared_event() {
        let private_key = [7; crypto::ED25519_PRIVATE_KEY_BYTES];
        let output = create_with_private_key(input(), private_key).expect("create device invite");

        assert_eq!(output.events.len(), 1);
        assert_eq!(
            output.value.keypair.public_key,
            crypto::ed25519_public_key(&private_key)
        );
        assert_eq!(output.value.keypair.private_key, private_key);

        let proposed = &output.events[0];
        assert_eq!(output.value.device_invite_id, proposed.event_id());
        assert_eq!(
            proposed.event_id(),
            event_id(&proposed.record().canonical_bytes)
        );
        assert_eq!(proposed.record().scope, EventScope::Shared);
        assert_eq!(
            proposed.record().dependencies,
            vec![[2; 32], [1; 32], [4; 32]]
        );

        let envelope = signed::codec::decode(&proposed.record().canonical_bytes)
            .expect("decode signed device invite");
        assert_eq!(envelope.signer_event_id, [2; 32]);
        assert_eq!(
            envelope.signer_public_key,
            crypto::ed25519_public_key(&[8; crypto::ED25519_PRIVATE_KEY_BYTES])
        );
        assert_eq!(envelope.inner_type, codec::TYPE_DEVICE_INVITE);

        let decoded = codec::decode(&envelope.payload).expect("decode device invite");
        assert_eq!(decoded.created_at_ms, 55);
        assert_eq!(decoded.workspace_id, [1; 32]);
        assert_eq!(decoded.user_authority_event_id, [2; 32]);
        assert_eq!(decoded.user_invite_event_id, Some([4; 32]));
        assert_eq!(decoded.public_key, output.value.keypair.public_key);
    }

    // Invariant: create can use endpoint shared signer without user invite dependency.
    #[test]
    fn create_can_use_endpoint_shared_signer_without_user_invite_dependency() {
        let private_key = [7; crypto::ED25519_PRIVATE_KEY_BYTES];
        let signer_private_key = [9; crypto::ED25519_PRIVATE_KEY_BYTES];
        let output = create_with_private_key(
            CreateDeviceInvite {
                user_invite_event_id: None,
                signer_event_id: [6; 32],
                signer_private_key,
                ..input()
            },
            private_key,
        )
        .expect("create device invite");

        assert_eq!(
            output.events[0].record().dependencies,
            vec![[6; 32], [1; 32], [2; 32]]
        );
        let envelope = signed::codec::decode(&output.events[0].record().canonical_bytes)
            .expect("decode signed device invite");
        assert_eq!(envelope.signer_event_id, [6; 32]);
        assert_eq!(
            envelope.signer_public_key,
            crypto::ed25519_public_key(&signer_private_key)
        );
        assert_eq!(
            codec::decode(&envelope.payload)
                .expect("payload")
                .user_invite_event_id,
            None
        );
    }

    // Invariant: create rejects empty workspace user authority or signer.
    #[test]
    fn create_rejects_empty_workspace_user_authority_or_signer() {
        let private_key = [7; crypto::ED25519_PRIVATE_KEY_BYTES];

        let err = create_with_private_key(
            CreateDeviceInvite {
                workspace_id: [0; 32],
                ..input()
            },
            private_key,
        )
        .expect_err("empty workspace must fail");
        assert_eq!(err, "workspace_id cannot be empty");

        let err = create_with_private_key(
            CreateDeviceInvite {
                user_authority_event_id: [0; 32],
                ..input()
            },
            private_key,
        )
        .expect_err("empty authority must fail");
        assert_eq!(err, "user_authority_event_id cannot be empty");

        let err = create_with_private_key(
            CreateDeviceInvite {
                signer_event_id: [0; 32],
                ..input()
            },
            private_key,
        )
        .expect_err("empty signer must fail");
        assert_eq!(err, "signer_event_id cannot be empty");

        let err = create_with_private_key(
            CreateDeviceInvite {
                user_invite_event_id: Some([0; 32]),
                ..input()
            },
            private_key,
        )
        .expect_err("empty user invite must fail");
        assert_eq!(err, "user_invite_event_id cannot be empty");
    }
}

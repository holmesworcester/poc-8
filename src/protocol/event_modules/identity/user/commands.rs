//! Commands for creating signed users.

use crate::core::crypto::{Ed25519PrivateKey, Ed25519PublicKey};
use crate::protocol::event_modules::identity::signed;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::CommandOutput;

use super::{codec, types::UserEvent};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateUser {
    pub created_at_ms: u64,
    pub workspace_id: EventId,
    pub public_key: Ed25519PublicKey,
    pub username: String,
    pub user_invite_event_id: EventId,
    pub user_invite_private_key: Ed25519PrivateKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateUserOutput {
    pub user_id: EventId,
    pub public_key: Ed25519PublicKey,
    pub username: String,
}

pub fn create(input: CreateUser) -> Result<CommandOutput<CreateUserOutput>, String> {
    if input.username.trim().is_empty() {
        return Err("username must not be empty".to_string());
    }
    let event = UserEvent {
        created_at_ms: input.created_at_ms,
        workspace_id: input.workspace_id,
        public_key: input.public_key,
        username: input.username,
    };
    let signed = signed::commands::sign_payload(
        input.user_invite_event_id,
        &input.user_invite_private_key,
        codec::encode(&event)?,
    )?;
    let user_id = signed.events[0].event_id();
    Ok(CommandOutput::with_proposed_events(
        CreateUserOutput {
            user_id,
            public_key: event.public_key,
            username: event.username,
        },
        signed.events,
    ))
}

#[cfg(test)]
mod tests {
    use crate::core::crypto;
    use crate::protocol::event_modules::types::event_id;

    use super::*;

    // Invariant: create returns signed user with user invite dependency.
    #[test]
    fn create_returns_signed_user_with_user_invite_dependency() {
        let invite_id = [2; 32];
        let invite_private_key = [8; 32];
        let user_public_key = crypto::ed25519_public_key(&[9; 32]);
        let output = create(CreateUser {
            created_at_ms: 12,
            workspace_id: [1; 32],
            public_key: user_public_key,
            username: "alice".to_string(),
            user_invite_event_id: invite_id,
            user_invite_private_key: invite_private_key,
        })
        .expect("create user");

        assert_eq!(output.events.len(), 1);
        let proposed = &output.events[0];
        assert_eq!(output.value.user_id, proposed.event_id());
        assert_eq!(
            proposed.event_id(),
            event_id(&proposed.record().canonical_bytes)
        );
        assert_eq!(proposed.record().dependencies, vec![invite_id, [1; 32]]);

        let envelope = crate::protocol::event_modules::identity::signed::codec::decode(
            &proposed.record().canonical_bytes,
        )
        .expect("decode signed envelope");
        assert_eq!(envelope.signer_event_id, invite_id);
        assert_eq!(envelope.inner_type, codec::TYPE_USER);

        let decoded = codec::decode(&envelope.payload).expect("decode user payload");
        assert_eq!(decoded.created_at_ms, 12);
        assert_eq!(decoded.workspace_id, [1; 32]);
        assert_eq!(decoded.public_key, user_public_key);
        assert_eq!(decoded.username, "alice");
    }

    // Invariant: create rejects blank username before proposing event.
    #[test]
    fn create_rejects_blank_username_before_proposing_event() {
        let err = create(CreateUser {
            created_at_ms: 12,
            workspace_id: [1; 32],
            public_key: crypto::ed25519_public_key(&[9; 32]),
            username: " ".to_string(),
            user_invite_event_id: [2; 32],
            user_invite_private_key: [8; 32],
        })
        .expect_err("blank username must fail");

        assert_eq!(err, "username must not be empty");
    }
}

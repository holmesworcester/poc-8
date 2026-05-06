//! Commands for creating admin grant events.
//!
//! The direct admin commands create canonical admin events with explicit
//! workspace, authority, and user binding inputs. Only the workspace-root
//! bootstrap grant uses workspace authority; all admin grants are signed.

use crate::core::crypto::Ed25519PrivateKey;
use crate::protocol::event_modules::identity::signed;
use crate::protocol::event_modules::types::{event_id, EventId};
use crate::protocol::event_modules::worker::CommandOutput;

use super::super::workspace::types::WorkspaceId;
use super::codec;
use super::types::{AdminEvent, AdminPublicKey, UserId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateBootstrapAdmin {
    pub created_at_ms: u64,
    pub workspace_id: WorkspaceId,
    pub root_public_key: AdminPublicKey,
    pub root_user_event_id: UserId,
    pub signer_private_key: Ed25519PrivateKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantAdmin {
    pub created_at_ms: u64,
    pub workspace_id: WorkspaceId,
    pub authority_admin_id: EventId,
    pub target_user_event_id: UserId,
    pub target_user_public_key: AdminPublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignGrantAdmin {
    pub grant: GrantAdmin,
    pub signer_event_id: EventId,
    pub signer_private_key: Ed25519PrivateKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminCommandOutput {
    pub admin_id: EventId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAdminCommandOutput {
    pub inner_admin_id: EventId,
    pub signed_event_id: EventId,
}

pub fn create_bootstrap(
    input: CreateBootstrapAdmin,
) -> Result<CommandOutput<AdminCommandOutput>, String> {
    let event = AdminEvent {
        created_at_ms: input.created_at_ms,
        workspace_id: input.workspace_id,
        public_key: input.root_public_key,
        authority_event_id: input.workspace_id,
        user_event_id: input.root_user_event_id,
    };
    let signed = signed::commands::sign_payload(
        input.workspace_id,
        &input.signer_private_key,
        codec::encode(&event),
    )?;
    Ok(CommandOutput::with_proposed_events(
        AdminCommandOutput {
            admin_id: signed.events[0].event_id(),
        },
        signed.events,
    ))
}

pub fn grant(input: GrantAdmin) -> Result<CommandOutput<AdminCommandOutput>, String> {
    if input.authority_admin_id == input.workspace_id {
        return Err("ongoing admin grant authority must be an admin event".to_string());
    }
    Err("ongoing admin grants must be signed by authority admin".to_string())
}

pub fn sign_grant(
    input: SignGrantAdmin,
) -> Result<CommandOutput<SignedAdminCommandOutput>, String> {
    if input.grant.authority_admin_id == input.grant.workspace_id {
        return Err("ongoing admin grant authority must be an admin event".to_string());
    }
    if input.signer_event_id != input.grant.authority_admin_id {
        return Err("signed admin grant signer must be the authority admin".to_string());
    }
    let event = admin_event_from_grant(input.grant);
    let payload = codec::encode(&event);
    let inner_admin_id = event_id(&payload);
    let signed =
        signed::commands::sign_payload(input.signer_event_id, &input.signer_private_key, payload)?;
    let signed_event_id = signed.events[0].event_id();
    Ok(CommandOutput::with_proposed_events(
        SignedAdminCommandOutput {
            inner_admin_id,
            signed_event_id,
        },
        signed.events,
    ))
}

fn admin_event_from_grant(input: GrantAdmin) -> AdminEvent {
    AdminEvent {
        created_at_ms: input.created_at_ms,
        workspace_id: input.workspace_id,
        public_key: input.target_user_public_key,
        authority_event_id: input.authority_admin_id,
        user_event_id: input.target_user_event_id,
    }
}

#[cfg(test)]
mod tests {
    use crate::core::crypto;
    use crate::protocol::event_modules::identity::signed;
    use crate::protocol::event_modules::types::EventScope;

    use super::*;

    // Invariant: bootstrap command proposes workspace signed admin event.
    #[test]
    fn bootstrap_command_proposes_workspace_signed_admin_event() {
        let signer_private_key = [7; crypto::ED25519_PRIVATE_KEY_BYTES];
        let signer_public_key = crypto::ed25519_public_key(&signer_private_key);
        let output = create_bootstrap(CreateBootstrapAdmin {
            created_at_ms: 70,
            workspace_id: [1; 32],
            root_public_key: signer_public_key,
            root_user_event_id: [1; 32],
            signer_private_key,
        })
        .expect("create bootstrap admin");

        assert_eq!(output.events.len(), 1);
        let proposed = &output.events[0];
        assert_eq!(output.value.admin_id, proposed.event_id());
        assert_eq!(
            proposed.event_id(),
            event_id(&proposed.record().canonical_bytes)
        );
        assert_eq!(proposed.record().dependencies, vec![[1; 32]]);
        assert_eq!(proposed.record().scope, EventScope::Shared);

        let envelope = signed::codec::decode(&proposed.record().canonical_bytes)
            .expect("decode signed bootstrap admin");
        assert_eq!(envelope.signer_event_id, [1; 32]);
        assert_eq!(envelope.signer_public_key, signer_public_key);
        assert_eq!(envelope.inner_type, codec::TYPE_ADMIN);
        let event = codec::decode(&envelope.payload).expect("decode admin");
        assert_eq!(event.created_at_ms, 70);
        assert_eq!(event.workspace_id, [1; 32]);
        assert_eq!(event.public_key, signer_public_key);
        assert_eq!(event.authority_event_id, [1; 32]);
        assert_eq!(event.user_event_id, [1; 32]);
    }

    // Invariant: grant command rejects unsigned ongoing admin grants.
    #[test]
    fn grant_command_rejects_unsigned_ongoing_admin_grants() {
        let err = grant(GrantAdmin {
            created_at_ms: 80,
            workspace_id: [1; 32],
            authority_admin_id: [9; 32],
            target_user_event_id: [5; 32],
            target_user_public_key: [6; 32],
        })
        .expect_err("unsigned ongoing grant must fail");

        assert_eq!(
            err,
            "ongoing admin grants must be signed by authority admin"
        );
    }

    // Invariant: grant rejects workspace authority so bootstrap shape stays explicit.
    #[test]
    fn grant_rejects_workspace_authority_so_bootstrap_shape_stays_explicit() {
        let err = grant(GrantAdmin {
            created_at_ms: 80,
            workspace_id: [1; 32],
            authority_admin_id: [1; 32],
            target_user_event_id: [5; 32],
            target_user_public_key: [6; 32],
        })
        .expect_err("workspace authority grant must fail");

        assert_eq!(err, "ongoing admin grant authority must be an admin event");
    }

    // Invariant: sign grant uses real signed envelope with inner dependencies.
    #[test]
    fn sign_grant_uses_real_signed_envelope_with_inner_dependencies() {
        let signer_private_key = [7; crypto::ED25519_PRIVATE_KEY_BYTES];
        let output = sign_grant(SignGrantAdmin {
            grant: GrantAdmin {
                created_at_ms: 90,
                workspace_id: [1; 32],
                authority_admin_id: [9; 32],
                target_user_event_id: [5; 32],
                target_user_public_key: [6; 32],
            },
            signer_event_id: [9; 32],
            signer_private_key,
        })
        .expect("sign grant");

        assert_eq!(output.events.len(), 1);
        let record = output.events[0].record();
        assert_eq!(record.dependencies, vec![[9; 32], [1; 32], [5; 32]]);
        assert_eq!(output.value.signed_event_id, output.events[0].event_id());

        let envelope =
            signed::codec::decode(&record.canonical_bytes).expect("decode signed envelope");
        assert_eq!(envelope.signer_event_id, [9; 32]);
        assert_eq!(envelope.inner_type, codec::TYPE_ADMIN);
        assert_eq!(output.value.inner_admin_id, event_id(&envelope.payload));
        assert_eq!(
            signed::codec::record_from_bytes(record.canonical_bytes.clone())
                .expect("signed record")
                .dependencies,
            vec![[9; 32], [1; 32], [5; 32]]
        );
    }

    // Invariant: sign grant rejects signer that is not authority admin.
    #[test]
    fn sign_grant_rejects_signer_that_is_not_authority_admin() {
        let err = sign_grant(SignGrantAdmin {
            grant: GrantAdmin {
                created_at_ms: 90,
                workspace_id: [1; 32],
                authority_admin_id: [9; 32],
                target_user_event_id: [5; 32],
                target_user_public_key: [6; 32],
            },
            signer_event_id: [8; 32],
            signer_private_key: [7; crypto::ED25519_PRIVATE_KEY_BYTES],
        })
        .expect_err("wrong signer must fail");

        assert_eq!(err, "signed admin grant signer must be the authority admin");
    }
}

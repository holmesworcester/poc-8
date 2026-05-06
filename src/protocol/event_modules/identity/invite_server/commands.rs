//! Commands for creating signed invite-server invites.

use crate::core::crypto::{Ed25519PrivateKey, Ed25519PublicKey};
use crate::protocol::event_modules::identity::signed;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::CommandOutput;

use super::{codec, types::InviteServerEvent};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateInviteServer {
    pub created_at_ms: u64,
    pub public_key: Ed25519PublicKey,
    pub workspace_id: EventId,
    pub authority_event_id: EventId,
    pub signer_event_id: EventId,
    pub signer_private_key: Ed25519PrivateKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateInviteServerOutput {
    pub invite_server_id: EventId,
    pub public_key: Ed25519PublicKey,
    pub workspace_id: EventId,
    pub authority_event_id: EventId,
}

pub fn create(
    input: CreateInviteServer,
) -> Result<CommandOutput<CreateInviteServerOutput>, String> {
    let event = InviteServerEvent {
        created_at_ms: input.created_at_ms,
        public_key: input.public_key,
        workspace_id: input.workspace_id,
        authority_event_id: input.authority_event_id,
    };
    let signed = signed::commands::sign_payload(
        input.signer_event_id,
        &input.signer_private_key,
        codec::encode(&event),
    )?;
    let invite_server_id = signed.events[0].event_id();
    Ok(CommandOutput::with_proposed_events(
        CreateInviteServerOutput {
            invite_server_id,
            public_key: event.public_key,
            workspace_id: event.workspace_id,
            authority_event_id: event.authority_event_id,
        },
        signed.events,
    ))
}

#[cfg(test)]
mod tests {
    use crate::core::crypto;
    use crate::protocol::event_modules::identity::signed;
    use crate::protocol::event_modules::types::event_id;

    use super::*;

    #[test]
    fn create_returns_signed_invite_server_with_signer_dependency() {
        let workspace_id = [2; 32];
        let signer_private_key = [7; 32];
        let invite_public_key = crypto::ed25519_public_key(&[8; 32]);
        let output = create(CreateInviteServer {
            created_at_ms: 11,
            public_key: invite_public_key,
            workspace_id,
            authority_event_id: workspace_id,
            signer_event_id: workspace_id,
            signer_private_key,
        })
        .expect("create invite_server");

        assert_eq!(output.events.len(), 1);
        let proposed = &output.events[0];
        assert_eq!(output.value.invite_server_id, proposed.event_id());
        assert_eq!(
            proposed.event_id(),
            event_id(&proposed.record().canonical_bytes)
        );
        assert_eq!(proposed.record().dependencies, vec![workspace_id]);

        let envelope = signed::codec::decode(&proposed.record().canonical_bytes)
            .expect("decode signed envelope");
        assert_eq!(envelope.signer_event_id, workspace_id);
        assert_eq!(envelope.inner_type, codec::TYPE_INVITE_SERVER);

        let decoded = codec::decode(&envelope.payload).expect("decode invite_server payload");
        assert_eq!(decoded.created_at_ms, 11);
        assert_eq!(decoded.public_key, invite_public_key);
        assert_eq!(decoded.workspace_id, workspace_id);
        assert_eq!(decoded.authority_event_id, workspace_id);
    }
}

//! Commands for creating signed endpoint-shared events.

use crate::core::crypto::Ed25519PrivateKey;
use crate::core::crypto::Ed25519PublicKey;
use crate::protocol::event_modules::identity::endpoint::types::EndpointId;
use crate::protocol::event_modules::identity::signed;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::CommandOutput;

use super::codec;
use super::types::EndpointSharedEvent;

pub trait EndpointMembershipRead {
    fn endpoint_membership(
        &self,
        endpoint_id: EndpointId,
        workspace_id: EventId,
    ) -> Result<Option<Vec<u8>>, String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareEndpoint {
    pub created_at_ms: u64,
    pub workspace_id: EventId,
    pub user_authority_event_id: EventId,
    pub endpoint_id: EndpointId,
    pub signing_public_key: Ed25519PublicKey,
    pub device_name: String,
    pub device_invite_id: EventId,
    pub device_invite_private_key: Ed25519PrivateKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareEndpointOutput {
    pub endpoint_shared_id: EventId,
}

pub fn share_endpoint(
    context: &impl EndpointMembershipRead,
    input: ShareEndpoint,
) -> Result<CommandOutput<ShareEndpointOutput>, String> {
    validate_id("workspace_id", &input.workspace_id)?;
    validate_id("user_authority_event_id", &input.user_authority_event_id)?;
    validate_id("endpoint_id", &input.endpoint_id)?;
    validate_id("signing_public_key", &input.signing_public_key)?;
    validate_id("device_invite_id", &input.device_invite_id)?;

    if context
        .endpoint_membership(input.endpoint_id, input.workspace_id)?
        .is_some()
    {
        return Err("endpoint is already joined to workspace".to_string());
    }

    let payload = codec::encode(&EndpointSharedEvent {
        created_at_ms: input.created_at_ms,
        workspace_id: input.workspace_id,
        user_authority_event_id: input.user_authority_event_id,
        endpoint_id: input.endpoint_id,
        signing_public_key: input.signing_public_key,
        device_name: input.device_name,
    })?;
    let signed = signed::commands::sign_payload(
        input.device_invite_id,
        &input.device_invite_private_key,
        payload,
    )?;
    let mut events = signed.events;
    let endpoint_shared_id = events
        .first()
        .ok_or_else(|| "signed endpoint_shared command produced no event".to_string())?
        .event_id();

    Ok(CommandOutput::with_proposed_events(
        ShareEndpointOutput { endpoint_shared_id },
        std::mem::take(&mut events),
    ))
}

fn validate_id(name: &str, id: &EventId) -> Result<(), String> {
    if id.iter().all(|byte| *byte == 0) {
        return Err(format!("{name} cannot be empty"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::core::crypto::{self, ED25519_PRIVATE_KEY_BYTES};
    use crate::protocol::event_modules::identity::device_invite;
    use crate::protocol::event_modules::types::{event_id, EventScope};

    use super::*;

    #[derive(Default)]
    struct ReadContext {
        membership: Option<Vec<u8>>,
    }

    impl EndpointMembershipRead for ReadContext {
        fn endpoint_membership(
            &self,
            _endpoint_id: EndpointId,
            _workspace_id: EventId,
        ) -> Result<Option<Vec<u8>>, String> {
            Ok(self.membership.clone())
        }
    }

    fn share_input(device_invite_id: EventId, private_key: Ed25519PrivateKey) -> ShareEndpoint {
        ShareEndpoint {
            created_at_ms: 88,
            workspace_id: [1; 32],
            user_authority_event_id: [2; 32],
            endpoint_id: [3; 32],
            signing_public_key: [4; 32],
            device_name: "laptop".to_string(),
            device_invite_id,
            device_invite_private_key: private_key,
        }
    }

    // Invariant: share endpoint returns signed event depending on device invite.
    #[test]
    fn share_endpoint_returns_signed_event_depending_on_device_invite() {
        let private_key = [7; ED25519_PRIVATE_KEY_BYTES];
        let device_invite = device_invite::commands::create_with_private_key(
            device_invite::commands::CreateDeviceInvite {
                created_at_ms: 70,
                workspace_id: [1; 32],
                user_authority_event_id: [2; 32],
                user_invite_event_id: Some([5; 32]),
                signer_event_id: [2; 32],
                signer_private_key: [8; ED25519_PRIVATE_KEY_BYTES],
            },
            private_key,
        )
        .expect("create device invite");
        let output = share_endpoint(
            &ReadContext::default(),
            share_input(device_invite.value.device_invite_id, private_key),
        )
        .expect("share endpoint");

        assert_eq!(output.events.len(), 1);
        let proposed = &output.events[0];
        assert_eq!(output.value.endpoint_shared_id, proposed.event_id());
        assert_eq!(
            proposed.event_id(),
            event_id(&proposed.record().canonical_bytes)
        );
        assert_eq!(proposed.record().scope, EventScope::Shared);
        assert_eq!(
            proposed.record().dependencies,
            vec![device_invite.value.device_invite_id, [1; 32], [2; 32]]
        );

        let envelope =
            signed::codec::decode(&proposed.record().canonical_bytes).expect("signed envelope");
        assert_eq!(
            envelope.signer_event_id,
            device_invite.value.device_invite_id
        );
        assert_eq!(
            envelope.signer_public_key,
            crypto::ed25519_public_key(&private_key)
        );
        assert_eq!(envelope.inner_type, codec::TYPE_ENDPOINT_SHARED);

        let inner = codec::decode(&envelope.payload).expect("endpoint shared payload");
        assert_eq!(inner.workspace_id, [1; 32]);
        assert_eq!(inner.user_authority_event_id, [2; 32]);
        assert_eq!(inner.endpoint_id, [3; 32]);
        assert_eq!(inner.signing_public_key, [4; 32]);
        assert_eq!(inner.device_name, "laptop");
    }

    // Invariant: share endpoint rejects duplicate membership preflight.
    #[test]
    fn share_endpoint_rejects_duplicate_membership_preflight() {
        let err = share_endpoint(
            &ReadContext {
                membership: Some(vec![1]),
            },
            share_input([4; 32], [7; ED25519_PRIVATE_KEY_BYTES]),
        )
        .expect_err("duplicate membership must fail");

        assert_eq!(err, "endpoint is already joined to workspace");
    }

    // Invariant: share endpoint rejects empty ids and bad device name.
    #[test]
    fn share_endpoint_rejects_empty_ids_and_bad_device_name() {
        let err = share_endpoint(
            &ReadContext::default(),
            ShareEndpoint {
                workspace_id: [0; 32],
                ..share_input([4; 32], [7; ED25519_PRIVATE_KEY_BYTES])
            },
        )
        .expect_err("empty workspace must fail");
        assert_eq!(err, "workspace_id cannot be empty");

        let err = share_endpoint(
            &ReadContext::default(),
            ShareEndpoint {
                device_name: "bad\0name".to_string(),
                ..share_input([4; 32], [7; ED25519_PRIVATE_KEY_BYTES])
            },
        )
        .expect_err("bad name must fail");
        assert_eq!(err, "endpoint device name cannot contain NUL");
    }
}

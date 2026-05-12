//! Projector for signed endpoint-shared events.
//!
//! The common worker admits the signed envelope and supplies its signer
//! dependency. Projection validates that the signer dependency is the matching
//! signed device invite, then writes the shared endpoint row plus the local
//! membership index used by duplicate-join preflight.
//!
//! Endpoint joins are one-workspace facts. The device invite key authorizes one
//! endpoint_shared event for one user authority in one workspace; projection
//! re-checks all three bindings before writing the endpoint membership row that
//! later gates connection ingress and sync.

use crate::protocol::event_modules::identity::{
    device_invite, endpoint::types::EndpointRole, invite_server, signed,
};
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::{codec, schema};

pub fn project_signed(
    envelope: &signed::types::SignedEnvelope,
    event: &EventWithContext<'_>,
) -> Result<ProjectionOutput, String> {
    let endpoint_shared = codec::decode(&envelope.payload)?;
    if endpoint_shared.endpoint_id.iter().all(|byte| *byte == 0) {
        return Err("endpoint_shared endpoint_id cannot be empty".to_string());
    }
    if endpoint_shared
        .signing_public_key
        .iter()
        .all(|byte| *byte == 0)
    {
        return Err("endpoint_shared signing_public_key cannot be empty".to_string());
    }
    let signer = event
        .context
        .dependency(&envelope.signer_event_id)
        .ok_or_else(|| "endpoint_shared invite dependency is missing".to_string())?;
    let invite_envelope = signed::codec::decode(&signer.canonical_bytes)
        .map_err(|_| "endpoint_shared dependency is not a signed endpoint invite".to_string())?;
    let expected_role = match invite_envelope.inner_type {
        device_invite::codec::TYPE_DEVICE_INVITE => {
            validate_device_invite_authority(envelope, &invite_envelope, &endpoint_shared)?
        }
        invite_server::codec::TYPE_INVITE_SERVER => {
            validate_invite_server_authority(envelope, &invite_envelope, &endpoint_shared)?
        }
        _ => return Err("endpoint_shared dependency is not a signed endpoint invite".to_string()),
    };
    if endpoint_shared.endpoint_role != expected_role {
        return Err("endpoint_shared role does not match invite authority".to_string());
    }

    Ok(ProjectionOutput::rows(schema::endpoint_shared_rows(
        event.context.event_id,
        envelope.signer_event_id,
        &endpoint_shared,
    )?))
}

fn validate_device_invite_authority(
    envelope: &signed::types::SignedEnvelope,
    invite_envelope: &signed::types::SignedEnvelope,
    endpoint_shared: &super::types::EndpointSharedEvent,
) -> Result<EndpointRole, String> {
    let invite = device_invite::codec::decode(&invite_envelope.payload)
        .map_err(|_| "endpoint_shared dependency is not a signed endpoint invite".to_string())?;
    if invite.public_key != envelope.signer_public_key {
        return Err("endpoint_shared signer public key does not match device_invite".to_string());
    }
    if invite.workspace_id != endpoint_shared.workspace_id {
        return Err("endpoint_shared workspace does not match device_invite".to_string());
    }
    if invite.user_authority_event_id != endpoint_shared.user_authority_event_id {
        return Err("endpoint_shared user authority does not match device_invite".to_string());
    }
    Ok(EndpointRole::Device)
}

fn validate_invite_server_authority(
    envelope: &signed::types::SignedEnvelope,
    invite_envelope: &signed::types::SignedEnvelope,
    endpoint_shared: &super::types::EndpointSharedEvent,
) -> Result<EndpointRole, String> {
    let invite = invite_server::codec::decode(&invite_envelope.payload)
        .map_err(|_| "endpoint_shared dependency is not a signed endpoint invite".to_string())?;
    if invite.public_key != envelope.signer_public_key {
        return Err("endpoint_shared signer public key does not match invite_server".to_string());
    }
    if invite.workspace_id != endpoint_shared.workspace_id {
        return Err("endpoint_shared workspace does not match invite_server".to_string());
    }
    if envelope.signer_event_id != endpoint_shared.user_authority_event_id {
        return Err("endpoint_shared user authority does not match invite_server".to_string());
    }
    Ok(EndpointRole::InviteServer)
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::identity::endpoint_shared::commands;
    use crate::protocol::event_modules::types::event_id;
    use crate::protocol::event_modules::worker::{
        DependencyContext, EventContext, EventWithContext,
    };

    use super::*;

    #[derive(Default)]
    struct ReadContext;

    impl commands::EndpointMembershipRead for ReadContext {
        fn endpoint_membership(
            &self,
            _endpoint_id: crate::protocol::event_modules::identity::endpoint::types::EndpointId,
            _workspace_id: [u8; 32],
        ) -> Result<Option<Vec<u8>>, String> {
            Ok(None)
        }
    }

    fn public_key(private_key: &[u8; 32]) -> [u8; 32] {
        signed::commands::sign_payload([0; 32], private_key, vec![99])
            .expect("derive public key")
            .value
            .signer_public_key
    }

    fn device_invite_record(
        private_key: [u8; 32],
        workspace_id: [u8; 32],
        user_authority_event_id: [u8; 32],
    ) -> ([u8; 32], crate::protocol::event_modules::types::EventRecord) {
        let output = device_invite::commands::create_with_private_key(
            device_invite::commands::CreateDeviceInvite {
                created_at_ms: 10,
                workspace_id,
                user_authority_event_id,
                user_invite_event_id: Some([6; 32]),
                signer_event_id: user_authority_event_id,
                signer_private_key: [11; 32],
            },
            private_key,
        )
        .expect("create device invite");
        let record = output.events[0].record().clone();
        (output.value.device_invite_id, record)
    }

    fn signed_endpoint_shared_record(
        device_invite_id: [u8; 32],
        private_key: [u8; 32],
        workspace_id: [u8; 32],
        user_authority_event_id: [u8; 32],
    ) -> (
        [u8; 32],
        crate::protocol::event_modules::types::EventRecord,
        signed::types::SignedEnvelope,
    ) {
        let output = commands::share_endpoint(
            &ReadContext,
            commands::ShareEndpoint {
                created_at_ms: 20,
                workspace_id,
                user_authority_event_id,
                endpoint_id: [3; 32],
                signing_public_key: [4; 32],
                endpoint_role: EndpointRole::Device,
                device_name: "phone".to_string(),
                device_invite_id,
                device_invite_private_key: private_key,
            },
        )
        .expect("share endpoint");
        let record = output.events[0].record().clone();
        let envelope = signed::codec::decode(&record.canonical_bytes).expect("signed envelope");
        (output.value.endpoint_shared_id, record, envelope)
    }

    fn signed_context<'a>(
        endpoint_shared_id: [u8; 32],
        record: &'a crate::protocol::event_modules::types::EventRecord,
        device_invite_id: [u8; 32],
        device_invite_record: crate::protocol::event_modules::types::EventRecord,
    ) -> EventWithContext<'a> {
        EventWithContext {
            record,
            context: EventContext {
                event_id: endpoint_shared_id,
                dependencies: vec![DependencyContext {
                    event_id: device_invite_id,
                    record: device_invite_record,
                }],
                labels: Vec::new(),
                receive: None,
            },
        }
    }

    #[test]
    fn projects_endpoint_shared_and_membership_rows_from_signed_device_invite() {
        let (device_invite_id, invite_record) = device_invite_record([7; 32], [1; 32], [2; 32]);
        let (endpoint_shared_id, record, envelope) =
            signed_endpoint_shared_record(device_invite_id, [7; 32], [1; 32], [2; 32]);
        let event = signed_context(endpoint_shared_id, &record, device_invite_id, invite_record);

        let output = project_signed(&envelope, &event).expect("project endpoint shared");

        assert_eq!(output.labels.len(), 0);
        assert_eq!(output.rows.len(), 2);
        assert_eq!(output.rows[0].table, schema::ENDPOINT_SHARED);
        assert_eq!(
            output.rows[0].key,
            schema::endpoint_shared_key([1; 32], endpoint_shared_id)
        );
        assert_eq!(output.rows[1].table, schema::ENDPOINT_MEMBERSHIPS);
        assert_eq!(
            output.rows[1].key,
            schema::endpoint_membership_key([3; 32], [1; 32])
        );
    }

    #[test]
    fn rejects_when_device_invite_dependency_is_missing() {
        let (device_invite_id, _) = device_invite_record([7; 32], [1; 32], [2; 32]);
        let (endpoint_shared_id, record, envelope) =
            signed_endpoint_shared_record(device_invite_id, [7; 32], [1; 32], [2; 32]);
        let event = EventWithContext {
            record: &record,
            context: EventContext {
                event_id: endpoint_shared_id,
                dependencies: Vec::new(),
                labels: Vec::new(),
                receive: None,
            },
        };

        assert_eq!(
            project_signed(&envelope, &event).expect_err("missing dependency must fail"),
            "endpoint_shared invite dependency is missing"
        );
    }

    #[test]
    fn rejects_signer_public_key_mismatch() {
        let (device_invite_id, invite_record) = device_invite_record([7; 32], [1; 32], [2; 32]);
        let (endpoint_shared_id, record, envelope) =
            signed_endpoint_shared_record(device_invite_id, [8; 32], [1; 32], [2; 32]);
        let event = signed_context(endpoint_shared_id, &record, device_invite_id, invite_record);

        assert_eq!(
            project_signed(&envelope, &event).expect_err("wrong key must fail"),
            "endpoint_shared signer public key does not match device_invite"
        );
    }

    #[test]
    fn rejects_workspace_or_user_authority_mismatch() {
        let (device_invite_id, invite_record) = device_invite_record([7; 32], [1; 32], [2; 32]);
        let (endpoint_shared_id, record, envelope) =
            signed_endpoint_shared_record(device_invite_id, [7; 32], [9; 32], [2; 32]);
        let event = signed_context(
            endpoint_shared_id,
            &record,
            device_invite_id,
            invite_record.clone(),
        );
        assert_eq!(
            project_signed(&envelope, &event).expect_err("wrong workspace must fail"),
            "endpoint_shared workspace does not match device_invite"
        );

        let (endpoint_shared_id, record, envelope) =
            signed_endpoint_shared_record(device_invite_id, [7; 32], [1; 32], [9; 32]);
        let event = signed_context(endpoint_shared_id, &record, device_invite_id, invite_record);
        assert_eq!(
            project_signed(&envelope, &event).expect_err("wrong user must fail"),
            "endpoint_shared user authority does not match device_invite"
        );
    }

    #[test]
    fn rejects_unsigned_device_invite_dependency() {
        let raw_invite = device_invite::types::DeviceInviteEvent {
            created_at_ms: 10,
            workspace_id: [1; 32],
            user_authority_event_id: [2; 32],
            user_invite_event_id: Some([6; 32]),
            public_key: public_key(&[7; 32]),
        };
        let raw_record =
            device_invite::codec::record_from_bytes(device_invite::codec::encode(&raw_invite))
                .expect("raw invite record");
        let device_invite_id = event_id(&raw_record.canonical_bytes);
        let (endpoint_shared_id, record, envelope) =
            signed_endpoint_shared_record(device_invite_id, [7; 32], [1; 32], [2; 32]);
        let event = signed_context(endpoint_shared_id, &record, device_invite_id, raw_record);

        assert_eq!(
            project_signed(&envelope, &event).expect_err("unsigned invite must fail"),
            "endpoint_shared dependency is not a signed endpoint invite"
        );
    }

    #[test]
    fn projects_invite_server_endpoint_shared_role() {
        let server_private_key = [17; 32];
        let server_public_key = public_key(&server_private_key);
        let invite = invite_server::commands::create(invite_server::commands::CreateInviteServer {
            created_at_ms: 10,
            public_key: server_public_key,
            workspace_id: [1; 32],
            authority_event_id: [1; 32],
            signer_event_id: [1; 32],
            signer_private_key: [11; 32],
        })
        .expect("create invite-server");
        let invite_server_id = invite.value.invite_server_id;
        let invite_server_record = invite.events[0].record().clone();
        let output = commands::share_endpoint(
            &ReadContext,
            commands::ShareEndpoint {
                created_at_ms: 20,
                workspace_id: [1; 32],
                user_authority_event_id: invite_server_id,
                endpoint_id: [3; 32],
                signing_public_key: [4; 32],
                endpoint_role: EndpointRole::InviteServer,
                device_name: "relay".to_string(),
                device_invite_id: invite_server_id,
                device_invite_private_key: server_private_key,
            },
        )
        .expect("share invite-server endpoint");
        let record = output.events[0].record().clone();
        let envelope = signed::codec::decode(&record.canonical_bytes).expect("signed envelope");
        let event = signed_context(
            output.value.endpoint_shared_id,
            &record,
            invite_server_id,
            invite_server_record,
        );

        let output = project_signed(&envelope, &event).expect("project invite-server endpoint");
        let row = schema::decode_endpoint_shared_row(&output.rows[0].key, &output.rows[0].value)
            .expect("decode endpoint row");

        assert_eq!(row.endpoint_role, EndpointRole::InviteServer);
        assert_eq!(row.user_authority_event_id, invite_server_id);
    }

    #[test]
    fn rejects_endpoint_role_that_does_not_match_invite_authority() {
        let (device_invite_id, invite_record) = device_invite_record([7; 32], [1; 32], [2; 32]);
        let output = commands::share_endpoint(
            &ReadContext,
            commands::ShareEndpoint {
                created_at_ms: 20,
                workspace_id: [1; 32],
                user_authority_event_id: [2; 32],
                endpoint_id: [3; 32],
                signing_public_key: [4; 32],
                endpoint_role: EndpointRole::InviteServer,
                device_name: "phone".to_string(),
                device_invite_id,
                device_invite_private_key: [7; 32],
            },
        )
        .expect("share endpoint");
        let record = output.events[0].record().clone();
        let envelope = signed::codec::decode(&record.canonical_bytes).expect("signed envelope");
        let event = signed_context(
            output.value.endpoint_shared_id,
            &record,
            device_invite_id,
            invite_record,
        );

        assert_eq!(
            project_signed(&envelope, &event).expect_err("wrong role must fail"),
            "endpoint_shared role does not match invite authority"
        );
    }

    #[test]
    fn rejects_non_endpoint_shared_payload() {
        let (device_invite_id, invite_record) = device_invite_record([7; 32], [1; 32], [2; 32]);
        let payload = device_invite::codec::encode(&device_invite::types::DeviceInviteEvent {
            created_at_ms: 30,
            workspace_id: [1; 32],
            user_authority_event_id: [2; 32],
            user_invite_event_id: Some([6; 32]),
            public_key: [4; 32],
        });
        let signed = signed::commands::sign_payload(device_invite_id, &[7; 32], payload)
            .expect("sign payload");
        let record = signed.events[0].record().clone();
        let envelope = signed::codec::decode(&record.canonical_bytes).expect("signed envelope");
        let event = signed_context(
            event_id(&record.canonical_bytes),
            &record,
            device_invite_id,
            invite_record,
        );

        assert_eq!(
            project_signed(&envelope, &event).expect_err("wrong payload must fail"),
            "expected endpoint_shared"
        );
    }
}

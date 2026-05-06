//! Projector for signed device-invite events.
//!
//! Projection is row-only. The worker supplies immediate dependency records
//! named by the signed device-invite record. This projector verifies that the
//! signer is either the user identity named by the invite or an existing
//! endpoint_shared row for the same workspace/user authority.

use crate::protocol::event_modules::identity::{
    endpoint_shared, signed, user, user_invite, workspace,
};
use crate::protocol::event_modules::types::{EventId, EventRecord};
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::{codec, schema};

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let _ = event;
    Err("device_invite must be signed".to_string())
}

pub fn project_signed(
    envelope: &signed::types::SignedEnvelope,
    event: &EventWithContext<'_>,
) -> Result<ProjectionOutput, String> {
    if envelope.inner_type != codec::TYPE_DEVICE_INVITE {
        return Err("expected signed device_invite".to_string());
    }
    let device_invite = codec::decode(&envelope.payload)?;
    validate_workspace(&device_invite, event)?;
    validate_authority(envelope, &device_invite, event)?;

    Ok(ProjectionOutput::rows(vec![schema::device_invite_row(
        event.context.event_id,
        &device_invite,
    )?]))
}

fn validate_workspace(
    device_invite: &super::types::DeviceInviteEvent,
    event: &EventWithContext<'_>,
) -> Result<(), String> {
    let workspace = event
        .context
        .dependency(&device_invite.workspace_id)
        .ok_or_else(|| "device_invite workspace dependency is missing".to_string())?;
    workspace::codec::decode(&workspace.canonical_bytes)
        .map_err(|_| "device_invite workspace dependency is not a workspace".to_string())?;
    Ok(())
}

fn validate_authority(
    envelope: &signed::types::SignedEnvelope,
    device_invite: &super::types::DeviceInviteEvent,
    event: &EventWithContext<'_>,
) -> Result<(), String> {
    let signer = require_dependency(event, &envelope.signer_event_id, "signer")?;
    let signer_envelope = signed::codec::decode(&signer.canonical_bytes)
        .map_err(|_| "device_invite signer must be user or endpoint_shared".to_string())?;
    match signer_envelope.inner_type {
        user::codec::TYPE_USER => {
            validate_user_authority(envelope, &signer_envelope, device_invite, event)
        }
        endpoint_shared::codec::TYPE_ENDPOINT_SHARED => {
            validate_endpoint_shared_authority(envelope, &signer_envelope, device_invite)
        }
        _ => Err("device_invite signer must be user or endpoint_shared".to_string()),
    }
}

fn validate_user_authority(
    envelope: &signed::types::SignedEnvelope,
    user_envelope: &signed::types::SignedEnvelope,
    device_invite: &super::types::DeviceInviteEvent,
    event: &EventWithContext<'_>,
) -> Result<(), String> {
    if envelope.signer_event_id != device_invite.user_authority_event_id {
        return Err("user-signed device_invite authority must match signer user".to_string());
    }
    let signed_user = user::codec::decode(&user_envelope.payload)
        .map_err(|_| "device_invite user signer payload is invalid".to_string())?;
    if envelope.signer_public_key != signed_user.public_key {
        return Err("device_invite signer public key does not match user".to_string());
    }

    let user_invite_event_id = device_invite.user_invite_event_id.ok_or_else(|| {
        "user-signed device_invite must include user_invite dependency".to_string()
    })?;
    if user_envelope.signer_event_id != user_invite_event_id {
        return Err("device_invite user_invite dependency does not match signed user".to_string());
    }
    let user_invite_record = require_dependency(event, &user_invite_event_id, "user_invite")?;
    let user_invite_envelope = signed::codec::decode(&user_invite_record.canonical_bytes)
        .map_err(|_| "device_invite user_invite dependency is not a user_invite".to_string())?;
    if user_invite_envelope.inner_type != user_invite::codec::TYPE_USER_INVITE {
        return Err("device_invite user_invite dependency is not a user_invite".to_string());
    }
    let signed_user_invite = user_invite::codec::decode(&user_invite_envelope.payload)?;
    if user_envelope.signer_public_key != signed_user_invite.public_key {
        return Err("device_invite user signer key does not match user_invite".to_string());
    }
    if signed_user_invite.workspace_id != device_invite.workspace_id {
        return Err("device_invite user authority belongs to a different workspace".to_string());
    }
    Ok(())
}

fn validate_endpoint_shared_authority(
    envelope: &signed::types::SignedEnvelope,
    signer_envelope: &signed::types::SignedEnvelope,
    device_invite: &super::types::DeviceInviteEvent,
) -> Result<(), String> {
    if device_invite.user_invite_event_id.is_some() {
        return Err(
            "endpoint_shared-signed device_invite must not include user_invite dependency"
                .to_string(),
        );
    }
    let signer = endpoint_shared::codec::decode(&signer_envelope.payload)
        .map_err(|_| "device_invite endpoint_shared signer payload is invalid".to_string())?;
    if envelope.signer_public_key != signer.signing_public_key {
        return Err(
            "device_invite signer public key does not match endpoint_shared signing key"
                .to_string(),
        );
    }
    if signer.workspace_id != device_invite.workspace_id {
        return Err(
            "endpoint_shared-signed device_invite workspace does not match signer".to_string(),
        );
    }
    if signer.user_authority_event_id != device_invite.user_authority_event_id {
        return Err(
            "endpoint_shared-signed device_invite user authority does not match signer".to_string(),
        );
    }
    Ok(())
}

fn require_dependency<'a>(
    event: &'a EventWithContext<'_>,
    event_id: &EventId,
    name: &'static str,
) -> Result<&'a EventRecord, String> {
    event
        .context
        .dependency(event_id)
        .ok_or_else(|| format!("device_invite {name} dependency is missing"))
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::identity::endpoint_shared::commands::EndpointMembershipRead;
    use crate::protocol::event_modules::types::{event_id, EventRecord};
    use crate::protocol::event_modules::worker::{
        DependencyContext, EventContext, EventWithContext,
    };

    use super::*;

    const WORKSPACE_PRIVATE: [u8; 32] = [7; 32];
    const OTHER_WORKSPACE_PRIVATE: [u8; 32] = [17; 32];
    const USER_INVITE_PRIVATE: [u8; 32] = [8; 32];
    const USER_PRIVATE: [u8; 32] = [9; 32];
    const DEVICE_INVITE_PRIVATE: [u8; 32] = [10; 32];
    const ENDPOINT_PRIVATE: [u8; 32] = [11; 32];
    const OTHER_ENDPOINT_PRIVATE: [u8; 32] = [12; 32];

    #[derive(Default)]
    struct NoMembership;

    impl EndpointMembershipRead for NoMembership {
        fn endpoint_membership(
            &self,
            _endpoint_id: crate::protocol::event_modules::identity::endpoint::types::EndpointId,
            _workspace_id: EventId,
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

    fn workspace_record(private_key: &[u8; 32]) -> ([u8; 32], EventRecord) {
        let bytes = workspace::codec::encode(&workspace::types::WorkspaceEvent {
            created_at_ms: 1,
            public_key: public_key(private_key),
            name: "Workspace".to_string(),
        })
        .expect("encode workspace");
        let id = event_id(&bytes);
        let record = workspace::codec::record_from_bytes(bytes).expect("workspace record");
        (id, record)
    }

    fn signed_user_invite_record(workspace_id: EventId) -> (EventId, EventRecord) {
        let invite = user_invite::commands::create(user_invite::commands::CreateUserInvite {
            created_at_ms: 2,
            public_key: public_key(&USER_INVITE_PRIVATE),
            workspace_id,
            authority_event_id: workspace_id,
            signer_event_id: workspace_id,
            signer_private_key: WORKSPACE_PRIVATE,
        })
        .expect("create user_invite");
        (
            invite.value.user_invite_id,
            invite.events[0].record().clone(),
        )
    }

    fn signed_user_record(
        workspace_id: EventId,
        user_invite_id: EventId,
    ) -> (EventId, EventRecord) {
        let user = user::commands::create(user::commands::CreateUser {
            created_at_ms: 3,
            workspace_id,
            public_key: public_key(&USER_PRIVATE),
            username: "alice".to_string(),
            user_invite_event_id: user_invite_id,
            user_invite_private_key: USER_INVITE_PRIVATE,
        })
        .expect("create user");
        (user.value.user_id, user.events[0].record().clone())
    }

    fn signed_endpoint_shared_record(
        workspace_id: EventId,
        user_id: EventId,
        endpoint_private_key: [u8; 32],
    ) -> (EventId, EventRecord) {
        let output = endpoint_shared::commands::share_endpoint(
            &NoMembership,
            endpoint_shared::commands::ShareEndpoint {
                created_at_ms: 4,
                workspace_id,
                user_authority_event_id: user_id,
                endpoint_id: public_key(&OTHER_ENDPOINT_PRIVATE),
                signing_public_key: public_key(&endpoint_private_key),
                device_name: "laptop".to_string(),
                device_invite_id: [5; 32],
                device_invite_private_key: DEVICE_INVITE_PRIVATE,
            },
        )
        .expect("share endpoint");
        (
            output.value.endpoint_shared_id,
            output.events[0].record().clone(),
        )
    }

    fn signed_device_invite_record(
        workspace_id: EventId,
        user_id: EventId,
        user_invite_id: Option<EventId>,
        signer_event_id: EventId,
        signer_private_key: [u8; 32],
    ) -> (EventId, EventRecord, signed::types::SignedEnvelope) {
        let output = super::super::commands::create_with_private_key(
            super::super::commands::CreateDeviceInvite {
                created_at_ms: 5,
                workspace_id,
                user_authority_event_id: user_id,
                user_invite_event_id: user_invite_id,
                signer_event_id,
                signer_private_key,
            },
            DEVICE_INVITE_PRIVATE,
        )
        .expect("create device_invite");
        let record = output.events[0].record().clone();
        let envelope = signed::codec::decode(&record.canonical_bytes).expect("signed envelope");
        (output.value.device_invite_id, record, envelope)
    }

    fn context_for<'a>(
        record: &'a EventRecord,
        event_id: EventId,
        dependencies: Vec<(EventId, EventRecord)>,
    ) -> EventWithContext<'a> {
        EventWithContext {
            record,
            context: EventContext {
                event_id,
                dependencies: dependencies
                    .into_iter()
                    .map(|(event_id, record)| DependencyContext { event_id, record })
                    .collect(),
                labels: Vec::new(),
                receive: None,
            },
        }
    }

    // Invariant: projects user signed device invite row.
    #[test]
    fn projects_user_signed_device_invite_row() {
        let (workspace_id, workspace_record) = workspace_record(&WORKSPACE_PRIVATE);
        let (user_invite_id, user_invite_record) = signed_user_invite_record(workspace_id);
        let (user_id, user_record) = signed_user_record(workspace_id, user_invite_id);
        let (device_invite_id, record, envelope) = signed_device_invite_record(
            workspace_id,
            user_id,
            Some(user_invite_id),
            user_id,
            USER_PRIVATE,
        );
        let event = context_for(
            &record,
            device_invite_id,
            vec![
                (workspace_id, workspace_record),
                (user_id, user_record),
                (user_invite_id, user_invite_record),
            ],
        );

        let output = project_signed(&envelope, &event).expect("project device invite");

        assert_eq!(output.labels.len(), 0);
        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::DEVICE_INVITES);
        assert_eq!(
            output.rows[0].key,
            schema::device_invite_key(workspace_id, device_invite_id)
        );
        let decoded = schema::decode_device_invite_row(&output.rows[0].key, &output.rows[0].value)
            .expect("decode row");
        assert_eq!(decoded.workspace_id, workspace_id);
        assert_eq!(decoded.device_invite_id, device_invite_id);
        assert_eq!(decoded.user_authority_event_id, user_id);
        assert_eq!(decoded.user_invite_event_id, Some(user_invite_id));
    }

    // Invariant: rejects unsigned device invite payload.
    #[test]
    fn rejects_unsigned_device_invite_payload() {
        let (workspace_id, workspace_record) = workspace_record(&WORKSPACE_PRIVATE);
        let (user_invite_id, user_invite_record) = signed_user_invite_record(workspace_id);
        let (user_id, user_record) = signed_user_record(workspace_id, user_invite_id);
        let raw = super::super::types::DeviceInviteEvent {
            created_at_ms: 5,
            workspace_id,
            user_authority_event_id: user_id,
            user_invite_event_id: Some(user_invite_id),
            public_key: public_key(&DEVICE_INVITE_PRIVATE),
        };
        let record =
            codec::record_from_bytes(codec::encode(&raw)).expect("unsigned device_invite record");
        let event = context_for(
            &record,
            event_id(&record.canonical_bytes),
            vec![
                (workspace_id, workspace_record),
                (user_id, user_record),
                (user_invite_id, user_invite_record),
            ],
        );

        assert_eq!(
            project(&event).expect_err("unsigned device_invite must reject"),
            "device_invite must be signed"
        );
    }

    // Invariant: rejects user signed device invite without user invite dependency.
    #[test]
    fn rejects_user_signed_device_invite_without_user_invite_dependency() {
        let (workspace_id, workspace_record) = workspace_record(&WORKSPACE_PRIVATE);
        let (user_invite_id, _) = signed_user_invite_record(workspace_id);
        let (user_id, user_record) = signed_user_record(workspace_id, user_invite_id);
        let (device_invite_id, record, envelope) =
            signed_device_invite_record(workspace_id, user_id, None, user_id, USER_PRIVATE);
        let event = context_for(
            &record,
            device_invite_id,
            vec![(workspace_id, workspace_record), (user_id, user_record)],
        );

        assert_eq!(
            project_signed(&envelope, &event).expect_err("missing user_invite must reject"),
            "user-signed device_invite must include user_invite dependency"
        );
    }

    // Invariant: rejects user signed device invite for different workspace.
    #[test]
    fn rejects_user_signed_device_invite_for_different_workspace() {
        let (workspace_id, _) = workspace_record(&WORKSPACE_PRIVATE);
        let (other_workspace_id, other_workspace_record) =
            workspace_record(&OTHER_WORKSPACE_PRIVATE);
        let (user_invite_id, user_invite_record) = signed_user_invite_record(workspace_id);
        let (user_id, user_record) = signed_user_record(workspace_id, user_invite_id);
        let (device_invite_id, record, envelope) = signed_device_invite_record(
            other_workspace_id,
            user_id,
            Some(user_invite_id),
            user_id,
            USER_PRIVATE,
        );
        let event = context_for(
            &record,
            device_invite_id,
            vec![
                (other_workspace_id, other_workspace_record),
                (user_id, user_record),
                (user_invite_id, user_invite_record),
            ],
        );

        assert_eq!(
            project_signed(&envelope, &event).expect_err("wrong workspace must reject"),
            "device_invite user authority belongs to a different workspace"
        );
    }

    // Invariant: projects endpoint shared signed device invite row.
    #[test]
    fn projects_endpoint_shared_signed_device_invite_row() {
        let (workspace_id, workspace_record) = workspace_record(&WORKSPACE_PRIVATE);
        let (user_invite_id, _) = signed_user_invite_record(workspace_id);
        let (user_id, _) = signed_user_record(workspace_id, user_invite_id);
        let (endpoint_shared_id, endpoint_shared_record) =
            signed_endpoint_shared_record(workspace_id, user_id, ENDPOINT_PRIVATE);
        let (device_invite_id, record, envelope) = signed_device_invite_record(
            workspace_id,
            user_id,
            None,
            endpoint_shared_id,
            ENDPOINT_PRIVATE,
        );
        let event = context_for(
            &record,
            device_invite_id,
            vec![
                (workspace_id, workspace_record),
                (endpoint_shared_id, endpoint_shared_record),
            ],
        );

        let output = project_signed(&envelope, &event).expect("project device invite");
        let decoded = schema::decode_device_invite_row(&output.rows[0].key, &output.rows[0].value)
            .expect("decode row");
        assert_eq!(decoded.workspace_id, workspace_id);
        assert_eq!(decoded.user_authority_event_id, user_id);
        assert_eq!(decoded.user_invite_event_id, None);
    }

    // Invariant: rejects endpoint shared signed device invite with wrong endpoint key.
    #[test]
    fn rejects_endpoint_shared_signed_device_invite_with_wrong_endpoint_key() {
        let (workspace_id, workspace_record) = workspace_record(&WORKSPACE_PRIVATE);
        let (user_invite_id, _) = signed_user_invite_record(workspace_id);
        let (user_id, _) = signed_user_record(workspace_id, user_invite_id);
        let (endpoint_shared_id, endpoint_shared_record) =
            signed_endpoint_shared_record(workspace_id, user_id, ENDPOINT_PRIVATE);
        let (device_invite_id, record, envelope) = signed_device_invite_record(
            workspace_id,
            user_id,
            None,
            endpoint_shared_id,
            OTHER_ENDPOINT_PRIVATE,
        );
        let event = context_for(
            &record,
            device_invite_id,
            vec![
                (workspace_id, workspace_record),
                (endpoint_shared_id, endpoint_shared_record),
            ],
        );

        assert_eq!(
            project_signed(&envelope, &event).expect_err("wrong endpoint signer must reject"),
            "device_invite signer public key does not match endpoint_shared signing key"
        );
    }

    // Invariant: rejects endpoint shared signed device invite with user invite dependency.
    #[test]
    fn rejects_endpoint_shared_signed_device_invite_with_user_invite_dependency() {
        let (workspace_id, workspace_record) = workspace_record(&WORKSPACE_PRIVATE);
        let (user_invite_id, user_invite_record) = signed_user_invite_record(workspace_id);
        let (user_id, _) = signed_user_record(workspace_id, user_invite_id);
        let (endpoint_shared_id, endpoint_shared_record) =
            signed_endpoint_shared_record(workspace_id, user_id, ENDPOINT_PRIVATE);
        let (device_invite_id, record, envelope) = signed_device_invite_record(
            workspace_id,
            user_id,
            Some(user_invite_id),
            endpoint_shared_id,
            ENDPOINT_PRIVATE,
        );
        let event = context_for(
            &record,
            device_invite_id,
            vec![
                (workspace_id, workspace_record),
                (endpoint_shared_id, endpoint_shared_record),
                (user_invite_id, user_invite_record),
            ],
        );

        assert_eq!(
            project_signed(&envelope, &event)
                .expect_err("endpoint signer must not use user_invite"),
            "endpoint_shared-signed device_invite must not include user_invite dependency"
        );
    }

    // Invariant: rejects endpoint shared signed device invite workspace or user mismatch.
    #[test]
    fn rejects_endpoint_shared_signed_device_invite_workspace_or_user_mismatch() {
        let (workspace_id, _) = workspace_record(&WORKSPACE_PRIVATE);
        let (other_workspace_id, other_workspace_record) =
            workspace_record(&OTHER_WORKSPACE_PRIVATE);
        let (user_invite_id, _) = signed_user_invite_record(workspace_id);
        let (user_id, _) = signed_user_record(workspace_id, user_invite_id);
        let (endpoint_shared_id, endpoint_shared_record) =
            signed_endpoint_shared_record(workspace_id, user_id, ENDPOINT_PRIVATE);
        let (device_invite_id, record, envelope) = signed_device_invite_record(
            other_workspace_id,
            user_id,
            None,
            endpoint_shared_id,
            ENDPOINT_PRIVATE,
        );
        let event = context_for(
            &record,
            device_invite_id,
            vec![
                (other_workspace_id, other_workspace_record),
                (endpoint_shared_id, endpoint_shared_record.clone()),
            ],
        );
        assert_eq!(
            project_signed(&envelope, &event).expect_err("wrong workspace must reject"),
            "endpoint_shared-signed device_invite workspace does not match signer"
        );

        let (workspace_id, workspace_record) = workspace_record(&WORKSPACE_PRIVATE);
        let (device_invite_id, record, envelope) = signed_device_invite_record(
            workspace_id,
            [99; 32],
            None,
            endpoint_shared_id,
            ENDPOINT_PRIVATE,
        );
        let event = context_for(
            &record,
            device_invite_id,
            vec![
                (workspace_id, workspace_record),
                (endpoint_shared_id, endpoint_shared_record),
            ],
        );
        assert_eq!(
            project_signed(&envelope, &event).expect_err("wrong user must reject"),
            "endpoint_shared-signed device_invite user authority does not match signer"
        );
    }
}

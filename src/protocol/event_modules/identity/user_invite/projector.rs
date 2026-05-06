//! Projector for signed user-invite events.
//!
//! Bootstrap invites are signed directly by the workspace root. Ongoing invites
//! are signed by an endpoint_shared event whose endpoint belongs to the user
//! named by an admin grant in the same workspace.
//!
//! The endpoint_shared dependency has two keys with different meanings: the
//! endpoint id is the transport identity used for connections, while
//! signing_public_key is the Ed25519 key authorized to sign workspace actions.
//! This projector must validate the envelope signer against signing_public_key,
//! not endpoint_id.

use crate::protocol::event_modules::types::EventRecord;
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::{codec, schema};
use crate::protocol::event_modules::identity::{admin, endpoint_shared, signed, workspace};

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let envelope = signed::codec::decode(&event.record.canonical_bytes)?;
    if envelope.inner_type != codec::TYPE_USER_INVITE {
        return Err("expected signed user_invite".to_string());
    }
    let user_invite = codec::decode(&envelope.payload)?;
    let signer = event
        .context
        .dependency(&envelope.signer_event_id)
        .ok_or_else(|| "missing signer dependency context for user_invite".to_string())?;

    match signer.canonical_bytes.first().copied() {
        Some(workspace::codec::TYPE_WORKSPACE) => {
            validate_workspace_signed_invite(&envelope, &user_invite, signer)?;
        }
        Some(signed::codec::TYPE_SIGNED) => {
            validate_admin_signed_invite(&envelope, &user_invite, signer, event)?;
        }
        _ => return Err("user_invite signer must be workspace or endpoint_shared".to_string()),
    }

    Ok(ProjectionOutput::rows(vec![schema::user_invite_row(
        event.context.event_id,
        &user_invite,
    )]))
}

fn validate_workspace_signed_invite(
    envelope: &signed::types::SignedEnvelope,
    user_invite: &super::types::UserInviteEvent,
    signer: &EventRecord,
) -> Result<(), String> {
    let signer_workspace = workspace::codec::decode(&signer.canonical_bytes)
        .map_err(|_| "user_invite signer must be workspace or endpoint_shared".to_string())?;
    if envelope.signer_event_id != user_invite.workspace_id
        || user_invite.authority_event_id != user_invite.workspace_id
    {
        return Err("bootstrap user_invite must use workspace as signer and authority".to_string());
    }
    if envelope.signer_public_key != signer_workspace.public_key {
        return Err(
            "signed user_invite signer key does not match workspace public key".to_string(),
        );
    }
    Ok(())
}

fn validate_admin_signed_invite(
    envelope: &signed::types::SignedEnvelope,
    user_invite: &super::types::UserInviteEvent,
    signer: &EventRecord,
    event: &EventWithContext<'_>,
) -> Result<(), String> {
    if user_invite.authority_event_id == user_invite.workspace_id {
        return Err("admin-signed user_invite must name an admin authority".to_string());
    }

    let signer_endpoint = decode_endpoint_shared_record(signer)
        .map_err(|_| "user_invite signer must be workspace or endpoint_shared".to_string())?;
    if envelope.signer_public_key != signer_endpoint.signing_public_key {
        return Err(
            "signed user_invite signer key does not match endpoint_shared signing key".to_string(),
        );
    }
    if signer_endpoint.workspace_id != user_invite.workspace_id {
        return Err("user_invite signer endpoint belongs to a different workspace".to_string());
    }

    let authority_record = event
        .context
        .dependency(&user_invite.authority_event_id)
        .ok_or_else(|| "missing admin authority dependency for user_invite".to_string())?;
    let authority_admin = decode_admin_record(authority_record)
        .map_err(|_| "user_invite authority must be an admin event".to_string())?;
    if authority_admin.workspace_id != user_invite.workspace_id {
        return Err("user_invite admin authority belongs to a different workspace".to_string());
    }
    if signer_endpoint.user_authority_event_id != authority_admin.user_event_id {
        return Err("user_invite signer user does not match admin authority user".to_string());
    }
    Ok(())
}

fn decode_endpoint_shared_record(
    record: &EventRecord,
) -> Result<endpoint_shared::types::EndpointSharedEvent, String> {
    let envelope = signed::codec::decode(&record.canonical_bytes)?;
    if envelope.inner_type != endpoint_shared::codec::TYPE_ENDPOINT_SHARED {
        return Err("expected signed endpoint_shared".to_string());
    }
    endpoint_shared::codec::decode(&envelope.payload)
}

fn decode_admin_record(record: &EventRecord) -> Result<admin::types::AdminEvent, String> {
    match record.canonical_bytes.first().copied() {
        Some(admin::codec::TYPE_ADMIN) => admin::codec::decode(&record.canonical_bytes),
        Some(signed::codec::TYPE_SIGNED) => {
            let envelope = signed::codec::decode(&record.canonical_bytes)?;
            if envelope.inner_type != admin::codec::TYPE_ADMIN {
                return Err("expected signed admin".to_string());
            }
            admin::codec::decode(&envelope.payload)
        }
        _ => Err("expected admin".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::identity::workspace::types::WorkspaceEvent;
    use crate::protocol::event_modules::types::{event_id, EventId, EventRecord};
    use crate::protocol::event_modules::worker::{DependencyContext, EventContext};

    use super::*;

    type Record = EventRecord;

    const WORKSPACE_PRIVATE: [u8; 32] = [7; 32];
    const OTHER_PRIVATE: [u8; 32] = [8; 32];
    const ENDPOINT_PRIVATE: [u8; 32] = [9; 32];
    const TRANSPORT_ENDPOINT_PRIVATE: [u8; 32] = [10; 32];

    fn signer_public_key(private_key: &[u8; 32]) -> [u8; 32] {
        signed::commands::sign_payload([0; 32], private_key, vec![99])
            .expect("sign fixture")
            .value
            .signer_public_key
    }

    fn workspace_record(
        private_key: &[u8; 32],
    ) -> (crate::protocol::event_modules::types::EventId, EventRecord) {
        let workspace = WorkspaceEvent {
            created_at_ms: 1,
            public_key: signer_public_key(private_key),
            name: "Workspace".to_string(),
        };
        let bytes = workspace::codec::encode(&workspace).expect("encode workspace");
        let workspace_id = event_id(&bytes);
        (
            workspace_id,
            workspace::codec::record_from_bytes(bytes).expect("workspace record"),
        )
    }

    fn signed_user_invite_record(
        signer_event_id: EventId,
        signer_private_key: &[u8; 32],
        user_invite: super::super::types::UserInviteEvent,
    ) -> Record {
        let output = signed::commands::sign_payload(
            signer_event_id,
            signer_private_key,
            codec::encode(&user_invite),
        )
        .expect("sign user_invite");
        output.events[0].record().clone()
    }

    fn admin_record(workspace_id: EventId, admin_user_id: EventId) -> (EventId, EventRecord) {
        let admin = admin::types::AdminEvent {
            created_at_ms: 4,
            workspace_id,
            public_key: [7; 32],
            authority_event_id: workspace_id,
            user_event_id: admin_user_id,
        };
        let bytes = admin::codec::encode(&admin);
        let admin_id = event_id(&bytes);
        (
            admin_id,
            admin::codec::record_from_bytes(bytes).expect("admin record"),
        )
    }

    fn endpoint_shared_record(
        workspace_id: EventId,
        admin_user_id: EventId,
        endpoint_private_key: &[u8; 32],
    ) -> (EventId, EventRecord) {
        let endpoint_shared = endpoint_shared::types::EndpointSharedEvent {
            created_at_ms: 6,
            workspace_id,
            user_authority_event_id: admin_user_id,
            endpoint_id: signer_public_key(&TRANSPORT_ENDPOINT_PRIVATE),
            signing_public_key: signer_public_key(endpoint_private_key),
            endpoint_role:
                crate::protocol::event_modules::identity::endpoint::types::EndpointRole::Device,
            device_name: "admin-laptop".to_string(),
        };
        let signed = signed::commands::sign_payload(
            [44; 32],
            &[45; 32],
            endpoint_shared::codec::encode(&endpoint_shared).expect("encode endpoint_shared"),
        )
        .expect("sign endpoint_shared");
        let record = signed.events[0].record().clone();
        (event_id(&record.canonical_bytes), record)
    }

    fn context<'a>(
        record: &'a EventRecord,
        dependencies: Vec<DependencyContext>,
    ) -> EventWithContext<'a> {
        EventWithContext {
            record,
            context: EventContext {
                event_id: event_id(&record.canonical_bytes),
                dependencies,
                labels: Vec::new(),
                receive: None,
            },
        }
    }

    fn dependency(event_id: EventId, record: EventRecord) -> DependencyContext {
        DependencyContext { event_id, record }
    }

    #[test]
    fn projects_workspace_signed_user_invite_row() {
        let (workspace_id, workspace_record) = workspace_record(&WORKSPACE_PRIVATE);
        let invite = super::super::types::UserInviteEvent {
            created_at_ms: 9,
            public_key: [3; 32],
            workspace_id,
            authority_event_id: workspace_id,
        };
        let record = signed_user_invite_record(workspace_id, &WORKSPACE_PRIVATE, invite);
        let output = project(&context(
            &record,
            vec![dependency(workspace_id, workspace_record)],
        ))
        .expect("project user_invite");

        assert!(output.labels.is_empty());
        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::USER_INVITES);
        assert_eq!(
            output.rows[0].key,
            schema::user_invite_key(&workspace_id, &event_id(&record.canonical_bytes))
        );
        assert_eq!(
            schema::decode_user_invite_row(&output.rows[0].key, &output.rows[0].value)
                .expect("decode row")
                .public_key,
            [3; 32]
        );
    }

    #[test]
    fn rejects_missing_signer_dependency_context() {
        let (workspace_id, _) = workspace_record(&WORKSPACE_PRIVATE);
        let invite = super::super::types::UserInviteEvent {
            created_at_ms: 9,
            public_key: [3; 32],
            workspace_id,
            authority_event_id: workspace_id,
        };
        let record = signed_user_invite_record(workspace_id, &WORKSPACE_PRIVATE, invite);

        let err = project(&context(&record, Vec::new())).expect_err("missing context must fail");

        assert_eq!(err, "missing signer dependency context for user_invite");
    }

    #[test]
    fn rejects_workspace_authority_mismatch() {
        let (workspace_id, workspace_record) = workspace_record(&WORKSPACE_PRIVATE);
        let invite = super::super::types::UserInviteEvent {
            created_at_ms: 9,
            public_key: [3; 32],
            workspace_id,
            authority_event_id: [6; 32],
        };
        let record = signed_user_invite_record(workspace_id, &WORKSPACE_PRIVATE, invite);

        let err = project(&context(
            &record,
            vec![dependency(workspace_id, workspace_record)],
        ))
        .expect_err("authority mismatch must fail");

        assert_eq!(
            err,
            "bootstrap user_invite must use workspace as signer and authority"
        );
    }

    #[test]
    fn rejects_signer_key_that_does_not_match_workspace() {
        let (workspace_id, workspace_record) = workspace_record(&WORKSPACE_PRIVATE);
        let invite = super::super::types::UserInviteEvent {
            created_at_ms: 9,
            public_key: [3; 32],
            workspace_id,
            authority_event_id: workspace_id,
        };
        let record = signed_user_invite_record(workspace_id, &OTHER_PRIVATE, invite);

        let err = project(&context(
            &record,
            vec![dependency(workspace_id, workspace_record)],
        ))
        .expect_err("signer key mismatch must fail");

        assert_eq!(
            err,
            "signed user_invite signer key does not match workspace public key"
        );
    }

    #[test]
    fn projects_admin_signed_user_invite_from_endpoint_owned_by_admin_user() {
        let (workspace_id, _) = workspace_record(&WORKSPACE_PRIVATE);
        let admin_user_id = [50; 32];
        let (admin_id, admin_record) = admin_record(workspace_id, admin_user_id);
        let (endpoint_shared_id, endpoint_shared_record) =
            endpoint_shared_record(workspace_id, admin_user_id, &ENDPOINT_PRIVATE);
        let invite = super::super::types::UserInviteEvent {
            created_at_ms: 9,
            public_key: [3; 32],
            workspace_id,
            authority_event_id: admin_id,
        };
        let record = signed_user_invite_record(endpoint_shared_id, &ENDPOINT_PRIVATE, invite);

        let output = project(&context(
            &record,
            vec![
                dependency(endpoint_shared_id, endpoint_shared_record),
                dependency(admin_id, admin_record),
            ],
        ))
        .expect("project admin-signed user_invite");

        assert_eq!(output.rows.len(), 1);
        let row = schema::decode_user_invite_row(&output.rows[0].key, &output.rows[0].value)
            .expect("decode row");
        assert_eq!(row.workspace_id, workspace_id);
        assert_eq!(row.authority_event_id, admin_id);
    }

    #[test]
    fn rejects_admin_signed_user_invite_signed_by_transport_endpoint_key() {
        let (workspace_id, _) = workspace_record(&WORKSPACE_PRIVATE);
        let admin_user_id = [50; 32];
        let (admin_id, admin_record) = admin_record(workspace_id, admin_user_id);
        let (endpoint_shared_id, endpoint_shared_record) =
            endpoint_shared_record(workspace_id, admin_user_id, &ENDPOINT_PRIVATE);
        let invite = super::super::types::UserInviteEvent {
            created_at_ms: 9,
            public_key: [3; 32],
            workspace_id,
            authority_event_id: admin_id,
        };
        let record =
            signed_user_invite_record(endpoint_shared_id, &TRANSPORT_ENDPOINT_PRIVATE, invite);

        let err = project(&context(
            &record,
            vec![
                dependency(endpoint_shared_id, endpoint_shared_record),
                dependency(admin_id, admin_record),
            ],
        ))
        .expect_err("transport endpoint key must not authorize user_invite");

        assert_eq!(
            err,
            "signed user_invite signer key does not match endpoint_shared signing key"
        );
    }

    #[test]
    fn rejects_admin_signed_user_invite_when_admin_authority_is_from_another_workspace() {
        let (workspace_id, _) = workspace_record(&WORKSPACE_PRIVATE);
        let (other_workspace_id, _) = workspace_record(&OTHER_PRIVATE);
        let admin_user_id = [50; 32];
        let (admin_id, admin_record) = admin_record(other_workspace_id, admin_user_id);
        let (endpoint_shared_id, endpoint_shared_record) =
            endpoint_shared_record(workspace_id, admin_user_id, &ENDPOINT_PRIVATE);
        let invite = super::super::types::UserInviteEvent {
            created_at_ms: 9,
            public_key: [3; 32],
            workspace_id,
            authority_event_id: admin_id,
        };
        let record = signed_user_invite_record(endpoint_shared_id, &ENDPOINT_PRIVATE, invite);

        let err = project(&context(
            &record,
            vec![
                dependency(endpoint_shared_id, endpoint_shared_record),
                dependency(admin_id, admin_record),
            ],
        ))
        .expect_err("cross-workspace admin authority must reject");

        assert_eq!(
            err,
            "user_invite admin authority belongs to a different workspace"
        );
    }

    #[test]
    fn rejects_admin_signed_user_invite_when_signer_endpoint_user_is_not_admin_user() {
        let (workspace_id, _) = workspace_record(&WORKSPACE_PRIVATE);
        let admin_user_id = [50; 32];
        let (admin_id, admin_record) = admin_record(workspace_id, admin_user_id);
        let (endpoint_shared_id, endpoint_shared_record) =
            endpoint_shared_record(workspace_id, [51; 32], &ENDPOINT_PRIVATE);
        let invite = super::super::types::UserInviteEvent {
            created_at_ms: 9,
            public_key: [3; 32],
            workspace_id,
            authority_event_id: admin_id,
        };
        let record = signed_user_invite_record(endpoint_shared_id, &ENDPOINT_PRIVATE, invite);

        let err = project(&context(
            &record,
            vec![
                dependency(endpoint_shared_id, endpoint_shared_record),
                dependency(admin_id, admin_record),
            ],
        ))
        .expect_err("wrong signer user must reject");

        assert_eq!(
            err,
            "user_invite signer user does not match admin authority user"
        );
    }

    #[test]
    fn allows_same_admin_user_endpoint_to_authorize_invites_in_each_matching_workspace() {
        let (workspace_a_id, _) = workspace_record(&WORKSPACE_PRIVATE);
        let (workspace_b_id, _) = workspace_record(&OTHER_PRIVATE);
        let admin_user_id = [50; 32];
        let (admin_a_id, admin_a_record) = admin_record(workspace_a_id, admin_user_id);
        let (admin_b_id, admin_b_record) = admin_record(workspace_b_id, admin_user_id);
        let (endpoint_a_id, endpoint_a_record) =
            endpoint_shared_record(workspace_a_id, admin_user_id, &ENDPOINT_PRIVATE);
        let (endpoint_b_id, endpoint_b_record) =
            endpoint_shared_record(workspace_b_id, admin_user_id, &ENDPOINT_PRIVATE);

        for (workspace_id, admin_id, admin_record, endpoint_id, endpoint_record) in [
            (
                workspace_a_id,
                admin_a_id,
                admin_a_record,
                endpoint_a_id,
                endpoint_a_record,
            ),
            (
                workspace_b_id,
                admin_b_id,
                admin_b_record,
                endpoint_b_id,
                endpoint_b_record,
            ),
        ] {
            let invite = super::super::types::UserInviteEvent {
                created_at_ms: 9,
                public_key: [3; 32],
                workspace_id,
                authority_event_id: admin_id,
            };
            let record = signed_user_invite_record(endpoint_id, &ENDPOINT_PRIVATE, invite);
            project(&context(
                &record,
                vec![
                    dependency(endpoint_id, endpoint_record),
                    dependency(admin_id, admin_record),
                ],
            ))
            .expect("matching workspace invite should project");
        }
    }
}

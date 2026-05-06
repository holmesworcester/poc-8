//! Projector for signed invite-server invites.
//!
//! Invite-server invites deliberately follow user-invite authority rules, but
//! project to a distinct row/table. The later endpoint-shared event signed by
//! this invite is an invite-server endpoint, not a content-key recipient.

use crate::protocol::event_modules::identity::{admin, endpoint_shared, signed, workspace};
use crate::protocol::event_modules::types::EventRecord;
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::{codec, schema};

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let envelope = signed::codec::decode(&event.record.canonical_bytes)?;
    if envelope.inner_type != codec::TYPE_INVITE_SERVER {
        return Err("expected signed invite_server".to_string());
    }
    let invite_server = codec::decode(&envelope.payload)?;
    let signer = event
        .context
        .dependency(&envelope.signer_event_id)
        .ok_or_else(|| "missing signer dependency context for invite_server".to_string())?;

    match signer.canonical_bytes.first().copied() {
        Some(workspace::codec::TYPE_WORKSPACE) => {
            validate_workspace_signed_invite(&envelope, &invite_server, signer)?;
        }
        Some(signed::codec::TYPE_SIGNED) => {
            validate_admin_signed_invite(&envelope, &invite_server, signer, event)?;
        }
        _ => return Err("invite_server signer must be workspace or endpoint_shared".to_string()),
    }

    Ok(ProjectionOutput::rows(vec![schema::invite_server_row(
        event.context.event_id,
        &invite_server,
    )]))
}

fn validate_workspace_signed_invite(
    envelope: &signed::types::SignedEnvelope,
    invite_server: &super::types::InviteServerEvent,
    signer: &EventRecord,
) -> Result<(), String> {
    let signer_workspace = workspace::codec::decode(&signer.canonical_bytes)
        .map_err(|_| "invite_server signer must be workspace or endpoint_shared".to_string())?;
    if envelope.signer_event_id != invite_server.workspace_id
        || invite_server.authority_event_id != invite_server.workspace_id
    {
        return Err(
            "bootstrap invite_server must use workspace as signer and authority".to_string(),
        );
    }
    if envelope.signer_public_key != signer_workspace.public_key {
        return Err(
            "signed invite_server signer key does not match workspace public key".to_string(),
        );
    }
    Ok(())
}

fn validate_admin_signed_invite(
    envelope: &signed::types::SignedEnvelope,
    invite_server: &super::types::InviteServerEvent,
    signer: &EventRecord,
    event: &EventWithContext<'_>,
) -> Result<(), String> {
    if invite_server.authority_event_id == invite_server.workspace_id {
        return Err("admin-signed invite_server must name an admin authority".to_string());
    }

    let signer_endpoint = decode_endpoint_shared_record(signer)
        .map_err(|_| "invite_server signer must be workspace or endpoint_shared".to_string())?;
    if envelope.signer_public_key != signer_endpoint.signing_public_key {
        return Err(
            "signed invite_server signer key does not match endpoint_shared signing key"
                .to_string(),
        );
    }
    if signer_endpoint.workspace_id != invite_server.workspace_id {
        return Err("invite_server signer endpoint belongs to a different workspace".to_string());
    }

    let authority_record = event
        .context
        .dependency(&invite_server.authority_event_id)
        .ok_or_else(|| "missing admin authority dependency for invite_server".to_string())?;
    let authority_admin = decode_admin_record(authority_record)
        .map_err(|_| "invite_server authority must be an admin event".to_string())?;
    if authority_admin.workspace_id != invite_server.workspace_id {
        return Err("invite_server admin authority belongs to a different workspace".to_string());
    }
    if signer_endpoint.user_authority_event_id != authority_admin.user_event_id {
        return Err("invite_server signer user does not match admin authority user".to_string());
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

    type FixtureRecord = EventRecord;

    const WORKSPACE_PRIVATE: [u8; 32] = [7; 32];
    const OTHER_PRIVATE: [u8; 32] = [8; 32];

    fn signer_public_key(private_key: &[u8; 32]) -> [u8; 32] {
        signed::commands::sign_payload([0; 32], private_key, vec![99])
            .expect("sign fixture")
            .value
            .signer_public_key
    }

    fn workspace_record() -> (EventId, EventRecord) {
        let workspace = WorkspaceEvent {
            created_at_ms: 1,
            public_key: signer_public_key(&WORKSPACE_PRIVATE),
            name: "Workspace".to_string(),
        };
        let bytes = workspace::codec::encode(&workspace).expect("encode workspace");
        let workspace_id = event_id(&bytes);
        (
            workspace_id,
            workspace::codec::record_from_bytes(bytes).expect("workspace record"),
        )
    }

    fn signed_invite_server_record(
        signer_event_id: EventId,
        signer_private_key: &[u8; 32],
        invite_server: super::super::types::InviteServerEvent,
    ) -> FixtureRecord {
        let output = signed::commands::sign_payload(
            signer_event_id,
            signer_private_key,
            codec::encode(&invite_server),
        )
        .expect("sign invite_server");
        output.events[0].record().clone()
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
    fn projects_workspace_signed_invite_server_row() {
        let (workspace_id, workspace_record) = workspace_record();
        let invite_server = super::super::types::InviteServerEvent {
            created_at_ms: 9,
            public_key: [3; 32],
            workspace_id,
            authority_event_id: workspace_id,
        };
        let record = signed_invite_server_record(workspace_id, &WORKSPACE_PRIVATE, invite_server);

        let output = project(&context(
            &record,
            vec![dependency(workspace_id, workspace_record)],
        ))
        .expect("project invite_server");

        assert!(output.labels.is_empty());
        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::INVITE_SERVERS);
        assert_eq!(
            output.rows[0].key,
            schema::invite_server_key(&workspace_id, &event_id(&record.canonical_bytes))
        );
        assert_eq!(
            schema::decode_invite_server_row(&output.rows[0].key, &output.rows[0].value)
                .expect("decode row")
                .public_key,
            [3; 32]
        );
    }

    #[test]
    fn rejects_workspace_signer_key_mismatch() {
        let (workspace_id, workspace_record) = workspace_record();
        let invite_server = super::super::types::InviteServerEvent {
            created_at_ms: 9,
            public_key: [3; 32],
            workspace_id,
            authority_event_id: workspace_id,
        };
        let record = signed_invite_server_record(workspace_id, &OTHER_PRIVATE, invite_server);

        let err = project(&context(
            &record,
            vec![dependency(workspace_id, workspace_record)],
        ))
        .expect_err("signer key mismatch must fail");

        assert_eq!(
            err,
            "signed invite_server signer key does not match workspace public key"
        );
    }
}

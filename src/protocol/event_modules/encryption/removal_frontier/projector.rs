//! Projector for signed removal frontier events.
//!
//! A frontier can be introduced only by an endpoint membership whose user has
//! an admin grant in the same workspace. Frontier refs are accepted only when
//! admission has supplied the referenced dependency records and those records
//! belong to the same workspace. The removal fact vocabulary can tighten that
//! semantic check later without changing the fixed-width frontier shape.

use crate::protocol::event_modules::identity::{admin, endpoint_shared, signed};
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::{codec, schema};

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let envelope = codec::decode_signed(&event.record.canonical_bytes)?;
    let frontier = codec::decode(&envelope.payload)?;
    if event.record.workspace_id != Some(frontier.workspace_id) {
        return Err("removal frontier workspace metadata does not match event body".to_string());
    }
    validate_frontier_refs(event, &frontier)?;

    let signer_endpoint_shared =
        decode_signer_endpoint_shared(event, envelope.signer_endpoint_shared_id)?;
    if signer_endpoint_shared.workspace_id != frontier.workspace_id {
        return Err(
            "removal frontier signer endpoint_shared workspace does not match event".to_string(),
        );
    }
    if signer_endpoint_shared.signing_public_key != envelope.signer_public_key {
        return Err(
            "removal frontier signer public key does not match endpoint_shared".to_string(),
        );
    }

    let authority_admin = decode_authority_admin(event, frontier.authority_admin_id)?;
    if authority_admin.workspace_id != frontier.workspace_id {
        return Err(
            "removal frontier authority admin belongs to a different workspace".to_string(),
        );
    }
    if signer_endpoint_shared.user_authority_event_id != authority_admin.user_event_id {
        return Err("removal frontier signer user is not the authority admin".to_string());
    }

    Ok(ProjectionOutput::rows(vec![schema::removal_frontier_row(
        event.context.event_id,
        &frontier,
    )?]))
}

fn validate_frontier_refs(
    event: &EventWithContext<'_>,
    frontier: &super::types::RemovalFrontierEvent,
) -> Result<(), String> {
    for ref_id in &frontier.removal_event_ids {
        let record = event
            .context
            .dependency(ref_id)
            .ok_or_else(|| "removal frontier ref dependency is missing".to_string())?;
        if record.workspace_id != Some(frontier.workspace_id) {
            return Err("removal frontier ref belongs to a different workspace".to_string());
        }
    }
    Ok(())
}

fn decode_signer_endpoint_shared(
    event: &EventWithContext<'_>,
    endpoint_shared_id: [u8; 32],
) -> Result<endpoint_shared::types::EndpointSharedEvent, String> {
    let record = event
        .context
        .dependency(&endpoint_shared_id)
        .ok_or_else(|| {
            "removal frontier signer endpoint_shared dependency is missing".to_string()
        })?;
    let envelope = signed::codec::decode(&record.canonical_bytes).map_err(|_| {
        "removal frontier signer dependency is not a signed endpoint_shared".to_string()
    })?;
    if envelope.inner_type != endpoint_shared::codec::TYPE_ENDPOINT_SHARED {
        return Err(
            "removal frontier signer dependency is not a signed endpoint_shared".to_string(),
        );
    }
    endpoint_shared::codec::decode(&envelope.payload).map_err(|_| {
        "removal frontier signer dependency is not a signed endpoint_shared".to_string()
    })
}

fn decode_authority_admin(
    event: &EventWithContext<'_>,
    authority_admin_id: [u8; 32],
) -> Result<admin::types::AdminEvent, String> {
    let record = event
        .context
        .dependency(&authority_admin_id)
        .ok_or_else(|| "removal frontier authority admin dependency is missing".to_string())?;
    let envelope = signed::codec::decode(&record.canonical_bytes)
        .map_err(|_| "removal frontier authority dependency is not a signed admin".to_string())?;
    if envelope.inner_type != admin::codec::TYPE_ADMIN {
        return Err("removal frontier authority dependency is not a signed admin".to_string());
    }
    admin::codec::decode(&envelope.payload)
        .map_err(|_| "removal frontier authority dependency is not a signed admin".to_string())
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::identity::{admin, endpoint_shared, signed};
    use crate::protocol::event_modules::types::event_id;
    use crate::protocol::event_modules::worker::{
        DependencyContext, EventContext, EventWithContext,
    };

    use super::super::commands;
    use super::*;

    type Record = crate::protocol::event_modules::types::EventRecord;

    fn signer_public_key(private_key: &[u8; 32]) -> [u8; 32] {
        signed::commands::sign_payload([0; 32], private_key, vec![99])
            .expect("sign fixture")
            .value
            .signer_public_key
    }

    fn endpoint_shared_record(
        workspace_id: [u8; 32],
        user_authority_event_id: [u8; 32],
        signing_public_key: [u8; 32],
    ) -> Record {
        let payload =
            endpoint_shared::codec::encode(&endpoint_shared::types::EndpointSharedEvent {
                created_at_ms: 4,
                workspace_id,
                user_authority_event_id,
                endpoint_id: [21; 32],
                signing_public_key,
                endpoint_role:
                    crate::protocol::event_modules::identity::endpoint::types::EndpointRole::Device,
                device_name: "laptop".to_string(),
            })
            .expect("encode endpoint_shared");
        signed::commands::sign_payload([6; 32], &[5; 32], payload)
            .expect("sign endpoint_shared")
            .events[0]
            .record()
            .clone()
    }

    fn admin_record(workspace_id: [u8; 32], user_event_id: [u8; 32]) -> Record {
        let payload = admin::codec::encode(&admin::types::AdminEvent {
            created_at_ms: 3,
            workspace_id,
            public_key: [44; 32],
            authority_event_id: [33; 32],
            user_event_id,
        });
        signed::commands::sign_payload([8; 32], &[7; 32], payload)
            .expect("sign admin")
            .events[0]
            .record()
            .clone()
    }

    fn frontier_record(
        workspace_id: [u8; 32],
        signer_id: [u8; 32],
        signer_private_key: [u8; 32],
        authority_admin_id: [u8; 32],
        removal_event_ids: Vec<[u8; 32]>,
    ) -> Record {
        commands::create(commands::CreateRemovalFrontier {
            workspace_id,
            created_at_ms: 10,
            authority_admin_id,
            signer_endpoint_shared_id: signer_id,
            signer_private_key,
            removal_event_ids,
        })
        .expect("create frontier")
        .events[0]
            .record()
            .clone()
    }

    fn event_with_context<'a>(
        record: &'a Record,
        signer_id: [u8; 32],
        signer_record: Record,
        admin_id: [u8; 32],
        admin_record: Record,
        extra_dependencies: Vec<DependencyContext>,
    ) -> EventWithContext<'a> {
        let mut dependencies = vec![
            DependencyContext {
                event_id: signer_id,
                record: signer_record,
            },
            DependencyContext {
                event_id: admin_id,
                record: admin_record,
            },
        ];
        dependencies.extend(extra_dependencies);
        EventWithContext {
            record,
            context: EventContext {
                event_id: event_id(&record.canonical_bytes),
                dependencies,
                labels: Vec::new(),
                receive: None,
                now_unix_minute: None,
            },
        }
    }

    #[test]
    fn projects_frontier_row_from_admin_endpoint() {
        let signer_private_key = [9; 32];
        let signer_public_key = signer_public_key(&signer_private_key);
        let user_id = [2; 32];
        let signer_record = endpoint_shared_record([1; 32], user_id, signer_public_key);
        let signer_id = event_id(&signer_record.canonical_bytes);
        let admin_record = admin_record([1; 32], user_id);
        let admin_id = event_id(&admin_record.canonical_bytes);
        let record = frontier_record([1; 32], signer_id, signer_private_key, admin_id, Vec::new());
        let event = event_with_context(
            &record,
            signer_id,
            signer_record,
            admin_id,
            admin_record,
            Vec::new(),
        );

        let output = project(&event).expect("project frontier");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::REMOVAL_FRONTIERS);
        let row = schema::decode_removal_frontier_row(&output.rows[0].key, &output.rows[0].value)
            .expect("decode row");
        assert_eq!(row.workspace_id, [1; 32]);
        assert_eq!(row.removal_frontier_id, event.context.event_id);
        assert_eq!(row.authority_admin_id, admin_id);
    }

    #[test]
    fn projects_frontier_refs_when_dependency_closure_is_same_workspace() {
        let signer_private_key = [9; 32];
        let signer_public_key = signer_public_key(&signer_private_key);
        let user_id = [2; 32];
        let signer_record = endpoint_shared_record([1; 32], user_id, signer_public_key);
        let signer_id = event_id(&signer_record.canonical_bytes);
        let admin_record = admin_record([1; 32], user_id);
        let admin_id = event_id(&admin_record.canonical_bytes);
        let ref_record = Record {
            timestamp: 9,
            body_len: 3,
            canonical_bytes: b"ref".to_vec(),
            dependencies: Vec::new(),
            workspace_id: Some([1; 32]),
            scope: crate::protocol::event_modules::types::EventScope::Shared,
        };
        let ref_id = event_id(&ref_record.canonical_bytes);
        let record = frontier_record(
            [1; 32],
            signer_id,
            signer_private_key,
            admin_id,
            vec![ref_id],
        );
        let event = event_with_context(
            &record,
            signer_id,
            signer_record,
            admin_id,
            admin_record,
            vec![DependencyContext {
                event_id: ref_id,
                record: ref_record,
            }],
        );

        let output = project(&event).expect("project frontier");

        let row = schema::decode_removal_frontier_row(&output.rows[0].key, &output.rows[0].value)
            .expect("decode row");
        assert_eq!(row.removal_event_ids, vec![ref_id]);
    }

    #[test]
    fn rejects_signer_user_without_matching_admin() {
        let signer_private_key = [9; 32];
        let signer_public_key = signer_public_key(&signer_private_key);
        let signer_record = endpoint_shared_record([1; 32], [2; 32], signer_public_key);
        let signer_id = event_id(&signer_record.canonical_bytes);
        let admin_record = admin_record([1; 32], [3; 32]);
        let admin_id = event_id(&admin_record.canonical_bytes);
        let record = frontier_record([1; 32], signer_id, signer_private_key, admin_id, Vec::new());
        let event = event_with_context(
            &record,
            signer_id,
            signer_record,
            admin_id,
            admin_record,
            Vec::new(),
        );

        assert_eq!(
            project(&event).expect_err("wrong admin user must fail"),
            "removal frontier signer user is not the authority admin"
        );
    }
}

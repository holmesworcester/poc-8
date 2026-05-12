//! Projector for local invite acceptance.
//!
//! The projector validates only the immediate local dependency it names: the
//! scoped `invite_secret` event. It does not query broad identity state, validate
//! the shared invite row, create membership, or trigger bootstrap work. Those
//! responsibilities belong to the common event pipeline, shared identity
//! projectors, and bootstrap worker respectively.

use crate::protocol::event_modules::identity::invite;
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::{codec, schema, types::InviteAcceptedEvent};

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let accepted = codec::decode(&event.record.canonical_bytes)?;
    if event.record.workspace_id != Some(accepted.workspace_id) {
        return Err("invite_accepted workspace metadata does not match event body".to_string());
    }
    validate_invite_secret(event, &accepted)?;
    Ok(ProjectionOutput::rows(vec![schema::invite_accepted_row(
        event.context.event_id,
        &accepted,
    )]))
}

fn validate_invite_secret(
    event: &EventWithContext<'_>,
    accepted: &InviteAcceptedEvent,
) -> Result<(), String> {
    let secret_record = event
        .context
        .dependency(&accepted.invite_secret_event_id)
        .ok_or_else(|| "invite_accepted invite_secret dependency is missing".to_string())?;
    let secret = invite::codec::decode(&secret_record.canonical_bytes)
        .map_err(|_| "invite_accepted dependency is not an invite_secret event".to_string())?;
    if secret.bootstrap_hash != accepted.bootstrap_hash {
        return Err("invite_accepted bootstrap hash does not match invite_secret".to_string());
    }
    if secret.workspace_id != Some(accepted.workspace_id)
        || secret.invite_event_id != Some(accepted.invite_event_id)
    {
        return Err("invite_accepted invite_secret scope does not match acceptance".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::types::{event_id, EventRecord};
    use crate::protocol::event_modules::worker::{
        DependencyContext, EventContext, EventWithContext,
    };

    use super::*;

    type Record = EventRecord;

    fn invite_secret_record(
        secret: [u8; 32],
        workspace_id: [u8; 32],
        invite_event_id: [u8; 32],
    ) -> Record {
        let secret =
            invite::types::InviteSecretEvent::scoped(secret, workspace_id, invite_event_id);
        invite::codec::record_from_bytes(invite::codec::encode(&secret)).expect("secret record")
    }

    fn accepted_record(event: &InviteAcceptedEvent) -> Record {
        codec::record_from_bytes(codec::encode(event)).expect("accepted record")
    }

    fn event_with_context<'a>(
        record: &'a EventRecord,
        event_id: [u8; 32],
        dependency_id: [u8; 32],
        dependency: EventRecord,
    ) -> EventWithContext<'a> {
        EventWithContext {
            record,
            context: EventContext {
                event_id,
                dependencies: vec![DependencyContext {
                    event_id: dependency_id,
                    record: dependency,
                }],
                labels: Vec::new(),
                receive: None,
                now_unix_minute: None,
            },
        }
    }

    /// Invariant: invite_accepted projects only when its scoped invite-secret
    /// dependency proves the same workspace, invite id, and bootstrap hash.
    #[test]
    fn projects_acceptance_when_invite_secret_scope_matches() {
        let secret = [7; 32];
        let secret_record = invite_secret_record(secret, [1; 32], [2; 32]);
        let secret_id = event_id(&secret_record.canonical_bytes);
        let accepted = InviteAcceptedEvent {
            workspace_id: [1; 32],
            invite_event_id: [2; 32],
            invite_secret_event_id: secret_id,
            bootstrap_hash: invite::types::bootstrap_secret_hash(&secret),
            accepted_endpoint_id: [5; 32],
        };
        let record = accepted_record(&accepted);
        let event = event_with_context(&record, [9; 32], secret_id, secret_record);

        let output = project(&event).expect("project acceptance");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::INVITES_ACCEPTED);
        assert_eq!(
            schema::decode_invite_accepted_row(&output.rows[0].key, &output.rows[0].value)
                .expect("decode row"),
            super::super::types::InviteAcceptedRow {
                accepted_endpoint_id: [5; 32],
                workspace_id: [1; 32],
                invite_event_id: [2; 32],
                invite_accepted_event_id: [9; 32],
                invite_secret_event_id: secret_id,
                bootstrap_hash: invite::types::bootstrap_secret_hash(&secret),
            }
        );
    }

    /// Invariant: a local acceptance event cannot bind one invite link while
    /// depending on secret material scoped to a different workspace.
    #[test]
    fn rejects_acceptance_when_invite_secret_scope_differs() {
        let secret = [7; 32];
        let secret_record = invite_secret_record(secret, [8; 32], [2; 32]);
        let secret_id = event_id(&secret_record.canonical_bytes);
        let accepted = InviteAcceptedEvent {
            workspace_id: [1; 32],
            invite_event_id: [2; 32],
            invite_secret_event_id: secret_id,
            bootstrap_hash: invite::types::bootstrap_secret_hash(&secret),
            accepted_endpoint_id: [5; 32],
        };
        let record = accepted_record(&accepted);
        let event = event_with_context(&record, [9; 32], secret_id, secret_record);

        let err = project(&event).expect_err("mismatched scope must fail");

        assert_eq!(
            err,
            "invite_accepted invite_secret scope does not match acceptance"
        );
    }
}

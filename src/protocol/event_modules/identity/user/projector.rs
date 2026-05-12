//! Projector for signed user events.
//!
//! Projection validates that the signer dependency is a signed user-invite
//! event, and that this user event was signed by the invite key authorized by
//! that dependency.

use crate::protocol::event_modules::identity::{signed, user_invite};
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::{codec, schema};

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let envelope = signed::codec::decode(&event.record.canonical_bytes)?;
    if envelope.inner_type != codec::TYPE_USER {
        return Err("expected signed user".to_string());
    }
    let user = codec::decode(&envelope.payload)?;
    if user.username.trim().is_empty() {
        return Err("username must not be empty".to_string());
    }

    let signer = event
        .context
        .dependency(&envelope.signer_event_id)
        .ok_or_else(|| "missing signer dependency context for user".to_string())?;
    let invite_envelope = signed::codec::decode(&signer.canonical_bytes)
        .map_err(|_| "user signer must be user_invite".to_string())?;
    if invite_envelope.inner_type != user_invite::codec::TYPE_USER_INVITE {
        return Err("user signer must be user_invite".to_string());
    }
    let invite = user_invite::codec::decode(&invite_envelope.payload)?;
    if envelope.signer_public_key != invite.public_key {
        return Err("signed user signer key does not match user_invite public key".to_string());
    }
    if user.workspace_id != invite.workspace_id {
        return Err("user workspace does not match user_invite workspace".to_string());
    }

    Ok(ProjectionOutput::rows(vec![schema::user_row(
        user.workspace_id,
        event.context.event_id,
        envelope.signer_event_id,
        &user,
    )?]))
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::identity::workspace::types::WorkspaceEvent;
    use crate::protocol::event_modules::types::{event_id, EventRecord};
    use crate::protocol::event_modules::worker::{DependencyContext, EventContext};

    use super::*;

    type Record = EventRecord;

    const WORKSPACE_PRIVATE: [u8; 32] = [7; 32];
    const INVITE_PRIVATE: [u8; 32] = [8; 32];
    const OTHER_PRIVATE: [u8; 32] = [9; 32];

    fn signer_public_key(private_key: &[u8; 32]) -> [u8; 32] {
        signed::commands::sign_payload([0; 32], private_key, vec![99])
            .expect("sign fixture")
            .value
            .signer_public_key
    }

    fn workspace_id() -> crate::protocol::event_modules::types::EventId {
        let workspace = WorkspaceEvent {
            created_at_ms: 1,
            public_key: signer_public_key(&WORKSPACE_PRIVATE),
            disappearing_ttl_minutes: 0,
            name: "Workspace".to_string(),
        };
        let bytes = crate::protocol::event_modules::identity::workspace::codec::encode(&workspace)
            .expect("encode workspace");
        event_id(&bytes)
    }

    fn user_invite_record(
        invite_private_key: &[u8; 32],
    ) -> (crate::protocol::event_modules::types::EventId, EventRecord) {
        let workspace_id = workspace_id();
        let invite = user_invite::types::UserInviteEvent {
            created_at_ms: 2,
            public_key: signer_public_key(invite_private_key),
            workspace_id,
            authority_event_id: workspace_id,
        };
        let signed_invite = signed::commands::sign_payload(
            workspace_id,
            &WORKSPACE_PRIVATE,
            user_invite::codec::encode(&invite),
        )
        .expect("sign invite");
        (
            signed_invite.events[0].event_id(),
            signed_invite.events[0].record().clone(),
        )
    }

    fn signed_user_record(
        signer_event_id: crate::protocol::event_modules::types::EventId,
        signer_private_key: &[u8; 32],
        workspace_id: crate::protocol::event_modules::types::EventId,
        username: &str,
    ) -> Record {
        let user = super::super::types::UserEvent {
            created_at_ms: 3,
            workspace_id,
            public_key: signer_public_key(&[10; 32]),
            username: username.to_string(),
        };
        let signed_user = signed::commands::sign_payload(
            signer_event_id,
            signer_private_key,
            codec::encode(&user).expect("encode user"),
        )
        .expect("sign user");
        signed_user.events[0].record().clone()
    }

    fn context<'a>(
        record: &'a EventRecord,
        dependency: Option<(crate::protocol::event_modules::types::EventId, EventRecord)>,
    ) -> EventWithContext<'a> {
        EventWithContext {
            record,
            context: EventContext {
                event_id: event_id(&record.canonical_bytes),
                dependencies: dependency
                    .into_iter()
                    .map(|(event_id, record)| DependencyContext { event_id, record })
                    .collect(),
                labels: Vec::new(),
                receive: None,
                now_unix_minute: None,
            },
        }
    }

    #[test]
    fn projects_user_row_scoped_by_user_invite_workspace() {
        let (invite_id, invite_record) = user_invite_record(&INVITE_PRIVATE);
        let user_record = signed_user_record(invite_id, &INVITE_PRIVATE, workspace_id(), "alice");
        let output = project(&context(&user_record, Some((invite_id, invite_record))))
            .expect("project user");

        assert!(output.labels.is_empty());
        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::USERS);
        let row =
            schema::decode_user_row(&output.rows[0].key, &output.rows[0].value).expect("decode");
        assert_eq!(row.workspace_id, workspace_id());
        assert_eq!(row.user_id, event_id(&user_record.canonical_bytes));
        assert_eq!(row.user_invite_id, invite_id);
        assert_eq!(row.username, "alice");
    }

    #[test]
    fn rejects_missing_signer_dependency_context() {
        let (invite_id, _) = user_invite_record(&INVITE_PRIVATE);
        let user_record = signed_user_record(invite_id, &INVITE_PRIVATE, workspace_id(), "alice");

        let err = project(&context(&user_record, None)).expect_err("missing context must fail");

        assert_eq!(err, "missing signer dependency context for user");
    }

    #[test]
    fn rejects_wrong_signer_dependency_type() {
        let workspace_id = workspace_id();
        let workspace = WorkspaceEvent {
            created_at_ms: 1,
            public_key: signer_public_key(&WORKSPACE_PRIVATE),
            disappearing_ttl_minutes: 0,
            name: "Workspace".to_string(),
        };
        let workspace_record =
            crate::protocol::event_modules::identity::workspace::codec::record_from_bytes(
                crate::protocol::event_modules::identity::workspace::codec::encode(&workspace)
                    .expect("encode workspace"),
            )
            .expect("workspace record");
        let user_record =
            signed_user_record(workspace_id, &WORKSPACE_PRIVATE, workspace_id, "alice");

        let err = project(&context(
            &user_record,
            Some((workspace_id, workspace_record)),
        ))
        .expect_err("wrong signer type must fail");

        assert_eq!(err, "user signer must be user_invite");
    }

    #[test]
    fn rejects_user_signed_by_key_not_named_by_invite() {
        let (invite_id, invite_record) = user_invite_record(&INVITE_PRIVATE);
        let user_record = signed_user_record(invite_id, &OTHER_PRIVATE, workspace_id(), "alice");

        let err = project(&context(&user_record, Some((invite_id, invite_record))))
            .expect_err("wrong signer key must fail");

        assert_eq!(
            err,
            "signed user signer key does not match user_invite public key"
        );
    }

    #[test]
    fn rejects_blank_username() {
        let (invite_id, invite_record) = user_invite_record(&INVITE_PRIVATE);
        let user_record = signed_user_record(invite_id, &INVITE_PRIVATE, workspace_id(), "  ");

        let err = project(&context(&user_record, Some((invite_id, invite_record))))
            .expect_err("blank username must fail");

        assert_eq!(err, "username must not be empty");
    }

    #[test]
    fn rejects_user_for_different_workspace_than_invite() {
        let (invite_id, invite_record) = user_invite_record(&INVITE_PRIVATE);
        let user_record = signed_user_record(invite_id, &INVITE_PRIVATE, [99; 32], "alice");

        let err = project(&context(&user_record, Some((invite_id, invite_record))))
            .expect_err("workspace mismatch must fail");

        assert_eq!(err, "user workspace does not match user_invite workspace");
    }
}

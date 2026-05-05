//! Projector for signed messages.
//!
//! The shared event is the signed envelope. Projection validates that the
//! signer endpoint_shared belongs to the same workspace as the message body,
//! that the signer's public key matches the membership signing key, and that
//! the named author user is also a workspace member who signed off the
//! endpoint chain. The text itself is opaque; storage is keyed by workspace.

use crate::protocol::event_modules::content::message_deletion::types::deletion_label_author;
use crate::protocol::event_modules::identity::{endpoint_shared, signed, user};
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::{codec, schema};

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let envelope = codec::decode_signed(&event.record.canonical_bytes)?;
    let message = codec::decode(&envelope.payload)?;
    if event.record.workspace_id != Some(message.workspace_id) {
        return Err("message workspace metadata does not match event body".to_string());
    }

    let signer = event
        .context
        .dependency(&envelope.signer_endpoint_shared_id)
        .ok_or_else(|| "message signer endpoint_shared dependency is missing".to_string())?;
    let signer_envelope = signed::codec::decode(&signer.canonical_bytes)
        .map_err(|_| "message signer dependency is not a signed endpoint_shared".to_string())?;
    if signer_envelope.inner_type != endpoint_shared::codec::TYPE_ENDPOINT_SHARED {
        return Err("message signer dependency is not a signed endpoint_shared".to_string());
    }
    let signer_endpoint_shared = endpoint_shared::codec::decode(&signer_envelope.payload)
        .map_err(|_| "message signer dependency is not a signed endpoint_shared".to_string())?;
    if signer_endpoint_shared.workspace_id != message.workspace_id {
        return Err("message signer endpoint_shared workspace does not match message".to_string());
    }
    if signer_endpoint_shared.signing_public_key != envelope.signer_public_key {
        return Err("message signer public key does not match endpoint_shared".to_string());
    }

    let author = event
        .context
        .dependency(&message.author_user_id)
        .ok_or_else(|| "message author user dependency is missing".to_string())?;
    let author_envelope = signed::codec::decode(&author.canonical_bytes)
        .map_err(|_| "message author dependency is not a signed user".to_string())?;
    if author_envelope.inner_type != user::codec::TYPE_USER {
        return Err("message author dependency is not a signed user".to_string());
    }
    let author_user = user::codec::decode(&author_envelope.payload)
        .map_err(|_| "message author dependency is not a signed user".to_string())?;
    if author_user.workspace_id != message.workspace_id {
        return Err("message author workspace does not match message".to_string());
    }
    if signer_endpoint_shared.user_authority_event_id != message.author_user_id {
        return Err("message signer endpoint is not authorized by the named author".to_string());
    }

    // Purge-on-project: a deletion event labels its target message id with
    // `content.deleted:<author_user_id>`. If any deletion label authored by
    // this same user exists, the message is treated as already deleted and we
    // emit no row. Labels are loaded into `event.context` for this event id.
    let is_deleted_by_author = event.context.labels.iter().any(|label| {
        deletion_label_author(label)
            .map(|author| author == message.author_user_id)
            .unwrap_or(false)
    });
    if is_deleted_by_author {
        return Ok(ProjectionOutput::default());
    }

    Ok(ProjectionOutput::rows(vec![schema::message_row(
        event.context.event_id,
        envelope.signer_endpoint_shared_id,
        &message,
    )?]))
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::identity::{endpoint_shared, signed, user};
    use crate::protocol::event_modules::types::event_id;
    use crate::protocol::event_modules::worker::{
        DependencyContext, EventContext, EventWithContext,
    };

    use super::super::types::MessageEvent;
    use super::*;

    type Record = crate::protocol::event_modules::types::EventRecord;

    fn signing_public_key_for(private_key: &[u8; 32]) -> [u8; 32] {
        codec::sign([0; 32], private_key, vec![codec::TYPE_MESSAGE]).signer_public_key
    }

    fn endpoint_shared_record(
        workspace_id: [u8; 32],
        user_id: [u8; 32],
        signing_public_key: [u8; 32],
    ) -> Record {
        let payload =
            endpoint_shared::codec::encode(&endpoint_shared::types::EndpointSharedEvent {
                created_at_ms: 4,
                workspace_id,
                user_authority_event_id: user_id,
                endpoint_id: [21; 32],
                signing_public_key,
                device_name: "laptop".to_string(),
            })
            .expect("encode endpoint_shared");
        let signed = signed::commands::sign_payload([6; 32], &[5; 32], payload)
            .expect("sign endpoint_shared");
        signed.events[0].record().clone()
    }

    fn user_record(workspace_id: [u8; 32]) -> Record {
        let payload = user::codec::encode(&user::types::UserEvent {
            created_at_ms: 3,
            workspace_id,
            public_key: [22; 32],
            username: "alice".to_string(),
        })
        .expect("encode user");
        let signed =
            signed::commands::sign_payload([24; 32], &[25; 32], payload).expect("sign user");
        signed.events[0].record().clone()
    }

    fn build(
        workspace_id: [u8; 32],
        author_user_id: [u8; 32],
        signer_private_key: &[u8; 32],
        signer_endpoint_shared_id: [u8; 32],
    ) -> (Record, [u8; 32]) {
        let payload = codec::encode(&MessageEvent {
            workspace_id,
            created_at_ms: 5,
            author_user_id,
            text: "hello".to_string(),
        })
        .expect("encode message");
        let envelope = codec::sign(signer_endpoint_shared_id, signer_private_key, payload);
        let bytes = codec::encode_signed(&envelope);
        let id = event_id(&bytes);
        (codec::signed_record_from_bytes(bytes).expect("record"), id)
    }

    fn context_for<'a>(
        record: &'a Record,
        message_id: [u8; 32],
        signer_id: [u8; 32],
        signer_record: Record,
        author_id: [u8; 32],
        author_record: Record,
    ) -> EventWithContext<'a> {
        EventWithContext {
            record,
            context: EventContext {
                event_id: message_id,
                dependencies: vec![
                    DependencyContext {
                        event_id: signer_id,
                        record: signer_record,
                    },
                    DependencyContext {
                        event_id: author_id,
                        record: author_record,
                    },
                ],
                labels: Vec::new(),
                receive: None,
            },
        }
    }

    #[test]
    fn projects_message_row_for_workspace_member() {
        let workspace_id = [7; 32];
        let signer_private_key = [9; 32];
        let signer_pubkey = signing_public_key_for(&signer_private_key);
        let author_record = user_record(workspace_id);
        let author_id = event_id(&author_record.canonical_bytes);
        let signer_record = endpoint_shared_record(workspace_id, author_id, signer_pubkey);
        let signer_id = event_id(&signer_record.canonical_bytes);

        let (record, message_id) = build(workspace_id, author_id, &signer_private_key, signer_id);
        let event = context_for(
            &record,
            message_id,
            signer_id,
            signer_record,
            author_id,
            author_record,
        );

        let output = project(&event).expect("project message");
        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::MESSAGES);
        let row = schema::decode_message_row(&output.rows[0].key, &output.rows[0].value)
            .expect("decode row");
        assert_eq!(row.workspace_id, workspace_id);
        assert_eq!(row.message_id, message_id);
        assert_eq!(row.author_user_id, author_id);
        assert_eq!(row.signer_endpoint_shared_id, signer_id);
        assert_eq!(row.text, "hello");
    }

    #[test]
    fn rejects_workspace_metadata_mismatch() {
        let workspace_id = [7; 32];
        let signer_private_key = [9; 32];
        let signer_pubkey = signing_public_key_for(&signer_private_key);
        let author_record = user_record(workspace_id);
        let author_id = event_id(&author_record.canonical_bytes);
        let signer_record = endpoint_shared_record(workspace_id, author_id, signer_pubkey);
        let signer_id = event_id(&signer_record.canonical_bytes);

        let (mut record, message_id) =
            build(workspace_id, author_id, &signer_private_key, signer_id);
        record.workspace_id = Some([8; 32]);
        let event = context_for(
            &record,
            message_id,
            signer_id,
            signer_record,
            author_id,
            author_record,
        );

        assert_eq!(
            project(&event).expect_err("workspace mismatch must fail"),
            "message workspace metadata does not match event body"
        );
    }

    #[test]
    fn rejects_signer_for_other_workspace() {
        let workspace_id = [7; 32];
        let other_workspace_id = [8; 32];
        let signer_private_key = [9; 32];
        let signer_pubkey = signing_public_key_for(&signer_private_key);
        let author_record = user_record(workspace_id);
        let author_id = event_id(&author_record.canonical_bytes);
        let signer_record = endpoint_shared_record(other_workspace_id, author_id, signer_pubkey);
        let signer_id = event_id(&signer_record.canonical_bytes);

        let (record, message_id) = build(workspace_id, author_id, &signer_private_key, signer_id);
        let event = context_for(
            &record,
            message_id,
            signer_id,
            signer_record,
            author_id,
            author_record,
        );

        assert_eq!(
            project(&event).expect_err("workspace mismatch must fail"),
            "message signer endpoint_shared workspace does not match message"
        );
    }

    #[test]
    fn rejects_signer_pubkey_mismatch() {
        let workspace_id = [7; 32];
        let signer_private_key = [9; 32];
        let other_pubkey = signing_public_key_for(&[10; 32]);
        let author_record = user_record(workspace_id);
        let author_id = event_id(&author_record.canonical_bytes);
        let signer_record = endpoint_shared_record(workspace_id, author_id, other_pubkey);
        let signer_id = event_id(&signer_record.canonical_bytes);

        let (record, message_id) = build(workspace_id, author_id, &signer_private_key, signer_id);
        let event = context_for(
            &record,
            message_id,
            signer_id,
            signer_record,
            author_id,
            author_record,
        );

        assert_eq!(
            project(&event).expect_err("pubkey mismatch must fail"),
            "message signer public key does not match endpoint_shared"
        );
    }

    #[test]
    fn rejects_signer_not_authorized_by_author() {
        let workspace_id = [7; 32];
        let signer_private_key = [9; 32];
        let signer_pubkey = signing_public_key_for(&signer_private_key);
        let author_record = user_record(workspace_id);
        let author_id = event_id(&author_record.canonical_bytes);
        let other_user_id = [99; 32];
        let signer_record = endpoint_shared_record(workspace_id, other_user_id, signer_pubkey);
        let signer_id = event_id(&signer_record.canonical_bytes);

        let (record, message_id) = build(workspace_id, author_id, &signer_private_key, signer_id);
        let event = context_for(
            &record,
            message_id,
            signer_id,
            signer_record,
            author_id,
            author_record,
        );

        assert_eq!(
            project(&event).expect_err("author mismatch must fail"),
            "message signer endpoint is not authorized by the named author"
        );
    }

    #[test]
    fn purges_message_on_project_when_self_deletion_label_is_present() {
        use crate::protocol::event_modules::content::message_deletion::types::deletion_label;

        let workspace_id = [7; 32];
        let signer_private_key = [9; 32];
        let signer_pubkey = signing_public_key_for(&signer_private_key);
        let author_record = user_record(workspace_id);
        let author_id = event_id(&author_record.canonical_bytes);
        let signer_record = endpoint_shared_record(workspace_id, author_id, signer_pubkey);
        let signer_id = event_id(&signer_record.canonical_bytes);

        let (record, message_id) = build(workspace_id, author_id, &signer_private_key, signer_id);
        let mut event = context_for(
            &record,
            message_id,
            signer_id,
            signer_record,
            author_id,
            author_record,
        );
        event.context.labels.push(deletion_label(&author_id));

        let output = project(&event).expect("project deleted message");
        assert!(output.rows.is_empty());
        assert!(output.labels.is_empty());
    }

    #[test]
    fn ignores_deletion_label_authored_by_someone_other_than_message_author() {
        use crate::protocol::event_modules::content::message_deletion::types::deletion_label;

        let workspace_id = [7; 32];
        let signer_private_key = [9; 32];
        let signer_pubkey = signing_public_key_for(&signer_private_key);
        let author_record = user_record(workspace_id);
        let author_id = event_id(&author_record.canonical_bytes);
        let signer_record = endpoint_shared_record(workspace_id, author_id, signer_pubkey);
        let signer_id = event_id(&signer_record.canonical_bytes);

        let (record, message_id) = build(workspace_id, author_id, &signer_private_key, signer_id);
        let mut event = context_for(
            &record,
            message_id,
            signer_id,
            signer_record,
            author_id,
            author_record,
        );
        event.context.labels.push(deletion_label(&[42; 32]));

        let output = project(&event).expect("project not-by-author label");
        assert_eq!(output.rows.len(), 1);
    }

    #[test]
    fn raw_message_bytes_are_not_admissible() {
        let payload = codec::encode(&MessageEvent {
            workspace_id: [7; 32],
            created_at_ms: 5,
            author_user_id: [2; 32],
            text: "hello".to_string(),
        })
        .expect("encode message");

        assert_eq!(
            crate::protocol::event_modules::record_from_bytes(payload)
                .expect_err("raw message must fail"),
            "message must be signed"
        );
    }
}

//! Projector for signed message deletions.
//!
//! Deletion is projected as a single generic event label attached to the
//! target message id. The label payload encodes the deletion's `author_user_id`
//! so the message projector can purge-on-project iff the deleting user equals
//! the message's own author. The deletion event does not depend on the target
//! message; admission and projection are convergent under any arrival order.

use crate::protocol::event_modules::identity::{endpoint_shared, signed, user};
use crate::protocol::event_modules::schema::EventLabel;
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::codec;
use super::types::deletion_label;

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let envelope = codec::decode_signed(&event.record.canonical_bytes)?;
    let deletion = codec::decode(&envelope.payload)?;
    if event.record.workspace_id != Some(deletion.workspace_id) {
        return Err("deletion workspace metadata does not match event body".to_string());
    }

    let signer = event
        .context
        .dependency(&envelope.signer_endpoint_shared_id)
        .ok_or_else(|| "deletion signer endpoint_shared dependency is missing".to_string())?;
    let signer_envelope = signed::codec::decode(&signer.canonical_bytes)
        .map_err(|_| "deletion signer dependency is not a signed endpoint_shared".to_string())?;
    if signer_envelope.inner_type != endpoint_shared::codec::TYPE_ENDPOINT_SHARED {
        return Err("deletion signer dependency is not a signed endpoint_shared".to_string());
    }
    let signer_endpoint_shared = endpoint_shared::codec::decode(&signer_envelope.payload)
        .map_err(|_| "deletion signer dependency is not a signed endpoint_shared".to_string())?;
    if signer_endpoint_shared.workspace_id != deletion.workspace_id {
        return Err("deletion signer endpoint_shared workspace does not match deletion".to_string());
    }
    if signer_endpoint_shared.signing_public_key != envelope.signer_public_key {
        return Err("deletion signer public key does not match endpoint_shared".to_string());
    }
    if signer_endpoint_shared.user_authority_event_id != deletion.author_user_id {
        return Err("deletion signer endpoint is not authorized by the named author".to_string());
    }

    let author = event
        .context
        .dependency(&deletion.author_user_id)
        .ok_or_else(|| "deletion author user dependency is missing".to_string())?;
    let author_envelope = signed::codec::decode(&author.canonical_bytes)
        .map_err(|_| "deletion author dependency is not a signed user".to_string())?;
    if author_envelope.inner_type != user::codec::TYPE_USER {
        return Err("deletion author dependency is not a signed user".to_string());
    }
    let author_user = user::codec::decode(&author_envelope.payload)
        .map_err(|_| "deletion author dependency is not a signed user".to_string())?;
    if author_user.workspace_id != deletion.workspace_id {
        return Err("deletion author workspace does not match deletion".to_string());
    }

    Ok(ProjectionOutput::rows_and_labels(
        Vec::new(),
        vec![EventLabel {
            event_id: deletion.target_message_id,
            label: deletion_label(&deletion.author_user_id),
        }],
    ))
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::identity::{endpoint_shared, signed, user};
    use crate::protocol::event_modules::types::{event_id, EventScope};
    use crate::protocol::event_modules::worker::{
        DependencyContext, EventContext, EventWithContext,
    };

    use super::super::types::{deletion_label, MessageDeletionEvent};
    use super::*;

    type Record = crate::protocol::event_modules::types::EventRecord;

    fn signing_public_key_for(private_key: &[u8; 32]) -> [u8; 32] {
        codec::sign([0; 32], private_key, vec![codec::TYPE_MESSAGE_DELETION]).signer_public_key
    }

    fn endpoint_shared_record(
        workspace_id: [u8; 32],
        user_id: [u8; 32],
        signing_public_key: [u8; 32],
    ) -> Record {
        let payload = endpoint_shared::codec::encode(&endpoint_shared::types::EndpointSharedEvent {
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
        let signed = signed::commands::sign_payload([24; 32], &[25; 32], payload)
            .expect("sign user");
        signed.events[0].record().clone()
    }

    fn build(
        workspace_id: [u8; 32],
        author_user_id: [u8; 32],
        target_message_id: [u8; 32],
        signer_id: [u8; 32],
        signer_private_key: &[u8; 32],
    ) -> (Record, [u8; 32]) {
        let payload = codec::encode(&MessageDeletionEvent {
            workspace_id,
            created_at_ms: 7,
            target_message_id,
            author_user_id,
        });
        let envelope = codec::sign(signer_id, signer_private_key, payload);
        let bytes = codec::encode_signed(&envelope);
        let id = event_id(&bytes);
        (
            codec::signed_record_from_bytes(bytes).expect("record"),
            id,
        )
    }

    #[test]
    fn projects_label_on_target_message_id_carrying_deletion_author() {
        let workspace_id = [7; 32];
        let signer_private_key = [9; 32];
        let signer_pubkey = signing_public_key_for(&signer_private_key);
        let author_record = user_record(workspace_id);
        let author_id = event_id(&author_record.canonical_bytes);
        let signer_record = endpoint_shared_record(workspace_id, author_id, signer_pubkey);
        let signer_id = event_id(&signer_record.canonical_bytes);
        let target_id = [99; 32];

        let (record, deletion_id) = build(
            workspace_id,
            author_id,
            target_id,
            signer_id,
            &signer_private_key,
        );

        let event = EventWithContext {
            record: &record,
            context: EventContext {
                event_id: deletion_id,
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
        };
        let output = project(&event).expect("project deletion");

        assert!(output.rows.is_empty());
        assert_eq!(output.labels.len(), 1);
        assert_eq!(output.labels[0].event_id, target_id);
        assert_eq!(output.labels[0].label, deletion_label(&author_id));
    }

    #[test]
    fn rejects_signer_for_other_workspace() {
        let workspace_id = [7; 32];
        let other_workspace = [8; 32];
        let signer_private_key = [9; 32];
        let signer_pubkey = signing_public_key_for(&signer_private_key);
        let author_record = user_record(workspace_id);
        let author_id = event_id(&author_record.canonical_bytes);
        let signer_record = endpoint_shared_record(other_workspace, author_id, signer_pubkey);
        let signer_id = event_id(&signer_record.canonical_bytes);

        let (record, deletion_id) =
            build(workspace_id, author_id, [99; 32], signer_id, &signer_private_key);

        let event = EventWithContext {
            record: &record,
            context: EventContext {
                event_id: deletion_id,
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
        };

        assert_eq!(
            project(&event).expect_err("workspace mismatch must fail"),
            "deletion signer endpoint_shared workspace does not match deletion"
        );
    }

    #[test]
    fn record_has_three_dependencies_signer_workspace_author_only() {
        let payload = codec::encode(&MessageDeletionEvent {
            workspace_id: [7; 32],
            created_at_ms: 5,
            target_message_id: [10; 32],
            author_user_id: [11; 32],
        });
        let envelope = codec::sign([12; 32], &[13; 32], payload);
        let bytes = codec::encode_signed(&envelope);
        let record = codec::signed_record_from_bytes(bytes).expect("record");
        assert_eq!(record.dependencies, vec![[12; 32], [7; 32], [11; 32]]);
        assert_eq!(record.scope, EventScope::Shared);
    }

    #[test]
    fn raw_deletion_bytes_are_not_admissible() {
        let payload = codec::encode(&MessageDeletionEvent {
            workspace_id: [7; 32],
            created_at_ms: 5,
            target_message_id: [2; 32],
            author_user_id: [3; 32],
        });
        assert_eq!(
            crate::protocol::event_modules::record_from_bytes(payload)
                .expect_err("raw deletion must fail"),
            "message deletion must be signed"
        );
    }
}

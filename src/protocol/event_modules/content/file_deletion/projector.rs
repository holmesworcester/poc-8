//! Projector for signed file deletions.
//!
//! Deletion is projected as a generic event label attached to the target
//! file event id plus an exact delete for the file projection rows. The
//! label handles tombstone-before-file order; the deletes handle
//! file-before-tombstone order. The deletion event does not depend on the
//! target file event, so admission and projection are convergent under
//! either arrival order.
//!
//! Slice projection rows for the file's `file_id` cannot be deleted here
//! because the projector lacks the file's clear-text `file_id` (the
//! deletion event names only the file event id). The content purge worker
//! observes the deletion label, decodes the file's canonical bytes if they
//! are still present, and drops the slice rows there. Projector deletes
//! cover the descriptor's primary projection rows that are keyed by
//! `(workspace_id, file_event_id)` and are addressable from the deletion's
//! workspace + target id alone.

use crate::protocol::event_modules::content::file;
use crate::protocol::event_modules::content::message_deletion::schema as shared_schema;
use crate::protocol::event_modules::identity::{endpoint_shared, signed, user};
use crate::protocol::event_modules::schema::EventLabel;
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput, TableDelete};

use super::codec;
use super::types::deletion_label;

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let envelope = codec::decode_signed(&event.record.canonical_bytes)?;
    let deletion = codec::decode(&envelope.payload)?;
    if event.record.workspace_id != Some(deletion.workspace_id) {
        return Err("file deletion workspace metadata does not match event body".to_string());
    }

    let signer = event
        .context
        .dependency(&envelope.signer_endpoint_shared_id)
        .ok_or_else(|| "file deletion signer endpoint_shared dependency is missing".to_string())?;
    let signer_envelope = signed::codec::decode(&signer.canonical_bytes).map_err(|_| {
        "file deletion signer dependency is not a signed endpoint_shared".to_string()
    })?;
    if signer_envelope.inner_type != endpoint_shared::codec::TYPE_ENDPOINT_SHARED {
        return Err("file deletion signer dependency is not a signed endpoint_shared".to_string());
    }
    let signer_endpoint_shared =
        endpoint_shared::codec::decode(&signer_envelope.payload).map_err(|_| {
            "file deletion signer dependency is not a signed endpoint_shared".to_string()
        })?;
    if signer_endpoint_shared.workspace_id != deletion.workspace_id {
        return Err(
            "file deletion signer endpoint_shared workspace does not match deletion".to_string(),
        );
    }
    if signer_endpoint_shared.signing_public_key != envelope.signer_public_key {
        return Err("file deletion signer public key does not match endpoint_shared".to_string());
    }
    if signer_endpoint_shared.user_authority_event_id != deletion.author_user_id {
        return Err(
            "file deletion signer endpoint is not authorized by the named author".to_string(),
        );
    }

    let author = event
        .context
        .dependency(&deletion.author_user_id)
        .ok_or_else(|| "file deletion author user dependency is missing".to_string())?;
    let author_envelope = signed::codec::decode(&author.canonical_bytes)
        .map_err(|_| "file deletion author dependency is not a signed user".to_string())?;
    if author_envelope.inner_type != user::codec::TYPE_USER {
        return Err("file deletion author dependency is not a signed user".to_string());
    }
    let author_user = user::codec::decode(&author_envelope.payload)
        .map_err(|_| "file deletion author dependency is not a signed user".to_string())?;
    if author_user.workspace_id != deletion.workspace_id {
        return Err("file deletion author workspace does not match deletion".to_string());
    }

    let mut output = ProjectionOutput::rows(vec![shared_schema::purge_pending_row(
        deletion.target_file_event_id,
    )]);
    output.append(ProjectionOutput::deletes_and_labels(
        vec![TableDelete {
            table: file::schema::FILES,
            key: file::schema::file_key(deletion.workspace_id, deletion.target_file_event_id),
        }],
        vec![EventLabel {
            event_id: deletion.target_file_event_id,
            label: deletion_label(&deletion.author_user_id),
        }],
    ));
    Ok(output)
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::identity::{endpoint_shared, signed, user};
    use crate::protocol::event_modules::types::{event_id, EventScope};
    use crate::protocol::event_modules::worker::{
        DependencyContext, EventContext, EventWithContext,
    };

    use super::super::types::{deletion_label, FileDeletionEvent};
    use super::*;

    type Record = crate::protocol::event_modules::types::EventRecord;

    fn signing_public_key_for(private_key: &[u8; 32]) -> [u8; 32] {
        codec::sign([0; 32], private_key, vec![codec::TYPE_FILE_DELETION]).signer_public_key
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
                endpoint_role:
                    crate::protocol::event_modules::identity::endpoint::types::EndpointRole::Device,
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
        target_file_event_id: [u8; 32],
        signer_id: [u8; 32],
        signer_private_key: &[u8; 32],
    ) -> (Record, [u8; 32]) {
        let payload = codec::encode(&FileDeletionEvent {
            workspace_id,
            created_at_ms: 7,
            target_file_event_id,
            author_user_id,
        });
        let envelope = codec::sign(signer_id, signer_private_key, payload);
        let bytes = codec::encode_signed(&envelope);
        let id = event_id(&bytes);
        (codec::signed_record_from_bytes(bytes).expect("record"), id)
    }

    #[test]
    fn projects_label_on_target_file_id_carrying_deletion_author() {
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
                now_unix_minute: None,
            },
        };
        let output = project(&event).expect("project deletion");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(
            output.rows[0].table,
            crate::protocol::event_modules::content::message_deletion::schema::CONTENT_PURGE_PENDING
        );
        assert_eq!(output.rows[0].key, target_id.to_vec());
        assert_eq!(output.deletes.len(), 1);
        assert_eq!(output.deletes[0].table, file::schema::FILES);
        assert_eq!(
            output.deletes[0].key,
            file::schema::file_key(workspace_id, target_id)
        );
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

        let (record, deletion_id) = build(
            workspace_id,
            author_id,
            [99; 32],
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
                now_unix_minute: None,
            },
        };

        assert_eq!(
            project(&event).expect_err("workspace mismatch must fail"),
            "file deletion signer endpoint_shared workspace does not match deletion"
        );
    }

    #[test]
    fn record_has_three_dependencies_signer_workspace_author_only() {
        let payload = codec::encode(&FileDeletionEvent {
            workspace_id: [7; 32],
            created_at_ms: 5,
            target_file_event_id: [10; 32],
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
        let payload = codec::encode(&FileDeletionEvent {
            workspace_id: [7; 32],
            created_at_ms: 5,
            target_file_event_id: [2; 32],
            author_user_id: [3; 32],
        });
        assert_eq!(
            crate::protocol::event_modules::record_from_bytes(payload)
                .expect_err("raw deletion must fail"),
            "file deletion must be signed"
        );
    }
}

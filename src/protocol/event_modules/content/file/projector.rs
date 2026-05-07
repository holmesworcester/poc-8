//! Projector for signed file descriptors.
//!
//! The descriptor names a workspace-scoped file attached to a message. The
//! projector validates the signer endpoint_shared, the named author, and that
//! the parent message lives in the same workspace. The descriptor row, plus a
//! by-message index row and a by-file_id index row, is written atomically; the
//! file_slice projector uses the by-file_id index to dereference the descriptor
//! when slices arrive in any order.

use crate::protocol::event_modules::content::message;
use crate::protocol::event_modules::identity::{endpoint_shared, signed, user};
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::{codec, schema};

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let envelope = codec::decode_signed(&event.record.canonical_bytes)?;
    let file = codec::decode(&envelope.payload)?;
    if event.record.workspace_id != Some(file.workspace_id) {
        return Err("file workspace metadata does not match event body".to_string());
    }

    let signer = event
        .context
        .dependency(&envelope.signer_endpoint_shared_id)
        .ok_or_else(|| "file signer endpoint_shared dependency is missing".to_string())?;
    let signer_envelope = signed::codec::decode(&signer.canonical_bytes)
        .map_err(|_| "file signer dependency is not a signed endpoint_shared".to_string())?;
    if signer_envelope.inner_type != endpoint_shared::codec::TYPE_ENDPOINT_SHARED {
        return Err("file signer dependency is not a signed endpoint_shared".to_string());
    }
    let signer_endpoint_shared = endpoint_shared::codec::decode(&signer_envelope.payload)
        .map_err(|_| "file signer dependency is not a signed endpoint_shared".to_string())?;
    if signer_endpoint_shared.workspace_id != file.workspace_id {
        return Err("file signer endpoint_shared workspace does not match file".to_string());
    }
    if signer_endpoint_shared.signing_public_key != envelope.signer_public_key {
        return Err("file signer public key does not match endpoint_shared".to_string());
    }
    if signer_endpoint_shared.user_authority_event_id != file.author_user_id {
        return Err("file signer endpoint is not authorized by the named author".to_string());
    }

    let author = event
        .context
        .dependency(&file.author_user_id)
        .ok_or_else(|| "file author user dependency is missing".to_string())?;
    let author_envelope = signed::codec::decode(&author.canonical_bytes)
        .map_err(|_| "file author dependency is not a signed user".to_string())?;
    if author_envelope.inner_type != user::codec::TYPE_USER {
        return Err("file author dependency is not a signed user".to_string());
    }
    let author_user = user::codec::decode(&author_envelope.payload)
        .map_err(|_| "file author dependency is not a signed user".to_string())?;
    if author_user.workspace_id != file.workspace_id {
        return Err("file author workspace does not match file".to_string());
    }

    let parent = event
        .context
        .dependency(&file.message_id)
        .ok_or_else(|| "file parent message dependency is missing".to_string())?;
    let parent_envelope = message::codec::decode_signed(&parent.canonical_bytes)
        .map_err(|_| "file parent dependency is not a signed message".to_string())?;
    let parent_message = message::codec::decode(&parent_envelope.payload)
        .map_err(|_| "file parent dependency is not a signed message".to_string())?;
    if parent_message.workspace_id != file.workspace_id {
        return Err("file parent message workspace does not match file".to_string());
    }

    Ok(ProjectionOutput::rows(schema::file_rows(
        event.context.event_id,
        envelope.signer_endpoint_shared_id,
        &file,
    )?))
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::content::message;
    use crate::protocol::event_modules::identity::{endpoint_shared, signed, user};
    use crate::protocol::event_modules::types::{event_id, EventScope};
    use crate::protocol::event_modules::worker::{
        DependencyContext, EventContext, EventWithContext,
    };

    use super::super::types::FileEvent;
    use super::*;

    type Record = crate::protocol::event_modules::types::EventRecord;

    fn signing_public_key_for(private_key: &[u8; 32]) -> [u8; 32] {
        codec::sign([0; 32], private_key, vec![codec::TYPE_FILE]).signer_public_key
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

    fn message_record(workspace_id: [u8; 32], author_user_id: [u8; 32]) -> Record {
        let payload = message::codec::encode(&message::types::MessageEvent {
            workspace_id,
            created_at_ms: 1,
            author_user_id,
            removal_frontier_id: [30; 32],
            local_history_node_secret_id: [31; 32],
            nonce: [32; crate::core::crypto::XCHACHA20_POLY1305_NONCE_BYTES],
            ciphertext: [33; message::types::MESSAGE_CIPHERTEXT_BYTES],
        });
        let envelope = message::codec::sign([42; 32], &[43; 32], payload);
        let bytes = message::codec::encode_signed(&envelope);
        message::codec::signed_record_from_bytes(bytes).expect("record")
    }

    fn build(
        workspace_id: [u8; 32],
        author_user_id: [u8; 32],
        message_id: [u8; 32],
        signer_id: [u8; 32],
        signer_private_key: &[u8; 32],
    ) -> (Record, [u8; 32]) {
        let payload = codec::encode(&FileEvent {
            workspace_id,
            created_at_ms: 5,
            message_id,
            author_user_id,
            file_id: [99; 32],
            blob_bytes: 1024,
            total_slices: 1,
            slice_bytes: 1024,
            root_hash: [44; 32],
            filename: "photo.jpg".to_string(),
            mime_type: "image/jpeg".to_string(),
        })
        .expect("encode file");
        let envelope = codec::sign(signer_id, signer_private_key, payload);
        let bytes = codec::encode_signed(&envelope);
        let id = event_id(&bytes);
        (codec::signed_record_from_bytes(bytes).expect("record"), id)
    }

    #[test]
    fn projects_descriptor_with_message_and_file_id_indexes() {
        let workspace_id = [7; 32];
        let signer_private_key = [9; 32];
        let signer_pubkey = signing_public_key_for(&signer_private_key);
        let author_record = user_record(workspace_id);
        let author_id = event_id(&author_record.canonical_bytes);
        let signer_record = endpoint_shared_record(workspace_id, author_id, signer_pubkey);
        let signer_id = event_id(&signer_record.canonical_bytes);
        let parent_record = message_record(workspace_id, author_id);
        let parent_id = event_id(&parent_record.canonical_bytes);

        let (record, file_event_id) = build(
            workspace_id,
            author_id,
            parent_id,
            signer_id,
            &signer_private_key,
        );

        let event = EventWithContext {
            record: &record,
            context: EventContext {
                event_id: file_event_id,
                dependencies: vec![
                    DependencyContext {
                        event_id: signer_id,
                        record: signer_record,
                    },
                    DependencyContext {
                        event_id: author_id,
                        record: author_record,
                    },
                    DependencyContext {
                        event_id: parent_id,
                        record: parent_record,
                    },
                ],
                labels: Vec::new(),
                receive: None,
            },
        };
        let output = project(&event).expect("project file");

        assert_eq!(output.rows.len(), 3);
        assert_eq!(output.rows[0].table, schema::FILES);
        assert_eq!(output.rows[1].table, schema::FILES_BY_MESSAGE);
        assert_eq!(output.rows[2].table, schema::FILES_BY_FILE_ID);
        let row = schema::decode_file_row(&output.rows[0].key, &output.rows[0].value)
            .expect("decode row");
        assert_eq!(row.workspace_id, workspace_id);
        assert_eq!(row.file_event_id, file_event_id);
        assert_eq!(row.message_id, parent_id);
        assert_eq!(row.file_id, [99; 32]);
        assert_eq!(row.blob_bytes, 1024);
        assert_eq!(row.total_slices, 1);
        assert_eq!(row.filename, "photo.jpg");
        assert_eq!(row.mime_type, "image/jpeg");
    }

    #[test]
    fn rejects_parent_message_for_other_workspace() {
        let workspace_id = [7; 32];
        let other_workspace = [8; 32];
        let signer_private_key = [9; 32];
        let signer_pubkey = signing_public_key_for(&signer_private_key);
        let author_record = user_record(workspace_id);
        let author_id = event_id(&author_record.canonical_bytes);
        let signer_record = endpoint_shared_record(workspace_id, author_id, signer_pubkey);
        let signer_id = event_id(&signer_record.canonical_bytes);
        let parent_record = message_record(other_workspace, author_id);
        let parent_id = event_id(&parent_record.canonical_bytes);

        let (record, file_event_id) = build(
            workspace_id,
            author_id,
            parent_id,
            signer_id,
            &signer_private_key,
        );

        let event = EventWithContext {
            record: &record,
            context: EventContext {
                event_id: file_event_id,
                dependencies: vec![
                    DependencyContext {
                        event_id: signer_id,
                        record: signer_record,
                    },
                    DependencyContext {
                        event_id: author_id,
                        record: author_record,
                    },
                    DependencyContext {
                        event_id: parent_id,
                        record: parent_record,
                    },
                ],
                labels: Vec::new(),
                receive: None,
            },
        };

        assert_eq!(
            project(&event).expect_err("workspace mismatch must fail"),
            "file parent message workspace does not match file"
        );
    }

    #[test]
    fn record_exposes_signer_workspace_author_message_dependencies() {
        let payload = codec::encode(&FileEvent {
            workspace_id: [7; 32],
            created_at_ms: 5,
            message_id: [10; 32],
            author_user_id: [11; 32],
            file_id: [99; 32],
            blob_bytes: 0,
            total_slices: 0,
            slice_bytes: 0,
            root_hash: [0; 32],
            filename: "empty".to_string(),
            mime_type: "application/octet-stream".to_string(),
        })
        .expect("encode");
        let envelope = codec::sign([12; 32], &[13; 32], payload);
        let bytes = codec::encode_signed(&envelope);
        let record = codec::signed_record_from_bytes(bytes).expect("record");
        assert_eq!(
            record.dependencies,
            vec![[12; 32], [7; 32], [11; 32], [10; 32]]
        );
        assert_eq!(record.scope, EventScope::Shared);
    }

    #[test]
    fn raw_file_bytes_are_not_admissible() {
        let payload = codec::encode(&FileEvent {
            workspace_id: [7; 32],
            created_at_ms: 5,
            message_id: [10; 32],
            author_user_id: [11; 32],
            file_id: [99; 32],
            blob_bytes: 0,
            total_slices: 0,
            slice_bytes: 0,
            root_hash: [0; 32],
            filename: "empty".to_string(),
            mime_type: "application/octet-stream".to_string(),
        })
        .expect("encode");
        assert_eq!(
            crate::protocol::event_modules::record_from_bytes(payload)
                .expect_err("raw file must fail"),
            "file must be signed"
        );
    }
}

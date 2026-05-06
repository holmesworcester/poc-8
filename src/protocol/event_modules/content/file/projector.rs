//! Projector for signed file descriptors.
//!
//! The descriptor names a workspace-scoped file attached to a message. The
//! projector validates the signer endpoint_shared, the named author, and that
//! the parent message lives in the same workspace. It then writes a sealed
//! descriptor row plus its by-message and by-file_id index rows; the sealed
//! row carries the AEAD nonce + ciphertext that conceal filename and mime,
//! along with all clear-text descriptor fields workers and queries need to
//! schedule slices and find the parent message. The read-side CLI opens the
//! sealed slot using the local key-secret named by `local_key_secret_id` to
//! display filename and mime.

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
    if parent_message.local_key_secret_id != file.local_key_secret_id {
        return Err(
            "file local key secret id does not match parent message local key secret".to_string(),
        );
    }

    Ok(ProjectionOutput::rows(schema::file_rows(
        event.context.event_id,
        envelope.signer_endpoint_shared_id,
        &file,
    )?))
}

#[cfg(test)]
mod tests {
    use crate::core::crypto::{
        self, XChaCha20Poly1305Key, XChaCha20Poly1305Nonce, XCHACHA20_POLY1305_NONCE_BYTES,
    };
    use crate::protocol::event_modules::content::message;
    use crate::protocol::event_modules::encryption::local_key_secret;
    use crate::protocol::event_modules::identity::{endpoint_shared, signed, user};
    use crate::protocol::event_modules::types::{event_id, EventScope};
    use crate::protocol::event_modules::worker::{
        DependencyContext, EventContext, EventWithContext,
    };

    use super::super::types::{
        FileDescriptorPlaintext, FileEvent, FILE_DESCRIPTOR_CIPHERTEXT_BYTES,
    };
    use super::*;

    type Record = crate::protocol::event_modules::types::EventRecord;

    const KEY_SECRET: XChaCha20Poly1305Key = [77; 32];
    const NONCE: XChaCha20Poly1305Nonce = [13; XCHACHA20_POLY1305_NONCE_BYTES];

    struct BuiltDescriptor {
        record: Record,
        file_event_id: [u8; 32],
        signer_id: [u8; 32],
        signer_record: Record,
        author_id: [u8; 32],
        author_record: Record,
        parent_id: [u8; 32],
        parent_record: Record,
        local_secret_id: [u8; 32],
        workspace_id: [u8; 32],
    }

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

    fn message_record(
        workspace_id: [u8; 32],
        author_user_id: [u8; 32],
        frontier_id: [u8; 32],
        local_key_secret_id: [u8; 32],
    ) -> Record {
        let payload = message::codec::encode(&message::types::MessageEvent {
            workspace_id,
            created_at_ms: 1,
            author_user_id,
            removal_frontier_id: frontier_id,
            local_key_secret_id,
            nonce: [32; XCHACHA20_POLY1305_NONCE_BYTES],
            ciphertext: [33; message::types::MESSAGE_CIPHERTEXT_BYTES],
        });
        let envelope = message::codec::sign([42; 32], &[43; 32], payload);
        let bytes = message::codec::encode_signed(&envelope);
        message::codec::signed_record_from_bytes(bytes).expect("record")
    }

    fn local_secret_record(
        workspace_id: [u8; 32],
        frontier_id: [u8; 32],
    ) -> (Record, [u8; 32]) {
        let output = local_key_secret::commands::from_key_secret(
            workspace_id,
            frontier_id,
            KEY_SECRET,
        )
        .expect("local key secret");
        (
            output.events[0].record().clone(),
            output.value.local_key_secret_id,
        )
    }

    fn build_descriptor(filename: &str, mime: &str) -> BuiltDescriptor {
        let workspace_id = [7; 32];
        let frontier_id = [30; 32];
        let signer_private_key = [9; 32];
        let signer_pubkey = signing_public_key_for(&signer_private_key);
        let author_record = user_record(workspace_id);
        let author_id = event_id(&author_record.canonical_bytes);
        let signer_record = endpoint_shared_record(workspace_id, author_id, signer_pubkey);
        let signer_id = event_id(&signer_record.canonical_bytes);
        let (_, local_secret_id) = local_secret_record(workspace_id, frontier_id);
        let parent_record =
            message_record(workspace_id, author_id, frontier_id, local_secret_id);
        let parent_id = event_id(&parent_record.canonical_bytes);

        let blob: Vec<u8> = (0..1024u32).map(|byte| byte as u8).collect();
        let (root_hash, _) = crypto::bao_outboard(&blob).expect("outboard");

        let mut event = FileEvent {
            workspace_id,
            created_at_ms: 5,
            message_id: parent_id,
            author_user_id: author_id,
            file_id: [99; 32],
            blob_bytes: blob.len() as u64,
            total_slices: 1,
            slice_bytes: 1024,
            root_hash,
            removal_frontier_id: frontier_id,
            local_key_secret_id: local_secret_id,
            nonce: NONCE,
            ciphertext: [0; FILE_DESCRIPTOR_CIPHERTEXT_BYTES],
        };
        let aad = codec::descriptor_associated_data(&event, signer_id);
        event.ciphertext = codec::seal_descriptor_slot(
            &KEY_SECRET,
            &event.nonce,
            &aad,
            &FileDescriptorPlaintext {
                filename: filename.to_string(),
                mime_type: mime.to_string(),
            },
        )
        .expect("seal descriptor");
        let payload = codec::encode(&event).expect("encode file");
        let envelope = codec::sign(signer_id, &signer_private_key, payload);
        let bytes = codec::encode_signed(&envelope);
        let id = event_id(&bytes);
        let record = codec::signed_record_from_bytes(bytes).expect("record");
        BuiltDescriptor {
            record,
            file_event_id: id,
            signer_id,
            signer_record,
            author_id,
            author_record,
            parent_id,
            parent_record,
            local_secret_id,
            workspace_id,
        }
    }

    fn context_for<'a>(built: &'a BuiltDescriptor) -> EventWithContext<'a> {
        EventWithContext {
            record: &built.record,
            context: EventContext {
                event_id: built.file_event_id,
                dependencies: vec![
                    DependencyContext {
                        event_id: built.signer_id,
                        record: built.signer_record.clone(),
                    },
                    DependencyContext {
                        event_id: built.author_id,
                        record: built.author_record.clone(),
                    },
                    DependencyContext {
                        event_id: built.parent_id,
                        record: built.parent_record.clone(),
                    },
                ],
                labels: Vec::new(),
                receive: None,
            },
        }
    }

    #[test]
    fn projects_sealed_descriptor_with_message_and_file_id_indexes() {
        let built = build_descriptor("photo.jpg", "image/jpeg");
        let event = context_for(&built);
        let output = project(&event).expect("project file");
        assert_eq!(output.rows.len(), 3);
        assert_eq!(output.rows[0].table, schema::FILES);
        assert_eq!(output.rows[1].table, schema::FILES_BY_MESSAGE);
        assert_eq!(output.rows[2].table, schema::FILES_BY_FILE_ID);
        let row = schema::decode_sealed_file_row(&output.rows[0].key, &output.rows[0].value)
            .expect("decode row");
        assert_eq!(row.workspace_id, built.workspace_id);
        assert_eq!(row.file_event_id, built.file_event_id);
        assert_eq!(row.local_key_secret_id, built.local_secret_id);
        // Sealed row never carries plaintext filename or mime.
        assert!(!row
            .ciphertext
            .windows("photo.jpg".len())
            .any(|w| w == b"photo.jpg"));
        assert!(!row
            .ciphertext
            .windows("image/jpeg".len())
            .any(|w| w == b"image/jpeg"));
    }

    #[test]
    fn rejects_parent_message_for_other_workspace() {
        let mut built = build_descriptor("a.bin", "application/octet-stream");
        let other_workspace = [8; 32];
        let other_parent = message_record(
            other_workspace,
            built.author_id,
            [30; 32],
            built.local_secret_id,
        );
        built.parent_id = event_id(&other_parent.canonical_bytes);
        built.parent_record = other_parent;

        let envelope =
            codec::decode_signed(&built.record.canonical_bytes).expect("decode signed");
        let mut file = codec::decode(&envelope.payload).expect("decode file");
        file.message_id = built.parent_id;
        let payload = codec::encode(&file).expect("re-encode");
        let resigned = codec::sign(built.signer_id, &[9; 32], payload);
        let bytes = codec::encode_signed(&resigned);
        built.file_event_id = crate::protocol::event_modules::types::event_id(&bytes);
        built.record = codec::signed_record_from_bytes(bytes).expect("record");

        let event = context_for(&built);
        assert_eq!(
            project(&event).expect_err("workspace mismatch must fail"),
            "file parent message workspace does not match file"
        );
    }

    #[test]
    fn rejects_descriptor_whose_local_key_secret_id_diverges_from_parent_message() {
        let mut built = build_descriptor("a.bin", "application/octet-stream");
        // Build a descriptor that references a different local_key_secret_id
        // than the parent message; the projector must reject so that purges
        // and key-blocked admission rules cannot be bypassed.
        let envelope =
            codec::decode_signed(&built.record.canonical_bytes).expect("decode signed");
        let mut file = codec::decode(&envelope.payload).expect("decode file");
        file.local_key_secret_id = [200; 32];
        let payload = codec::encode(&file).expect("re-encode");
        let resigned = codec::sign(built.signer_id, &[9; 32], payload);
        let bytes = codec::encode_signed(&resigned);
        built.file_event_id = crate::protocol::event_modules::types::event_id(&bytes);
        built.record = codec::signed_record_from_bytes(bytes).expect("record");

        let event = context_for(&built);
        assert_eq!(
            project(&event).expect_err("local_key_secret mismatch must fail"),
            "file local key secret id does not match parent message local key secret"
        );
    }

    #[test]
    fn record_exposes_signer_workspace_author_message_local_key_dependencies() {
        let built = build_descriptor("a.bin", "application/octet-stream");
        let record = &built.record;
        assert_eq!(
            record.dependencies,
            vec![
                built.signer_id,
                built.workspace_id,
                built.author_id,
                built.parent_id,
                built.local_secret_id,
            ]
        );
        assert_eq!(record.scope, EventScope::Shared);
    }

    #[test]
    fn raw_file_bytes_are_not_admissible() {
        let built = build_descriptor("a.bin", "application/octet-stream");
        let envelope =
            codec::decode_signed(&built.record.canonical_bytes).expect("decode signed");
        assert_eq!(
            crate::protocol::event_modules::record_from_bytes(envelope.payload)
                .expect_err("raw file must fail"),
            "file must be signed"
        );
    }
}

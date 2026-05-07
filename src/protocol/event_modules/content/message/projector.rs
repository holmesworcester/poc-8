//! Projector for signed messages.
//!
//! The shared event is the signed envelope. Projection validates that the
//! signer endpoint_shared belongs to the same workspace as the message body,
//! that the signer's public key matches the membership signing key, and that
//! the named author user is also a workspace member who signed off the
//! endpoint chain. The text itself is opaque; storage is keyed by workspace.

use crate::protocol::event_modules::content::message_deletion::types::deletion_label_author;
use crate::protocol::event_modules::identity::{endpoint_shared, signed, user};
use crate::protocol::event_modules::leaf_history_node;
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput, TableDelete};

use super::types::unix_minute_for;
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

    // Validate the binding to the per-message leaf event. The message's
    // canonical bytes name the leaf id as a dependency, so projection runs
    // after the leaf has been admitted by its own projector. The leaf event
    // body must declare the same `unix_minute` as the message and carry
    // `event_id_in_minute = Some(message.leaf_nonce)`.
    let leaf_record = event
        .context
        .dependency(&message.local_history_node_secret_id)
        .ok_or_else(|| "message leaf history node dependency is missing".to_string())?;
    let leaf = leaf_history_node::codec::decode(&leaf_record.canonical_bytes)
        .map_err(|_| "message leaf dependency is not a local_history_node_secret".to_string())?;
    if leaf.workspace_id != message.workspace_id
        || leaf.removal_frontier_id != message.removal_frontier_id
    {
        return Err("message leaf workspace or frontier does not match message".to_string());
    }
    let expected_minute = unix_minute_for(message.created_at_ms);
    if leaf.range_start != expected_minute || leaf.range_width != super::types::LEAF_RANGE_WIDTH {
        return Err("message leaf coordinate does not match message minute".to_string());
    }
    if leaf.event_id_in_minute != Some(message.leaf_nonce) {
        return Err("message leaf event_id_in_minute does not match message leaf_nonce".to_string());
    }

    // Purge-on-project: a deletion event labels its target message id with
    // `content.deleted:<author_user_id>`. If the tombstone arrived first, the
    // message is valid but must not leave a visible row behind.
    let is_deleted_by_author = event.context.labels.iter().any(|label| {
        deletion_label_author(label)
            .map(|author| author == message.author_user_id)
            .unwrap_or(false)
    });
    if is_deleted_by_author {
        let key = schema::message_key(message.workspace_id, event.context.event_id);
        return Ok(ProjectionOutput {
            rows: vec![schema::message_tombstone_row(
                message.workspace_id,
                event.context.event_id,
                message.author_user_id,
            )],
            deletes: vec![TableDelete {
                table: schema::MESSAGES,
                key,
            }],
            labels: Vec::new(),
        });
    }

    Ok(ProjectionOutput::rows(vec![schema::sealed_message_row(
        event.context.event_id,
        envelope.signer_endpoint_shared_id,
        &message,
    )?]))
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::encryption::local_history_node_secret as leaf_module;
    use crate::protocol::event_modules::identity::{endpoint_shared, signed, user};
    use crate::protocol::event_modules::types::event_id;
    use crate::protocol::event_modules::worker::{
        DependencyContext, EventContext, EventWithContext,
    };

    use super::super::types::{unix_minute_for, MessageEvent};
    use super::*;

    type Record = crate::protocol::event_modules::types::EventRecord;
    const KEY_SECRET: [u8; 32] = [77; 32];

    struct BuiltMessage {
        record: Record,
        message_id: [u8; 32],
        leaf_id: [u8; 32],
        leaf_record: Record,
    }

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
        signer_private_key: &[u8; 32],
        signer_endpoint_shared_id: [u8; 32],
    ) -> BuiltMessage {
        let created_at_ms = 5u64;
        let removal_frontier_id = [30; 32];
        // Mint a real leaf event for `(unix_minute_for(5), leaf_nonce)` so
        // the projector's leaf-binding check has a real local_history_node_secret
        // dependency. Source it from a stub minute_node id so derivation
        // succeeds; production would source from the minute_node admitted
        // earlier in the worker.
        let leaf_nonce = [44; 32];
        let leaf_output = leaf_module::commands::derive(leaf_module::commands::DeriveHistoryNodeSecret {
            workspace_id,
            removal_frontier_id,
            source_secret_id: [200; 32],
            source_secret: [201; 32],
            range_start: unix_minute_for(created_at_ms),
            range_width: super::super::types::LEAF_RANGE_WIDTH,
            event_id_in_minute: Some(leaf_nonce),
            tombstone_node_id: None,
        })
        .expect("derive leaf for projector test");
        let leaf_record = leaf_output.events[0].record().clone();
        let leaf_id = leaf_output.value.local_history_node_secret_id;
        let output = super::super::commands::send(super::super::commands::SendMessage {
            workspace_id,
            created_at_ms,
            author_user_id,
            signer_endpoint_shared_id,
            signer_private_key: *signer_private_key,
            removal_frontier_id,
            local_history_node_secret_id: leaf_id,
            leaf_nonce,
            leaf_node_secret: KEY_SECRET,
            text: "hello".to_string(),
        })
        .expect("send");
        let record = output.events[0].record().clone();
        BuiltMessage {
            record,
            message_id: output.value.message_id,
            leaf_id,
            leaf_record,
        }
    }

    fn context_for<'a>(
        built: &'a BuiltMessage,
        signer_id: [u8; 32],
        signer_record: Record,
        author_id: [u8; 32],
        author_record: Record,
    ) -> EventWithContext<'a> {
        EventWithContext {
            record: &built.record,
            context: EventContext {
                event_id: built.message_id,
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
                        event_id: built.leaf_id,
                        record: built.leaf_record.clone(),
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

        let built = build(workspace_id, author_id, &signer_private_key, signer_id);
        let event = context_for(&built, signer_id, signer_record, author_id, author_record);

        let output = project(&event).expect("project message");
        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::SEALED_MESSAGES);
        let row = schema::decode_sealed_message_row(&output.rows[0].key, &output.rows[0].value)
            .expect("decode sealed row");
        assert_eq!(row.workspace_id, workspace_id);
        assert_eq!(row.message_id, built.message_id);
        assert_eq!(row.author_user_id, author_id);
        assert_eq!(row.signer_endpoint_shared_id, signer_id);
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

        let mut built = build(workspace_id, author_id, &signer_private_key, signer_id);
        built.record.workspace_id = Some([8; 32]);
        let event = context_for(&built, signer_id, signer_record, author_id, author_record);

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

        let built = build(workspace_id, author_id, &signer_private_key, signer_id);
        let event = context_for(&built, signer_id, signer_record, author_id, author_record);

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

        let built = build(workspace_id, author_id, &signer_private_key, signer_id);
        let event = context_for(&built, signer_id, signer_record, author_id, author_record);

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

        let built = build(workspace_id, author_id, &signer_private_key, signer_id);
        let event = context_for(&built, signer_id, signer_record, author_id, author_record);

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

        let built = build(workspace_id, author_id, &signer_private_key, signer_id);
        let mut event = context_for(&built, signer_id, signer_record, author_id, author_record);
        event.context.labels.push(deletion_label(&author_id));

        let output = project(&event).expect("project deleted message");
        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::MESSAGE_TOMBSTONES);
        assert!(output.labels.is_empty());
        assert_eq!(output.deletes.len(), 1);
        assert_eq!(output.deletes[0].table, schema::MESSAGES);
        assert_eq!(
            output.deletes[0].key,
            schema::message_key(workspace_id, built.message_id)
        );
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

        let built = build(workspace_id, author_id, &signer_private_key, signer_id);
        let mut event = context_for(&built, signer_id, signer_record, author_id, author_record);
        event.context.labels.push(deletion_label(&[42; 32]));

        let output = project(&event).expect("project not-by-author label");
        assert_eq!(output.rows.len(), 1);
        assert!(output.deletes.is_empty());
    }

    #[test]
    fn raw_message_bytes_are_not_admissible() {
        let payload = codec::encode(&MessageEvent {
            workspace_id: [7; 32],
            created_at_ms: 5,
            author_user_id: [2; 32],
            removal_frontier_id: [3; 32],
            local_history_node_secret_id: [4; 32],
            leaf_nonce: [10; 32],
            nonce: [5; 24],
            ciphertext: [6; super::super::types::MESSAGE_CIPHERTEXT_BYTES],
        });

        assert_eq!(
            crate::protocol::event_modules::record_from_bytes(payload)
                .expect_err("raw message must fail"),
            "message must be signed"
        );
    }
}

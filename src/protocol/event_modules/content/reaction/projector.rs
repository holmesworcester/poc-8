//! Projector for signed reactions.
//!
//! The reaction projector validates the signer endpoint_shared, the named
//! author user, and that the target message exists in the same workspace.
//! Storage is keyed by workspace; display-time grouping by `(author, emoji)`
//! preserves the poc-7 reaction summary rule without an extra index.

use crate::protocol::event_modules::content::message;
use crate::protocol::event_modules::identity::{endpoint_shared, signed, user};
use crate::protocol::event_modules::leaf_history_node;
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::{codec, schema};

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let envelope = codec::decode_signed(&event.record.canonical_bytes)?;
    let reaction = codec::decode(&envelope.payload)?;
    if event.record.workspace_id != Some(reaction.workspace_id) {
        return Err("reaction workspace metadata does not match event body".to_string());
    }

    let signer = event
        .context
        .dependency(&envelope.signer_endpoint_shared_id)
        .ok_or_else(|| "reaction signer endpoint_shared dependency is missing".to_string())?;
    let signer_envelope = signed::codec::decode(&signer.canonical_bytes)
        .map_err(|_| "reaction signer dependency is not a signed endpoint_shared".to_string())?;
    if signer_envelope.inner_type != endpoint_shared::codec::TYPE_ENDPOINT_SHARED {
        return Err("reaction signer dependency is not a signed endpoint_shared".to_string());
    }
    let signer_endpoint_shared = endpoint_shared::codec::decode(&signer_envelope.payload)
        .map_err(|_| "reaction signer dependency is not a signed endpoint_shared".to_string())?;
    if signer_endpoint_shared.workspace_id != reaction.workspace_id {
        return Err(
            "reaction signer endpoint_shared workspace does not match reaction".to_string(),
        );
    }
    if signer_endpoint_shared.signing_public_key != envelope.signer_public_key {
        return Err("reaction signer public key does not match endpoint_shared".to_string());
    }
    if signer_endpoint_shared.user_authority_event_id != reaction.author_user_id {
        return Err("reaction signer endpoint is not authorized by the named author".to_string());
    }

    let author = event
        .context
        .dependency(&reaction.author_user_id)
        .ok_or_else(|| "reaction author user dependency is missing".to_string())?;
    let author_envelope = signed::codec::decode(&author.canonical_bytes)
        .map_err(|_| "reaction author dependency is not a signed user".to_string())?;
    if author_envelope.inner_type != user::codec::TYPE_USER {
        return Err("reaction author dependency is not a signed user".to_string());
    }
    let author_user = user::codec::decode(&author_envelope.payload)
        .map_err(|_| "reaction author dependency is not a signed user".to_string())?;
    if author_user.workspace_id != reaction.workspace_id {
        return Err("reaction author workspace does not match reaction".to_string());
    }

    let target = event
        .context
        .dependency(&reaction.target_message_id)
        .ok_or_else(|| "reaction target message dependency is missing".to_string())?;
    let target_envelope = message::codec::decode_signed(&target.canonical_bytes)
        .map_err(|_| "reaction target dependency is not a signed message".to_string())?;
    let target_message = message::codec::decode(&target_envelope.payload)
        .map_err(|_| "reaction target dependency is not a signed message".to_string())?;
    if target_message.workspace_id != reaction.workspace_id {
        return Err("reaction target message workspace does not match reaction".to_string());
    }

    // Validate the binding to the per-reaction leaf event named in canonical
    // bytes. The leaf must live in the reaction's `unix_minute` and carry
    // `event_id_in_minute = Some(reaction.event_id_in_minute_derived())`. The
    // projector recomputes the deterministic leaf coord from canonical
    // fields rather than trusting any wire-side nonce.
    let leaf_record = event
        .context
        .dependency(&reaction.local_history_node_secret_id)
        .ok_or_else(|| "reaction leaf history node dependency is missing".to_string())?;
    let leaf = leaf_history_node::codec::decode(&leaf_record.canonical_bytes)
        .map_err(|_| "reaction leaf dependency is not a local_history_node_secret".to_string())?;
    if leaf.workspace_id != reaction.workspace_id
        || leaf.removal_frontier_id != reaction.removal_frontier_id
    {
        return Err("reaction leaf workspace or frontier does not match reaction".to_string());
    }
    let expected_minute = message::types::unix_minute_for(reaction.created_at_ms);
    if leaf.range_start != expected_minute || leaf.range_width != message::types::LEAF_RANGE_WIDTH {
        return Err("reaction leaf coordinate does not match reaction minute".to_string());
    }
    if leaf.bit_depth != leaf_history_node::types::TRIE_LEAF_BIT_DEPTH
        || leaf.event_id_prefix != reaction.event_id_in_minute_derived()
    {
        return Err(
            "reaction leaf event_id_in_minute does not match deterministic reaction coord"
                .to_string(),
        );
    }

    Ok(ProjectionOutput::rows(vec![schema::sealed_reaction_row(
        event.context.event_id,
        envelope.signer_endpoint_shared_id,
        &reaction,
    )?]))
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::content::message;
    use crate::protocol::event_modules::encryption::{
        local_history_node_secret as leaf_module, removal_frontier,
    };
    use crate::protocol::event_modules::identity::{endpoint_shared, signed, user};
    use crate::protocol::event_modules::types::{event_id, EventScope};
    use crate::protocol::event_modules::worker::{
        DependencyContext, EventContext, EventWithContext,
    };

    use super::super::types::ReactionEvent;
    use super::*;

    type Record = crate::protocol::event_modules::types::EventRecord;
    const KEY_SECRET: [u8; 32] = [77; 32];

    struct BuiltReaction {
        record: Record,
        reaction_id: [u8; 32],
        frontier_id: [u8; 32],
        frontier_record: Record,
        leaf_id: [u8; 32],
        leaf_record: Record,
    }

    fn signing_public_key_for(private_key: &[u8; 32]) -> [u8; 32] {
        codec::sign([0; 32], private_key, vec![codec::TYPE_REACTION]).signer_public_key
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

    fn target_message_record(workspace_id: [u8; 32], author_user_id: [u8; 32]) -> Record {
        let payload = message::codec::encode(&message::types::MessageEvent {
            workspace_id,
            created_at_ms: 1,
            author_user_id,
            removal_frontier_id: [30; 32],
            local_history_node_secret_id: [31; 32],
            expires_at_minute: u64::MAX,
            disappearing_setting_id: [1; 32],
            nonce: [32; crate::core::crypto::XCHACHA20_POLY1305_NONCE_BYTES],
            ciphertext: [33; message::types::MESSAGE_CIPHERTEXT_BYTES],
        });
        let envelope = message::codec::sign([42; 32], &[43; 32], payload);
        let bytes = message::codec::encode_signed(&envelope);
        message::codec::signed_record_from_bytes(bytes).expect("record")
    }

    fn build_reaction(
        workspace_id: [u8; 32],
        target_id: [u8; 32],
        author_id: [u8; 32],
        signer_id: [u8; 32],
        signer_private_key: [u8; 32],
    ) -> BuiltReaction {
        let frontier_record =
            removal_frontier::commands::create(removal_frontier::commands::CreateRemovalFrontier {
                workspace_id,
                created_at_ms: 4,
                authority_admin_id: [34; 32],
                signer_endpoint_shared_id: [35; 32],
                signer_private_key: [36; 32],
                removal_event_ids: Vec::new(),
            })
            .expect("frontier")
            .events[0]
                .record()
                .clone();
        let frontier_id = event_id(&frontier_record.canonical_bytes);
        let created_at_ms = 5u64;
        let event_id_in_minute = super::super::types::reaction_event_id_in_minute(
            &workspace_id,
            &author_id,
            &target_id,
            &frontier_id,
            created_at_ms,
        );
        let leaf_output =
            leaf_module::commands::derive_trie_split(leaf_module::commands::DeriveTrieSplit {
                workspace_id,
                removal_frontier_id: frontier_id,
                parent_secret_id: [200; 32],
                parent_secret: [201; 32],
                range_start: super::super::super::message::types::unix_minute_for(created_at_ms),
                parent_bit_depth: 0,
                parent_event_id_prefix: [0; 32],
                child_side: leaf_module::types::bit_at(&event_id_in_minute, 0),
                child_bit_depth: leaf_module::types::TRIE_LEAF_BIT_DEPTH,
                child_event_id_prefix: event_id_in_minute,
                tombstone_node_id: None,
            })
            .expect("derive leaf");
        let leaf_record = leaf_output.events[0].record().clone();
        let leaf_id = leaf_output.value.local_history_node_secret_id;
        let output = super::super::commands::post(super::super::commands::PostReaction {
            workspace_id,
            created_at_ms,
            target_message_id: target_id,
            author_user_id: author_id,
            signer_endpoint_shared_id: signer_id,
            signer_private_key,
            removal_frontier_id: frontier_id,
            local_history_node_secret_id: leaf_id,
            leaf_node_secret: KEY_SECRET,
            emoji: "🔥".to_string(),
        })
        .expect("post reaction");
        BuiltReaction {
            record: output.events[0].record().clone(),
            reaction_id: output.value.reaction_id,
            frontier_id,
            frontier_record,
            leaf_id,
            leaf_record,
        }
    }

    fn event_with_context<'a>(
        built: &'a BuiltReaction,
        signer_id: [u8; 32],
        signer_record: Record,
        author_id: [u8; 32],
        author_record: Record,
        target_id: [u8; 32],
        target_record: Record,
    ) -> EventWithContext<'a> {
        EventWithContext {
            record: &built.record,
            context: EventContext {
                event_id: built.reaction_id,
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
                        event_id: target_id,
                        record: target_record,
                    },
                    DependencyContext {
                        event_id: built.frontier_id,
                        record: built.frontier_record.clone(),
                    },
                    DependencyContext {
                        event_id: built.leaf_id,
                        record: built.leaf_record.clone(),
                    },
                ],
                labels: Vec::new(),
                receive: None,
                now_unix_minute: None,
            },
        }
    }

    #[test]
    fn projects_one_reaction_row() {
        let workspace_id = [7; 32];
        let signer_private_key = [9; 32];
        let signer_pubkey = signing_public_key_for(&signer_private_key);
        let author_record = user_record(workspace_id);
        let author_id = event_id(&author_record.canonical_bytes);
        let signer_record = endpoint_shared_record(workspace_id, author_id, signer_pubkey);
        let signer_id = event_id(&signer_record.canonical_bytes);
        let target_record = target_message_record(workspace_id, author_id);
        let target_id = event_id(&target_record.canonical_bytes);
        let built = build_reaction(
            workspace_id,
            target_id,
            author_id,
            signer_id,
            signer_private_key,
        );

        let event = event_with_context(
            &built,
            signer_id,
            signer_record,
            author_id,
            author_record,
            target_id,
            target_record,
        );
        let output = project(&event).expect("project reaction");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::SEALED_REACTIONS);
        let row = schema::decode_sealed_reaction_row(&output.rows[0].key, &output.rows[0].value)
            .expect("decode row");
        assert_eq!(row.workspace_id, workspace_id);
        assert_eq!(row.reaction_id, built.reaction_id);
        assert_eq!(row.target_message_id, target_id);
        assert_eq!(row.author_user_id, author_id);
        assert_eq!(row.signer_endpoint_shared_id, signer_id);
        assert_eq!(row.removal_frontier_id, built.frontier_id);
        assert_eq!(row.local_history_node_secret_id, built.leaf_id);
    }

    #[test]
    fn rejects_target_for_other_workspace() {
        let workspace_id = [7; 32];
        let other_workspace = [8; 32];
        let signer_private_key = [9; 32];
        let signer_pubkey = signing_public_key_for(&signer_private_key);
        let author_record = user_record(workspace_id);
        let author_id = event_id(&author_record.canonical_bytes);
        let signer_record = endpoint_shared_record(workspace_id, author_id, signer_pubkey);
        let signer_id = event_id(&signer_record.canonical_bytes);
        let target_record = target_message_record(other_workspace, author_id);
        let target_id = event_id(&target_record.canonical_bytes);

        let built = build_reaction(
            workspace_id,
            target_id,
            author_id,
            signer_id,
            signer_private_key,
        );
        let event = event_with_context(
            &built,
            signer_id,
            signer_record,
            author_id,
            author_record,
            target_id,
            target_record,
        );

        assert_eq!(
            project(&event).expect_err("workspace mismatch must fail"),
            "reaction target message workspace does not match reaction"
        );
    }

    #[test]
    fn record_exposes_signer_workspace_author_target_dependencies() {
        let workspace_id = [7; 32];
        let event = ReactionEvent {
            workspace_id,
            created_at_ms: 5,
            target_message_id: [10; 32],
            author_user_id: [11; 32],
            removal_frontier_id: [14; 32],
            local_history_node_secret_id: [15; 32],
            nonce: [16; crate::core::crypto::XCHACHA20_POLY1305_NONCE_BYTES],
            ciphertext: [17; super::super::types::REACTION_CIPHERTEXT_BYTES],
        };
        let payload = codec::encode(&event);
        let envelope = codec::sign([12; 32], &[13; 32], payload);
        let bytes = codec::encode_signed(&envelope);
        let record = codec::signed_record_from_bytes(bytes).expect("record");
        assert_eq!(
            record.dependencies,
            vec![[12; 32], [7; 32], [11; 32], [10; 32], [14; 32], [15; 32]]
        );
        assert_eq!(record.scope, EventScope::Shared);
    }

    #[test]
    fn raw_reaction_bytes_are_not_admissible() {
        let payload = codec::encode(&ReactionEvent {
            workspace_id: [7; 32],
            created_at_ms: 5,
            target_message_id: [2; 32],
            author_user_id: [3; 32],
            removal_frontier_id: [4; 32],
            local_history_node_secret_id: [5; 32],
            nonce: [6; crate::core::crypto::XCHACHA20_POLY1305_NONCE_BYTES],
            ciphertext: [7; super::super::types::REACTION_CIPHERTEXT_BYTES],
        });

        assert_eq!(
            crate::protocol::event_modules::event_from_bytes(payload)
                .expect_err("raw reaction must fail"),
            "reaction must be signed"
        );
    }
}

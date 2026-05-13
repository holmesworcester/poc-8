//! Projector for signed messages.
//!
//! The shared event is the signed envelope. Projection validates that the
//! signer endpoint_shared belongs to the same workspace as the message body,
//! that the signer's public key matches the membership signing key, and that
//! the named author user is also a workspace member who signed off the
//! endpoint chain. The text itself is opaque; storage is keyed by workspace.

use crate::protocol::event_modules::content::message_deletion::types::deletion_label_author;
use crate::protocol::event_modules::disappearing_messages_setting;
use crate::protocol::event_modules::identity::{endpoint_shared, signed, user};
use crate::protocol::event_modules::identity::workspace;
use crate::protocol::event_modules::leaf_history_node;
use crate::protocol::event_modules::types::{EventId, EventRecord};
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
    // `event_id_in_minute = Some(message.event_id_in_minute_derived())`. The
    // projector recomputes the deterministic leaf coordinate from canonical
    // fields rather than trusting any wire-side nonce.
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
    if leaf.bit_depth != leaf_history_node::types::TRIE_LEAF_BIT_DEPTH
        || leaf.event_id_prefix != message.event_id_in_minute_derived()
    {
        return Err(
            "message leaf event_id_in_minute does not match deterministic message coord"
                .to_string(),
        );
    }

    // Disappearing-messages policy validation: the message references a
    // disappearing-messages setting (a signed
    // `disappearing_messages_setting` event id) or the workspace event id
    // (slice-1 fallback) in canonical bytes. The projector verifies that
    // `expires_at_minute` matches what the referenced policy permits. A
    // mismatch rejects the message: an admin-signed setting establishes a
    // bound that authors must honor, and the projector enforces it. The
    // trust gap (a peer can still pick an *older* setting with a longer
    // TTL) is documented in `disappearing_messages_plan.md` §6.
    let permitted_ttl = resolve_permitted_ttl_minutes(
        event,
        message.workspace_id,
        message.disappearing_setting_id,
    )?;
    let authored_minute = unix_minute_for(message.created_at_ms);
    let expected_expires = if permitted_ttl == 0 {
        super::types::EXPIRES_NEVER
    } else {
        authored_minute.saturating_add(permitted_ttl as u64)
    };
    if message.expires_at_minute != expected_expires {
        return Err(format!(
            "message expires_at_minute {} disagrees with referenced setting (permits ttl_minutes={}, expected {})",
            message.expires_at_minute, permitted_ttl, expected_expires
        ));
    }

    // Purge-on-project: drop the message's read-model and sealed rows when
    // the author has tombstoned the message (deletion label set on the
    // event by the deletion projector).
    //
    // Past-TTL re-deliveries are caught earlier, by the receive-side
    // admission gate (`schema::admit_check_received`), so by the time
    // projection runs the only remaining tombstone trigger is the
    // author-driven deletion label.
    let is_deleted_by_author = event.context.labels.iter().any(|label| {
        deletion_label_author(label)
            .map(|author| author == message.author_user_id)
            .unwrap_or(false)
    });
    if is_deleted_by_author {
        let key = schema::message_key(message.workspace_id, event.context.event_id);
        let sealed_key = schema::message_key(message.workspace_id, event.context.event_id);
        let output = ProjectionOutput {
            rows: vec![schema::message_tombstone_row(
                message.workspace_id,
                event.context.event_id,
                message.author_user_id,
                authored_minute,
            )],
            deletes: vec![
                TableDelete {
                    table: schema::MESSAGES,
                    key,
                },
                TableDelete {
                    table: schema::SEALED_MESSAGES,
                    key: sealed_key,
                },
            ],
            labels: Vec::new(),
        };
        return Ok(output);
    }

    Ok(ProjectionOutput::rows(vec![schema::sealed_message_row(
        event.context.event_id,
        envelope.signer_endpoint_shared_id,
        &message,
    )?]))
}

/// Look up the disappearing-messages policy referenced by a message and
/// return the `ttl_minutes` it permits. The reference is one of:
///   * The workspace event for this workspace — the slice-1 fallback
///     when no setting has been admitted. Returns the workspace event's
///     `disappearing_ttl_minutes`.
///   * A signed `disappearing_messages_setting` for the same workspace —
///     slice 2. Returns the setting's `ttl_minutes`.
/// Mismatched workspaces and dependency-type mismatches are rejected.
/// The setting module is reached through the
/// `protocol::event_modules::disappearing_messages_setting` alias to
/// keep the projector lint clean.
fn resolve_permitted_ttl_minutes(
    event: &EventWithContext<'_>,
    message_workspace_id: EventId,
    disappearing_setting_id: EventId,
) -> Result<u32, String> {
    let dependency = event
        .context
        .dependency(&disappearing_setting_id)
        .ok_or_else(|| "message disappearing_setting_id dependency is missing".to_string())?;
    if disappearing_setting_id == message_workspace_id {
        resolve_workspace_ttl(dependency, message_workspace_id)
    } else {
        resolve_setting_ttl(dependency, message_workspace_id, disappearing_setting_id)
    }
}

fn resolve_workspace_ttl(
    dependency: &EventRecord,
    message_workspace_id: EventId,
) -> Result<u32, String> {
    let workspace_event = workspace::codec::decode(&dependency.canonical_bytes).map_err(|_| {
        "message disappearing_setting_id references workspace_id but dependency is not a workspace event".to_string()
    })?;
    if dependency.workspace_id != Some(message_workspace_id) {
        return Err(
            "message disappearing_setting_id workspace event does not match message workspace"
                .to_string(),
        );
    }
    Ok(workspace_event.disappearing_ttl_minutes)
}

fn resolve_setting_ttl(
    dependency: &EventRecord,
    message_workspace_id: EventId,
    disappearing_setting_id: EventId,
) -> Result<u32, String> {
    let envelope = disappearing_messages_setting::codec::decode_signed(&dependency.canonical_bytes)
        .map_err(|_| {
            "message disappearing_setting_id dependency is not a signed disappearing_messages_setting event".to_string()
        })?;
    let setting = disappearing_messages_setting::codec::decode(&envelope.payload).map_err(|_| {
        "message disappearing_setting_id dependency is not a disappearing_messages_setting".to_string()
    })?;
    if setting.workspace_id != message_workspace_id {
        return Err(
            "message disappearing_setting_id setting workspace does not match message workspace"
                .to_string(),
        );
    }
    if dependency.workspace_id != Some(message_workspace_id) {
        return Err(
            "message disappearing_setting_id setting record workspace does not match message workspace"
                .to_string(),
        );
    }
    let _ = disappearing_setting_id;
    Ok(setting.ttl_minutes)
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::encryption::local_history_node_secret as leaf_module;
    use crate::protocol::event_modules::identity::{endpoint_shared, signed, user, workspace};
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
        // Mint a real leaf event for the deterministic
        // `(unix_minute_for(5), event_id_in_minute_derived())` so the
        // projector's leaf-binding check has a real local_history_node_secret
        // dependency. Source it from a stub minute_node id so derivation
        // succeeds; production would source from the minute_node admitted
        // earlier in the worker.
        let event_id_in_minute = super::super::types::message_event_id_in_minute(
            &workspace_id,
            &author_user_id,
            &removal_frontier_id,
            created_at_ms,
        );
        let leaf_output =
            leaf_module::commands::derive_trie_split(leaf_module::commands::DeriveTrieSplit {
                workspace_id,
                removal_frontier_id,
                parent_secret_id: [200; 32],
                parent_secret: [201; 32],
                range_start: unix_minute_for(created_at_ms),
                parent_bit_depth: 0,
                parent_event_id_prefix: [0; 32],
                child_side: leaf_module::types::bit_at(&event_id_in_minute, 0),
                child_bit_depth: leaf_module::types::TRIE_LEAF_BIT_DEPTH,
                child_event_id_prefix: event_id_in_minute,
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
            leaf_node_secret: KEY_SECRET,
            expires_at_minute: u64::MAX,
            disappearing_setting_id: workspace_id,
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

    /// Build a workspace event record for use as the slice-1 fallback
    /// disappearing-policy dependency. The workspace event id IS the
    /// `workspace_id` (workspaces are self-naming), so passing the same
    /// 32-byte value as both `workspace_id` and the message's
    /// `disappearing_setting_id` resolves the dep to this record.
    fn workspace_record(workspace_id: [u8; 32], ttl_minutes: u32) -> Record
    {
        let event = workspace::types::WorkspaceEvent {
            created_at_ms: 1,
            public_key: [99; 32],
            disappearing_ttl_minutes: ttl_minutes,
            name: "test".to_string(),
        };
        let bytes = workspace::codec::encode(&event).expect("encode workspace");
        let mut record = workspace::codec::record_from_bytes(bytes).expect("workspace record");
        // Self-naming: force the workspace id to match the test fixture.
        record.workspace_id = Some(workspace_id);
        record
    }

    fn context_for<'a>(
        built: &'a BuiltMessage,
        signer_id: [u8; 32],
        signer_record: Record,
        author_id: [u8; 32],
        author_record: Record,
    ) -> EventWithContext<'a> {
        context_for_with_workspace_ttl(
            built,
            signer_id,
            signer_record,
            author_id,
            author_record,
            0,
        )
    }

    fn context_for_with_workspace_ttl<'a>(
        built: &'a BuiltMessage,
        signer_id: [u8; 32],
        signer_record: Record,
        author_id: [u8; 32],
        author_record: Record,
        workspace_ttl_minutes: u32,
    ) -> EventWithContext<'a> {
        let envelope = codec::decode_signed(&built.record.canonical_bytes)
            .expect("decode signed message");
        let inner = codec::decode(&envelope.payload).expect("decode inner message");
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
                    DependencyContext {
                        event_id: inner.disappearing_setting_id,
                        record: workspace_record(inner.workspace_id, workspace_ttl_minutes),
                    },
                ],
                labels: Vec::new(),
                receive: None,
                now_unix_minute: None,
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
        // For self-deletes the label is already on the event (set by the
        // deletion projector); we don't double-write it.
        assert!(output.labels.is_empty());
        // Two deletes: read-model (MESSAGES) + ciphertext (SEALED_MESSAGES).
        assert_eq!(output.deletes.len(), 2);
        let tables: Vec<_> = output.deletes.iter().map(|d| d.table).collect();
        assert!(tables.contains(&schema::MESSAGES));
        assert!(tables.contains(&schema::SEALED_MESSAGES));
    }

    fn build_with_expiry(
        workspace_id: [u8; 32],
        author_user_id: [u8; 32],
        signer_private_key: &[u8; 32],
        signer_endpoint_shared_id: [u8; 32],
        expires_at_minute: u64,
    ) -> BuiltMessage {
        let created_at_ms = 6_000_000u64;
        let removal_frontier_id = [30; 32];
        let event_id_in_minute = super::super::types::message_event_id_in_minute(
            &workspace_id,
            &author_user_id,
            &removal_frontier_id,
            created_at_ms,
        );
        let leaf_output =
            leaf_module::commands::derive_trie_split(leaf_module::commands::DeriveTrieSplit {
                workspace_id,
                removal_frontier_id,
                parent_secret_id: [200; 32],
                parent_secret: [201; 32],
                range_start: unix_minute_for(created_at_ms),
                parent_bit_depth: 0,
                parent_event_id_prefix: [0; 32],
                child_side: leaf_module::types::bit_at(&event_id_in_minute, 0),
                child_bit_depth: leaf_module::types::TRIE_LEAF_BIT_DEPTH,
                child_event_id_prefix: event_id_in_minute,
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
            leaf_node_secret: KEY_SECRET,
            expires_at_minute,
            disappearing_setting_id: workspace_id,
            text: "ttl".to_string(),
        })
        .expect("send message");
        let record = output.events[0].record().clone();
        BuiltMessage {
            record,
            message_id: output.value.message_id,
            leaf_id,
            leaf_record,
        }
    }

    #[test]
    fn keeps_finite_expiry_message_visible_when_clock_is_before_expiry() {
        let workspace_id = [7; 32];
        let signer_private_key = [9; 32];
        let signer_pubkey = signing_public_key_for(&signer_private_key);
        let author_record = user_record(workspace_id);
        let author_id = event_id(&author_record.canonical_bytes);
        let signer_record = endpoint_shared_record(workspace_id, author_id, signer_pubkey);
        let signer_id = event_id(&signer_record.canonical_bytes);

        // expires_at_minute=105 = authored_minute(100) + ttl_minutes(5).
        let built =
            build_with_expiry(workspace_id, author_id, &signer_private_key, signer_id, 105);
        let mut event = context_for_with_workspace_ttl(
            &built,
            signer_id,
            signer_record,
            author_id,
            author_record,
            5,
        );
        event.context.now_unix_minute = Some(102);

        let output = project(&event).expect("project before-expiry message");
        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::SEALED_MESSAGES);
        assert!(output.deletes.is_empty());
        assert!(output.labels.is_empty());
    }

    #[test]
    fn rejects_message_whose_expiry_disagrees_with_referenced_policy() {
        // A peer that lies — stamps `expires_at_minute = M + 99` while
        // referencing the workspace event whose
        // `disappearing_ttl_minutes` is 1 — must be rejected by the
        // projector. Validates the slice-3 enforcement that closes
        // slice-2's trust gap. (The remaining gap, where the lying peer
        // points at an *older* admin setting with a longer TTL, is
        // documented in `disappearing_messages_plan.md` §6.)
        let workspace_id = [7; 32];
        let signer_private_key = [9; 32];
        let signer_pubkey = signing_public_key_for(&signer_private_key);
        let author_record = user_record(workspace_id);
        let author_id = event_id(&author_record.canonical_bytes);
        let signer_record = endpoint_shared_record(workspace_id, author_id, signer_pubkey);
        let signer_id = event_id(&signer_record.canonical_bytes);

        // Author stamps expires_at_minute = 199 (i.e., minute 100 + 99),
        // but the workspace's `disappearing_ttl_minutes` will be 1 in
        // the dependency context. The projector must reject.
        let built =
            build_with_expiry(workspace_id, author_id, &signer_private_key, signer_id, 199);
        let event = context_for_with_workspace_ttl(
            &built,
            signer_id,
            signer_record,
            author_id,
            author_record,
            1,
        );
        let err = project(&event).expect_err("inflated expiry must be rejected");
        assert!(
            err.contains("disagrees with referenced setting"),
            "{err}"
        );
    }

    #[test]
    fn keeps_never_expire_message_visible_at_any_clock() {
        // expires_at_minute == EXPIRES_NEVER must short-circuit the
        // expiry check regardless of how far the clock has advanced.
        let workspace_id = [7; 32];
        let signer_private_key = [9; 32];
        let signer_pubkey = signing_public_key_for(&signer_private_key);
        let author_record = user_record(workspace_id);
        let author_id = event_id(&author_record.canonical_bytes);
        let signer_record = endpoint_shared_record(workspace_id, author_id, signer_pubkey);
        let signer_id = event_id(&signer_record.canonical_bytes);

        let built = build(workspace_id, author_id, &signer_private_key, signer_id);
        let mut event = context_for(&built, signer_id, signer_record, author_id, author_record);
        event.context.now_unix_minute = Some(u64::MAX - 1);

        let output = project(&event).expect("project never-expire message");
        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::SEALED_MESSAGES);
        assert!(output.deletes.is_empty());
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
            expires_at_minute: u64::MAX,
            disappearing_setting_id: [1; 32],
            nonce: [5; 24],
            ciphertext: [6; super::super::types::MESSAGE_CIPHERTEXT_BYTES],
        });

        assert_eq!(
            crate::protocol::event_modules::event_from_bytes(payload)
                .expect_err("raw message must fail"),
            "message must be signed"
        );
    }

}

//! Projection preparation for encrypted content events.
//!
//! Dependencies are public event ids, so the common event pipeline can load the
//! full dependency context before content plaintext exists. This module is the
//! content-owned preparation step between generic context loading and pure
//! row projection: validate the signed content authority, prove the local
//! key-secret dependency belongs to the named removal frontier, then decrypt the
//! current event only for this projection attempt.

use crate::core::crypto;
use crate::protocol::event_modules::encryption::{local_key_secret, removal_frontier};
use crate::protocol::event_modules::identity::{endpoint_shared, signed, user};
use crate::protocol::event_modules::types::{EventId, EventRecord};
use crate::protocol::event_modules::worker::EventWithContext;

use super::{message, reaction};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedMessage {
    pub message_id: EventId,
    pub signer_endpoint_shared_id: EventId,
    pub plaintext: message::types::MessagePlaintext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedReaction {
    pub reaction_id: EventId,
    pub signer_endpoint_shared_id: EventId,
    pub plaintext: reaction::types::ReactionPlaintext,
}

pub fn prepare_message(event: &EventWithContext<'_>) -> Result<PreparedMessage, String> {
    let envelope = message::codec::decode_signed(&event.record.canonical_bytes)?;
    let message = message::codec::decode(&envelope.payload)?;
    if event.record.workspace_id != Some(message.workspace_id) {
        return Err("message workspace metadata does not match event body".to_string());
    }

    validate_authority(
        event,
        "message",
        envelope.signer_endpoint_shared_id,
        envelope.signer_public_key,
        message.workspace_id,
        message.author_user_id,
    )?;
    let key_secret = content_key_secret(
        event,
        "message",
        message.workspace_id,
        message.removal_frontier_id,
        message.local_key_secret_id,
    )?;
    let plaintext = crypto::xchacha20poly1305_decrypt(
        &key_secret,
        &message::codec::associated_data(&message, envelope.signer_endpoint_shared_id),
        &message.nonce,
        &message.ciphertext,
    )
    .map_err(|_| "open message ciphertext".to_string())?;
    let text = message::codec::decode_text_slot(&plaintext)?;

    Ok(PreparedMessage {
        message_id: event.context.event_id,
        signer_endpoint_shared_id: envelope.signer_endpoint_shared_id,
        plaintext: message::types::MessagePlaintext {
            workspace_id: message.workspace_id,
            created_at_ms: message.created_at_ms,
            author_user_id: message.author_user_id,
            removal_frontier_id: message.removal_frontier_id,
            local_key_secret_id: message.local_key_secret_id,
            text,
        },
    })
}

pub fn prepare_reaction(event: &EventWithContext<'_>) -> Result<PreparedReaction, String> {
    let envelope = reaction::codec::decode_signed(&event.record.canonical_bytes)?;
    let reaction = reaction::codec::decode(&envelope.payload)?;
    if event.record.workspace_id != Some(reaction.workspace_id) {
        return Err("reaction workspace metadata does not match event body".to_string());
    }

    validate_authority(
        event,
        "reaction",
        envelope.signer_endpoint_shared_id,
        envelope.signer_public_key,
        reaction.workspace_id,
        reaction.author_user_id,
    )?;
    validate_target_message_workspace(event, &reaction)?;
    let key_secret = content_key_secret(
        event,
        "reaction",
        reaction.workspace_id,
        reaction.removal_frontier_id,
        reaction.local_key_secret_id,
    )?;
    let plaintext = crypto::xchacha20poly1305_decrypt(
        &key_secret,
        &reaction::codec::associated_data(&reaction, envelope.signer_endpoint_shared_id),
        &reaction.nonce,
        &reaction.ciphertext,
    )
    .map_err(|_| "open reaction ciphertext".to_string())?;
    let emoji = reaction::codec::decode_emoji_slot(&plaintext)?;

    Ok(PreparedReaction {
        reaction_id: event.context.event_id,
        signer_endpoint_shared_id: envelope.signer_endpoint_shared_id,
        plaintext: reaction::types::ReactionPlaintext {
            workspace_id: reaction.workspace_id,
            created_at_ms: reaction.created_at_ms,
            target_message_id: reaction.target_message_id,
            author_user_id: reaction.author_user_id,
            removal_frontier_id: reaction.removal_frontier_id,
            local_key_secret_id: reaction.local_key_secret_id,
            emoji,
        },
    })
}

fn validate_authority(
    event: &EventWithContext<'_>,
    name: &str,
    signer_endpoint_shared_id: EventId,
    signer_public_key: crypto::Ed25519PublicKey,
    workspace_id: EventId,
    author_user_id: EventId,
) -> Result<(), String> {
    let signer_endpoint_shared =
        decode_signer_endpoint_shared(event, name, signer_endpoint_shared_id)?;
    if signer_endpoint_shared.workspace_id != workspace_id {
        return Err(format!(
            "{name} signer endpoint_shared workspace does not match {name}"
        ));
    }
    if signer_endpoint_shared.signing_public_key != signer_public_key {
        return Err(format!(
            "{name} signer public key does not match endpoint_shared"
        ));
    }
    if signer_endpoint_shared.user_authority_event_id != author_user_id {
        return Err(format!(
            "{name} signer endpoint is not authorized by the named author"
        ));
    }

    let author_user = decode_author(event, name, author_user_id)?;
    if author_user.workspace_id != workspace_id {
        return Err(format!("{name} author workspace does not match {name}"));
    }
    Ok(())
}

fn content_key_secret(
    event: &EventWithContext<'_>,
    name: &str,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    local_key_secret_id: EventId,
) -> Result<crypto::XChaCha20Poly1305Key, String> {
    validate_removal_frontier(event, name, workspace_id, removal_frontier_id)?;
    let local_record = dependency_record(event, &local_key_secret_id)
        .ok_or_else(|| format!("{name} local key-secret dependency is missing"))?;
    let local = local_key_secret::codec::decode(&local_record.canonical_bytes)
        .map_err(|_| format!("{name} dependency is not a local key secret"))?;
    if local.workspace_id != workspace_id {
        return Err(format!(
            "{name} local key-secret workspace does not match {name}"
        ));
    }
    if local.removal_frontier_id != removal_frontier_id {
        return Err(format!(
            "{name} local key-secret frontier does not match {name}"
        ));
    }
    Ok(local.key_secret)
}

fn validate_removal_frontier(
    event: &EventWithContext<'_>,
    name: &str,
    workspace_id: EventId,
    removal_frontier_id: EventId,
) -> Result<(), String> {
    let frontier_record = dependency_record(event, &removal_frontier_id)
        .ok_or_else(|| format!("{name} removal frontier dependency is missing"))?;
    let envelope = removal_frontier::codec::decode_signed(&frontier_record.canonical_bytes)
        .map_err(|_| format!("{name} dependency is not a removal frontier"))?;
    let frontier = removal_frontier::codec::decode(&envelope.payload)
        .map_err(|_| format!("{name} dependency is not a removal frontier"))?;
    if frontier.workspace_id != workspace_id {
        return Err(format!(
            "{name} removal frontier workspace does not match {name}"
        ));
    }
    Ok(())
}

fn validate_target_message_workspace(
    event: &EventWithContext<'_>,
    reaction: &reaction::types::ReactionEvent,
) -> Result<(), String> {
    let target = dependency_record(event, &reaction.target_message_id)
        .ok_or_else(|| "reaction target message dependency is missing".to_string())?;
    let target_envelope = message::codec::decode_signed(&target.canonical_bytes)
        .map_err(|_| "reaction target dependency is not a signed message".to_string())?;
    let target_message = message::codec::decode(&target_envelope.payload)
        .map_err(|_| "reaction target dependency is not a signed message".to_string())?;
    if target_message.workspace_id != reaction.workspace_id {
        return Err("reaction target message workspace does not match reaction".to_string());
    }
    Ok(())
}

fn decode_signer_endpoint_shared(
    event: &EventWithContext<'_>,
    name: &str,
    signer_endpoint_shared_id: EventId,
) -> Result<endpoint_shared::types::EndpointSharedEvent, String> {
    let signer = dependency_record(event, &signer_endpoint_shared_id)
        .ok_or_else(|| format!("{name} signer endpoint_shared dependency is missing"))?;
    let envelope = signed::codec::decode(&signer.canonical_bytes)
        .map_err(|_| format!("{name} signer dependency is not a signed endpoint_shared"))?;
    if envelope.inner_type != endpoint_shared::codec::TYPE_ENDPOINT_SHARED {
        return Err(format!(
            "{name} signer dependency is not a signed endpoint_shared"
        ));
    }
    endpoint_shared::codec::decode(&envelope.payload)
        .map_err(|_| format!("{name} signer dependency is not a signed endpoint_shared"))
}

fn decode_author(
    event: &EventWithContext<'_>,
    name: &str,
    author_user_id: EventId,
) -> Result<user::types::UserEvent, String> {
    let author = dependency_record(event, &author_user_id)
        .ok_or_else(|| format!("{name} author user dependency is missing"))?;
    let envelope = signed::codec::decode(&author.canonical_bytes)
        .map_err(|_| format!("{name} author dependency is not a signed user"))?;
    if envelope.inner_type != user::codec::TYPE_USER {
        return Err(format!("{name} author dependency is not a signed user"));
    }
    user::codec::decode(&envelope.payload)
        .map_err(|_| format!("{name} author dependency is not a signed user"))
}

fn dependency_record<'a>(
    event: &'a EventWithContext<'_>,
    event_id: &EventId,
) -> Option<&'a EventRecord> {
    event
        .context
        .dependencies
        .iter()
        .find(|dependency| &dependency.event_id == event_id)
        .map(|dependency| &dependency.record)
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::encryption::local_key_secret;
    use crate::protocol::event_modules::identity::endpoint;
    use crate::protocol::event_modules::types::event_id;
    use crate::protocol::event_modules::worker::{
        DependencyContext, EventContext, EventWithContext,
    };

    use super::*;

    const WORKSPACE: EventId = [7; 32];
    const KEY_SECRET: [u8; 32] = [77; 32];

    struct PreparedFixture {
        message_record: EventRecord,
        message_id: EventId,
        reaction_record: EventRecord,
        reaction_id: EventId,
        signer_id: EventId,
        signer_record: EventRecord,
        author_id: EventId,
        author_record: EventRecord,
        frontier_id: EventId,
        frontier_record: EventRecord,
        local_key_secret_id: EventId,
        local_key_secret_record: EventRecord,
    }

    fn fixture() -> PreparedFixture {
        let author_record = user_record(WORKSPACE);
        let author_id = event_id(&author_record.canonical_bytes);
        let signer_private_key = [9; 32];
        let signer_record = endpoint_shared_record(
            WORKSPACE,
            author_id,
            crypto::ed25519_public_key(&signer_private_key),
        );
        let signer_id = event_id(&signer_record.canonical_bytes);
        let (frontier_id, frontier_record) = frontier_record(WORKSPACE);
        let local_key_secret =
            local_key_secret::commands::from_key_secret(WORKSPACE, frontier_id, KEY_SECRET)
                .expect("local key secret");
        let local_key_secret_id = local_key_secret.value.local_key_secret_id;
        let local_key_secret_record = local_key_secret.events[0].record().clone();
        let message = message::commands::send(message::commands::SendMessage {
            workspace_id: WORKSPACE,
            created_at_ms: 10,
            author_user_id: author_id,
            signer_endpoint_shared_id: signer_id,
            signer_private_key,
            removal_frontier_id: frontier_id,
            local_key_secret_id,
            key_secret: KEY_SECRET,
            text: "hello".to_string(),
        })
        .expect("message");
        let message_id = message.value.message_id;
        let message_record = message.events[0].record().clone();
        let reaction = reaction::commands::post(reaction::commands::PostReaction {
            workspace_id: WORKSPACE,
            created_at_ms: 11,
            target_message_id: message_id,
            author_user_id: author_id,
            signer_endpoint_shared_id: signer_id,
            signer_private_key,
            removal_frontier_id: frontier_id,
            local_key_secret_id,
            key_secret: KEY_SECRET,
            emoji: "+1".to_string(),
        })
        .expect("reaction");
        let reaction_id = reaction.value.reaction_id;
        let reaction_record = reaction.events[0].record().clone();
        PreparedFixture {
            message_record,
            message_id,
            reaction_record,
            reaction_id,
            signer_id,
            signer_record,
            author_id,
            author_record,
            frontier_id,
            frontier_record,
            local_key_secret_id,
            local_key_secret_record,
        }
    }

    fn message_context(fixture: &PreparedFixture) -> EventWithContext<'_> {
        event_context(
            &fixture.message_record,
            fixture.message_id,
            vec![
                (fixture.signer_id, fixture.signer_record.clone()),
                (fixture.author_id, fixture.author_record.clone()),
                (fixture.frontier_id, fixture.frontier_record.clone()),
                (
                    fixture.local_key_secret_id,
                    fixture.local_key_secret_record.clone(),
                ),
            ],
        )
    }

    fn reaction_context(fixture: &PreparedFixture) -> EventWithContext<'_> {
        event_context(
            &fixture.reaction_record,
            fixture.reaction_id,
            vec![
                (fixture.signer_id, fixture.signer_record.clone()),
                (fixture.author_id, fixture.author_record.clone()),
                (fixture.message_id, fixture.message_record.clone()),
                (fixture.frontier_id, fixture.frontier_record.clone()),
                (
                    fixture.local_key_secret_id,
                    fixture.local_key_secret_record.clone(),
                ),
            ],
        )
    }

    fn event_context<'a>(
        record: &'a EventRecord,
        event_id: EventId,
        dependencies: Vec<(EventId, EventRecord)>,
    ) -> EventWithContext<'a> {
        EventWithContext {
            record,
            context: EventContext {
                event_id,
                dependencies: dependencies
                    .into_iter()
                    .map(|(event_id, record)| DependencyContext { event_id, record })
                    .collect(),
                labels: Vec::new(),
                receive: None,
            },
        }
    }

    fn user_record(workspace_id: EventId) -> EventRecord {
        let payload = user::codec::encode(&user::types::UserEvent {
            created_at_ms: 3,
            workspace_id,
            public_key: [22; 32],
            username: "alice".to_string(),
        })
        .expect("encode user");
        signed::commands::sign_payload([24; 32], &[25; 32], payload)
            .expect("sign user")
            .events[0]
            .record()
            .clone()
    }

    fn endpoint_shared_record(
        workspace_id: EventId,
        user_authority_event_id: EventId,
        signing_public_key: crypto::Ed25519PublicKey,
    ) -> EventRecord {
        let payload =
            endpoint_shared::codec::encode(&endpoint_shared::types::EndpointSharedEvent {
                created_at_ms: 4,
                workspace_id,
                user_authority_event_id,
                endpoint_id: [21; 32],
                signing_public_key,
                endpoint_role: endpoint::types::EndpointRole::Device,
                device_name: "laptop".to_string(),
            })
            .expect("encode endpoint_shared");
        signed::commands::sign_payload([6; 32], &[5; 32], payload)
            .expect("sign endpoint_shared")
            .events[0]
            .record()
            .clone()
    }

    fn frontier_record(workspace_id: EventId) -> (EventId, EventRecord) {
        let output =
            removal_frontier::commands::create(removal_frontier::commands::CreateRemovalFrontier {
                workspace_id,
                created_at_ms: 5,
                authority_admin_id: [3; 32],
                signer_endpoint_shared_id: [4; 32],
                signer_private_key: [9; 32],
                removal_event_ids: Vec::new(),
            })
            .expect("create frontier");
        let record = output.events[0].record().clone();
        (event_id(&record.canonical_bytes), record)
    }

    #[test]
    fn prepare_message_opens_ciphertext_from_dependency_key_secret() {
        let fixture = fixture();
        let prepared = prepare_message(&message_context(&fixture)).expect("prepare message");

        assert_eq!(prepared.message_id, fixture.message_id);
        assert_eq!(prepared.signer_endpoint_shared_id, fixture.signer_id);
        assert_eq!(prepared.plaintext.workspace_id, WORKSPACE);
        assert_eq!(prepared.plaintext.author_user_id, fixture.author_id);
        assert_eq!(prepared.plaintext.text, "hello");
    }

    #[test]
    fn prepare_reaction_opens_ciphertext_and_checks_target_workspace() {
        let fixture = fixture();
        let prepared = prepare_reaction(&reaction_context(&fixture)).expect("prepare reaction");

        assert_eq!(prepared.reaction_id, fixture.reaction_id);
        assert_eq!(prepared.plaintext.target_message_id, fixture.message_id);
        assert_eq!(prepared.plaintext.emoji, "+1");
    }

    #[test]
    fn prepare_rejects_signer_public_key_mismatch() {
        let mut fixture = fixture();
        fixture.signer_record = endpoint_shared_record(WORKSPACE, fixture.author_id, [99; 32]);

        assert_eq!(
            prepare_message(&message_context(&fixture)).expect_err("bad signer must fail"),
            "message signer public key does not match endpoint_shared"
        );
    }

    #[test]
    fn prepare_rejects_ciphertext_that_does_not_open_with_named_secret() {
        let mut fixture = fixture();
        let signer_private_key = [9; 32];
        let wrong_key_message = message::commands::send(message::commands::SendMessage {
            workspace_id: WORKSPACE,
            created_at_ms: 10,
            author_user_id: fixture.author_id,
            signer_endpoint_shared_id: fixture.signer_id,
            signer_private_key,
            removal_frontier_id: fixture.frontier_id,
            local_key_secret_id: fixture.local_key_secret_id,
            key_secret: [88; 32],
            text: "hello".to_string(),
        })
        .expect("message");
        fixture.message_id = wrong_key_message.value.message_id;
        fixture.message_record = wrong_key_message.events[0].record().clone();

        assert_eq!(
            prepare_message(&message_context(&fixture)).expect_err("wrong key must fail"),
            "open message ciphertext"
        );
    }

    #[test]
    fn prepare_rejects_reaction_target_from_other_workspace() {
        let mut fixture = fixture();
        let other = message::commands::send(message::commands::SendMessage {
            workspace_id: [8; 32],
            created_at_ms: 10,
            author_user_id: fixture.author_id,
            signer_endpoint_shared_id: fixture.signer_id,
            signer_private_key: [9; 32],
            removal_frontier_id: fixture.frontier_id,
            local_key_secret_id: fixture.local_key_secret_id,
            key_secret: KEY_SECRET,
            text: "other".to_string(),
        })
        .expect("other message");
        fixture.message_record = other.events[0].record().clone();

        assert_eq!(
            prepare_reaction(&reaction_context(&fixture)).expect_err("wrong target must fail"),
            "reaction target message workspace does not match reaction"
        );
    }
}

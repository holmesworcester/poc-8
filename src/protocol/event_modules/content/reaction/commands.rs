//! Commands for posting reactions.

use crate::core::crypto::Ed25519PrivateKey;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::CommandOutput;

use super::codec;
use super::types::ReactionEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostReaction {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub target_message_id: EventId,
    pub author_user_id: EventId,
    pub signer_endpoint_shared_id: EventId,
    pub signer_private_key: Ed25519PrivateKey,
    pub emoji: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostReactionOutput {
    pub reaction_id: EventId,
    pub target_message_id: EventId,
    pub emoji: String,
}

pub fn post(input: PostReaction) -> Result<CommandOutput<PostReactionOutput>, String> {
    if input.emoji.trim().is_empty() {
        return Err("reaction emoji must not be empty".to_string());
    }
    let event = ReactionEvent {
        workspace_id: input.workspace_id,
        created_at_ms: input.created_at_ms,
        target_message_id: input.target_message_id,
        author_user_id: input.author_user_id,
        emoji: input.emoji,
    };
    let payload = codec::encode(&event)?;
    let envelope = codec::sign(
        input.signer_endpoint_shared_id,
        &input.signer_private_key,
        payload,
    );
    let bytes = codec::encode_signed(&envelope);
    let record = codec::signed_record_from_bytes(bytes)?;
    let reaction_id = crate::protocol::event_modules::types::event_id(&record.canonical_bytes);
    Ok(CommandOutput::with_events(
        PostReactionOutput {
            reaction_id,
            target_message_id: event.target_message_id,
            emoji: event.emoji,
        },
        vec![record],
    ))
}

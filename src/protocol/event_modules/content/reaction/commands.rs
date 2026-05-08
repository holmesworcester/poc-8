//! Commands for posting reactions.
//!
//! Commands encrypt the emoji into the canonical reaction payload and return a
//! proposed signed event. They rely on the caller to provide the already
//! authorized signer and content key; they do not check target-message
//! existence or write projection rows.

use crate::core::crypto::{self, Ed25519PrivateKey, XChaCha20Poly1305Key};
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
    pub removal_frontier_id: EventId,
    pub local_history_node_secret_id: EventId,
    pub leaf_node_secret: XChaCha20Poly1305Key,
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
    let plaintext = codec::encode_emoji_slot(&input.emoji)?;
    let mut event = ReactionEvent {
        workspace_id: input.workspace_id,
        created_at_ms: input.created_at_ms,
        target_message_id: input.target_message_id,
        author_user_id: input.author_user_id,
        removal_frontier_id: input.removal_frontier_id,
        local_history_node_secret_id: input.local_history_node_secret_id,
        nonce: crypto::random_xchacha20poly1305_nonce(),
        ciphertext: [0; super::types::REACTION_CIPHERTEXT_BYTES],
    };
    let ciphertext = crypto::xchacha20poly1305_encrypt(
        &input.leaf_node_secret,
        &codec::associated_data(&event, input.signer_endpoint_shared_id),
        &event.nonce,
        &plaintext,
    )?;
    event.ciphertext = ciphertext
        .try_into()
        .map_err(|_| "reaction ciphertext length mismatch".to_string())?;

    let payload = codec::encode(&event);
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
            emoji: input.emoji,
        },
        vec![record],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_proposes_signed_ciphertext_without_emoji_bytes() {
        let output = post(PostReaction {
            workspace_id: [1; 32],
            created_at_ms: 10,
            target_message_id: [2; 32],
            author_user_id: [3; 32],
            signer_endpoint_shared_id: [4; 32],
            signer_private_key: [9; 32],
            removal_frontier_id: [5; 32],
            local_history_node_secret_id: [6; 32],
            leaf_node_secret: [7; 32],
            emoji: "secret-react".to_string(),
        })
        .expect("post");
        let record = output.events[0].record();

        assert!(!record
            .canonical_bytes
            .windows("secret-react".len())
            .any(|window| window == b"secret-react"));
        assert_eq!(
            record.dependencies,
            vec![[4; 32], [1; 32], [3; 32], [2; 32], [5; 32], [6; 32]]
        );

        let envelope = codec::decode_signed(&record.canonical_bytes).expect("signed");
        let event = codec::decode(&envelope.payload).expect("event");
        let plaintext = crypto::xchacha20poly1305_decrypt(
            &[7; 32],
            &codec::associated_data(&event, [4; 32]),
            &event.nonce,
            &event.ciphertext,
        )
        .expect("decrypt");
        assert_eq!(
            codec::decode_emoji_slot(&plaintext).expect("decode emoji"),
            "secret-react"
        );
    }
}

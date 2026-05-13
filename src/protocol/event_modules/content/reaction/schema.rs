//! Reaction projection rows.
//!
//! Rows are keyed by `workspace_id || reaction_id`. The target message id is
//! stored in the value so display queries can group reactions by target without
//! a per-target index. The deduplication of `(author_user_id, emoji)` happens at
//! read time, matching the poc-7 grouping rule without writing an extra index.

use crate::core::store::{Schema, Store, TableName, TableRow};
use crate::protocol::event_modules::content::message;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::AdmitDecision;
use crate::protocol::wire::{Reader, Writer};

use super::codec;
use super::types::{
    ReactionCiphertext, ReactionEvent, ReactionPlaintext, ReactionRow, REACTION_CIPHERTEXT_BYTES,
    REACTION_EMOJI_BYTES,
};

/// Receive-side admission gate for signed reactions.
///
/// Drops the reaction if its parent message is already tombstoned. Mirrors
/// the cascade predicate the content_purge worker uses for reactions when
/// the parent message is later tombstoned, enforced earlier so re-deliveries
/// of orphaned reactions never get stored.
pub fn admit_check_received(store: &Store, bytes: &[u8]) -> Result<AdmitDecision, String> {
    let envelope = codec::decode_signed(bytes)?;
    let reaction = codec::decode(&envelope.payload)?;
    if message::queries::message_tombstone_exists(
        store,
        reaction.workspace_id,
        reaction.target_message_id,
    )? {
        return Ok(AdmitDecision::Drop);
    }
    Ok(AdmitDecision::Admit)
}

pub const REACTIONS: TableName = TableName::new("content.reactions");
pub const SEALED_REACTIONS: TableName = TableName::new("content.sealed_reactions");

pub const SCHEMAS: &[Schema] = &[
    Schema::durable_row_table("content.reactions.v2", REACTIONS),
    Schema::durable_row_table("content.sealed_reactions.v2", SEALED_REACTIONS),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedReactionRow {
    pub workspace_id: EventId,
    pub reaction_id: EventId,
    pub created_at_ms: u64,
    pub target_message_id: EventId,
    pub author_user_id: EventId,
    pub signer_endpoint_shared_id: EventId,
    pub removal_frontier_id: EventId,
    pub local_history_node_secret_id: EventId,
    pub nonce: crate::core::crypto::XChaCha20Poly1305Nonce,
    pub ciphertext: ReactionCiphertext,
}

pub fn reaction_row(
    reaction_id: EventId,
    signer_endpoint_shared_id: EventId,
    event: &ReactionPlaintext,
) -> Result<TableRow, String> {
    Ok(TableRow {
        table: REACTIONS,
        key: reaction_key(event.workspace_id, reaction_id),
        value: encode_value(signer_endpoint_shared_id, event)?,
    })
}

pub fn reaction_key(workspace_id: EventId, reaction_id: EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&reaction_id);
    key
}

pub fn sealed_reaction_row(
    reaction_id: EventId,
    signer_endpoint_shared_id: EventId,
    event: &ReactionEvent,
) -> Result<TableRow, String> {
    Ok(TableRow {
        table: SEALED_REACTIONS,
        key: reaction_key(event.workspace_id, reaction_id),
        value: encode_sealed_value(signer_endpoint_shared_id, event),
    })
}

pub fn decode_sealed_reaction_row(key: &[u8], value: &[u8]) -> Result<SealedReactionRow, String> {
    if key.len() != 64 {
        return Err("sealed reaction row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut reaction_id = [0; 32];
    reaction_id.copy_from_slice(&key[32..64]);

    let mut reader = Reader::new(value, "sealed reaction row");
    let created_at_ms = reader.u64()?;
    let target_message_id = reader.id()?;
    let author_user_id = reader.id()?;
    let signer_endpoint_shared_id = reader.id()?;
    let removal_frontier_id = reader.id()?;
    let local_history_node_secret_id = reader.id()?;
    let nonce = reader
        .bytes(crate::core::crypto::XCHACHA20_POLY1305_NONCE_BYTES)?
        .try_into()
        .map_err(|_| "sealed reaction row nonce length mismatch".to_string())?;
    let ciphertext = reader
        .bytes(REACTION_CIPHERTEXT_BYTES)?
        .try_into()
        .map_err(|_| "sealed reaction row ciphertext length mismatch".to_string())?;
    reader.finish()?;
    Ok(SealedReactionRow {
        workspace_id,
        reaction_id,
        created_at_ms,
        target_message_id,
        author_user_id,
        signer_endpoint_shared_id,
        removal_frontier_id,
        local_history_node_secret_id,
        nonce,
        ciphertext,
    })
}

pub fn decode_reaction_row(key: &[u8], value: &[u8]) -> Result<ReactionRow, String> {
    if key.len() != 64 {
        return Err("reaction row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut reaction_id = [0; 32];
    reaction_id.copy_from_slice(&key[32..64]);

    let mut reader = Reader::new(value, "reaction row");
    let created_at_ms = reader.u64()?;
    let target_message_id = reader.id()?;
    let author_user_id = reader.id()?;
    let signer_endpoint_shared_id = reader.id()?;
    let emoji = codec::decode_emoji_slot(reader.slice(REACTION_EMOJI_BYTES)?)?;
    reader.finish()?;

    Ok(ReactionRow {
        workspace_id,
        reaction_id,
        target_message_id,
        author_user_id,
        signer_endpoint_shared_id,
        created_at_ms,
        emoji,
    })
}

fn encode_value(
    signer_endpoint_shared_id: EventId,
    event: &ReactionPlaintext,
) -> Result<Vec<u8>, String> {
    let emoji = codec::encode_emoji_slot(&event.emoji)?;
    let mut out = Writer::with_capacity(8 + 32 + 32 + 32 + REACTION_EMOJI_BYTES);
    out.u64(event.created_at_ms);
    out.id(&event.target_message_id);
    out.id(&event.author_user_id);
    out.id(&signer_endpoint_shared_id);
    out.raw(&emoji);
    Ok(out.finish())
}

fn encode_sealed_value(signer_endpoint_shared_id: EventId, event: &ReactionEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(
        8 + 32
            + 32
            + 32
            + 32
            + 32
            + crate::core::crypto::XCHACHA20_POLY1305_NONCE_BYTES
            + REACTION_CIPHERTEXT_BYTES,
    );
    out.u64(event.created_at_ms);
    out.id(&event.target_message_id);
    out.id(&event.author_user_id);
    out.id(&signer_endpoint_shared_id);
    out.id(&event.removal_frontier_id);
    out.id(&event.local_history_node_secret_id);
    out.raw(&event.nonce);
    out.raw(&event.ciphertext);
    out.finish()
}

#[cfg(test)]
mod tests {
    use crate::protocol::Protocol;

    use super::*;

    #[test]
    fn admit_drops_reaction_with_tombstoned_parent() {
        let store = Protocol::open_memory_store().expect("store");
        let workspace_id = [17; 32];
        let target_message_id = [42; 32];
        let author_user_id = [3; 32];

        let inner = ReactionEvent {
            workspace_id,
            created_at_ms: 1,
            target_message_id,
            author_user_id,
            removal_frontier_id: [30; 32],
            local_history_node_secret_id: [40; 32],
            nonce: [0; crate::core::crypto::XCHACHA20_POLY1305_NONCE_BYTES],
            ciphertext: [0; REACTION_CIPHERTEXT_BYTES],
        };
        let payload = codec::encode(&inner);
        let envelope = codec::sign([8; 32], &[7; 32], payload);
        let bytes = codec::encode_signed(&envelope);

        // No tombstone yet -> admit.
        assert_eq!(
            admit_check_received(&store, &bytes).expect("admit"),
            AdmitDecision::Admit
        );

        // Tombstone the parent message -> reaction must drop.
        store
            .insert_table_rows(vec![message::schema::message_tombstone_row(
                workspace_id,
                target_message_id,
                author_user_id,
                0,
            )])
            .expect("insert tombstone");
        assert_eq!(
            admit_check_received(&store, &bytes).expect("admit"),
            AdmitDecision::Drop
        );
    }
}

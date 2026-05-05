//! Reaction projection rows.
//!
//! Rows are keyed by `workspace_id || reaction_id`. The target message id is
//! stored in the value so display queries can group reactions by target without
//! a per-target index. The deduplication of `(author_user_id, emoji)` happens at
//! read time, matching the poc-7 grouping rule without writing an extra index.

use std::collections::BTreeMap;

use crate::core::store::{Schema, Store, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::{Reader, Writer};

use super::codec;
use super::types::{ReactionEvent, ReactionRow, REACTION_EMOJI_BYTES};

pub const REACTIONS: TableName = TableName::new("content.reactions");

pub const SCHEMAS: &[Schema] = &[Schema::durable_row_table("content.reactions.v1", REACTIONS)];

pub fn reaction_row(
    reaction_id: EventId,
    signer_endpoint_shared_id: EventId,
    event: &ReactionEvent,
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

pub fn list_for_workspace(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<ReactionRow>, String> {
    let mut rows = store
        .table_rows_with_key_prefix(REACTIONS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load reactions: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_reaction_row(&key, &value))
        .collect::<Result<Vec<_>, _>>()?;
    rows.sort_by(|a, b| {
        a.created_at_ms
            .cmp(&b.created_at_ms)
            .then_with(|| a.reaction_id.cmp(&b.reaction_id))
    });
    Ok(rows)
}

pub fn count_for_workspace(store: &Store, workspace_id: EventId) -> Result<usize, String> {
    store
        .table_rows_with_key_prefix(REACTIONS, &workspace_id, usize::MAX)
        .map(|rows| rows.len())
        .map_err(|err| format!("count reactions: {err}"))
}

pub fn reactions_grouped_by_message(
    store: &Store,
    workspace_id: EventId,
) -> Result<BTreeMap<EventId, Vec<String>>, String> {
    let rows = list_for_workspace(store, workspace_id)?;
    let mut grouped: BTreeMap<EventId, Vec<(EventId, String)>> = BTreeMap::new();
    for row in rows {
        let entry = grouped.entry(row.target_message_id).or_default();
        let key_pair = (row.author_user_id, row.emoji.clone());
        if !entry.iter().any(|existing| existing == &key_pair) {
            entry.push(key_pair);
        }
    }
    Ok(grouped
        .into_iter()
        .map(|(target, pairs)| (target, pairs.into_iter().map(|(_, emoji)| emoji).collect()))
        .collect())
}

fn encode_value(
    signer_endpoint_shared_id: EventId,
    event: &ReactionEvent,
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

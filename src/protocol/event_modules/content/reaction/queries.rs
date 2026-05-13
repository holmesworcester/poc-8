//! Read-only views over the reaction projection tables.
//!
//! Rows are keyed by `workspace_id || reaction_id`. The target message
//! id is stored in the value, so display-time grouping by
//! `(target_message_id, author, emoji)` happens on the read path without
//! an extra index.

use std::collections::BTreeMap;

use crate::core::store::Store;
use crate::protocol::event_modules::types::EventId;

use super::schema::{decode_reaction_row, decode_sealed_reaction_row, SealedReactionRow,
    REACTIONS, SEALED_REACTIONS};
use super::types::ReactionRow;

pub fn list_sealed(store: &Store, limit: usize) -> Result<Vec<SealedReactionRow>, String> {
    store
        .table_rows_with_key_prefix(SEALED_REACTIONS, &[], limit)
        .map_err(|err| format!("load sealed reactions: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_sealed_reaction_row(&key, &value))
        .collect()
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

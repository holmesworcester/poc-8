//! Read-only views over the local history node secret tables.
//!
//! Secret rows are keyed by
//! `(workspace_id, removal_frontier_id, range_start, range_width, bit_depth,
//!   event_id_prefix)`. These helpers compose bounded prefix scans into
//! the lookups workers and the CLI need:
//!
//! * `get`, `get_leaf`, `get_minute_node` — single-row lookups by full
//!   coordinate or by the conventional shorthand for leaves and
//!   minute_nodes.
//! * `list_for_frontier`, `list_for_workspace` — bounded prefix scans
//!   used by the encryption worker's chop / retire walks.
//! * `list_minute_nodes`, `list_leaves` — filtered views the worker uses
//!   when it only cares about one shape of row.
//! * `cover_summary` — a stable byte-equal fingerprint over the retained
//!   tree and tombstones; used to assert peers converge after retire/chop.

use crate::core::store::Store;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::Writer;

use super::schema::{
    self, decode_local_history_node_secret_row, decode_local_history_node_tombstone_row,
    local_history_node_secret_key, LOCAL_HISTORY_NODE_SECRETS, LOCAL_HISTORY_NODE_TOMBSTONES,
};
use super::types::{
    is_leaf_row, is_minute_node_row, mask_prefix_to_depth, LocalHistoryNodeSecretRow,
    LocalHistoryNodeTombstoneRow,
};

pub fn list_for_frontier(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
) -> Result<Vec<LocalHistoryNodeSecretRow>, String> {
    let mut prefix = Vec::with_capacity(64);
    prefix.extend_from_slice(&workspace_id);
    prefix.extend_from_slice(&removal_frontier_id);
    store
        .table_rows_with_key_prefix(LOCAL_HISTORY_NODE_SECRETS, &prefix, usize::MAX)
        .map_err(|err| format!("load local history node secrets: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_local_history_node_secret_row(&key, &value))
        .collect()
}

/// Look up a node by its full coordinate.
pub fn get(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    range_start: u64,
    range_width: u64,
    bit_depth: u16,
    event_id_prefix: EventId,
) -> Result<Option<LocalHistoryNodeSecretRow>, String> {
    let key = local_history_node_secret_key(
        workspace_id,
        removal_frontier_id,
        range_start,
        range_width,
        bit_depth,
        event_id_prefix,
    );
    store
        .table_row(LOCAL_HISTORY_NODE_SECRETS, &key)
        .map_err(|err| format!("load local history node secret: {err}"))?
        .map(|value| decode_local_history_node_secret_row(&key, &value))
        .transpose()
}

/// Convenience: look up a per-event leaf row by `(unix_minute,
/// event_id_in_minute)`.
pub fn get_leaf(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    unix_minute: u64,
    event_id_in_minute: EventId,
) -> Result<Option<LocalHistoryNodeSecretRow>, String> {
    get(
        store,
        workspace_id,
        removal_frontier_id,
        unix_minute,
        1,
        super::types::TRIE_LEAF_BIT_DEPTH,
        event_id_in_minute,
    )
}

/// Convenience: look up a minute_node row by `unix_minute`.
pub fn get_minute_node(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    unix_minute: u64,
) -> Result<Option<LocalHistoryNodeSecretRow>, String> {
    get(
        store,
        workspace_id,
        removal_frontier_id,
        unix_minute,
        1,
        super::types::TIME_TREE_BIT_DEPTH,
        [0; 32],
    )
}

pub fn list_for_workspace(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<LocalHistoryNodeSecretRow>, String> {
    store
        .table_rows_with_key_prefix(LOCAL_HISTORY_NODE_SECRETS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load local history node secrets: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_local_history_node_secret_row(&key, &value))
        .collect()
}

pub fn list_tombstones_for_workspace(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<LocalHistoryNodeTombstoneRow>, String> {
    store
        .table_rows_with_key_prefix(LOCAL_HISTORY_NODE_TOMBSTONES, &workspace_id, usize::MAX)
        .map_err(|err| format!("load local history node tombstones: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_local_history_node_tombstone_row(&key, &value))
        .collect()
}

/// Return all materialized minute_node rows for a workspace+frontier.
pub fn list_minute_nodes(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<LocalHistoryNodeSecretRow>, String> {
    Ok(list_for_workspace(store, workspace_id)?
        .into_iter()
        .filter(is_minute_node_row)
        .collect())
}

/// Return all materialized leaf rows (`bit_depth = 256`) for a workspace.
pub fn list_leaves(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<LocalHistoryNodeSecretRow>, String> {
    Ok(list_for_workspace(store, workspace_id)?
        .into_iter()
        .filter(is_leaf_row)
        .collect())
}

/// Canonical, workspace-independent encoding of every retained node-secret
/// coordinate AND every retire tombstone in this store.
///
/// The encoding is deliberately stable and platform-agnostic:
///
/// ```text
/// "topo cover summary v4"
/// || u32_be(secret_rows.len())
/// || (for each secret row, sorted by (frontier_id, range_start, range_width,
///                                     bit_depth, event_id_prefix):
///       removal_frontier_id (32B)
///       || u64_be(range_start)
///       || u64_be(range_width)
///       || u16_be(bit_depth)
///       || event_id_prefix (32B; masked to bit_depth)
///   )
/// || u32_be(tombstones.len())
/// || (for each tombstone, sorted by (frontier_id, tombstone_node_id):
///       removal_frontier_id (32B)
///       || tombstone_node_id (32B)
///   )
/// ```
///
/// Each secret row encodes 32 + 8 + 8 + 2 + 32 = **82 bytes**; each tombstone
/// encodes 32 + 32 = **64 bytes**. Total summary length is therefore
/// `21 + 4 + 82 * secret_rows.len() + 4 + 64 * tombstones.len()` and so
/// O(materialized_rows + tombstones).
///
/// Two stores that have admitted the same shared event set and run the same
/// retain/retire operations against it must produce byte-equal cover summaries
/// modulo `workspace_id`. Two stores with different workspace_ids will differ;
/// the workspace_id is intentionally not in the summary so it functions as the
/// pure structural fingerprint of the retained tree.
pub fn cover_summary(store: &Store, workspace_id: EventId) -> Result<Vec<u8>, String> {
    let mut rows = list_for_workspace(store, workspace_id)?;
    rows.sort_by(|a, b| {
        a.removal_frontier_id
            .cmp(&b.removal_frontier_id)
            .then_with(|| a.range_start.cmp(&b.range_start))
            .then_with(|| a.range_width.cmp(&b.range_width))
            .then_with(|| a.bit_depth.cmp(&b.bit_depth))
            .then_with(|| a.event_id_prefix.cmp(&b.event_id_prefix))
    });
    let mut tombstones = list_tombstones_for_workspace(store, workspace_id)?;
    tombstones.sort_by(|a, b| {
        a.removal_frontier_id
            .cmp(&b.removal_frontier_id)
            .then_with(|| a.tombstone_node_id.cmp(&b.tombstone_node_id))
    });
    let mut out = Writer::with_capacity(
        b"topo cover summary v4".len()
            + 4
            + rows.len() * schema::COVER_SUMMARY_ROW_LEN
            + 4
            + tombstones.len() * schema::COVER_SUMMARY_TOMBSTONE_LEN,
    );
    out.raw(b"topo cover summary v4");
    let len = u32::try_from(rows.len()).unwrap_or(u32::MAX);
    out.raw(&len.to_be_bytes());
    for row in &rows {
        out.id(&row.removal_frontier_id);
        out.raw(&row.range_start.to_be_bytes());
        out.raw(&row.range_width.to_be_bytes());
        out.raw(&row.bit_depth.to_be_bytes());
        out.id(&mask_prefix_to_depth(row.event_id_prefix, row.bit_depth));
    }
    let tomb_len = u32::try_from(tombstones.len()).unwrap_or(u32::MAX);
    out.raw(&tomb_len.to_be_bytes());
    for tomb in &tombstones {
        out.id(&tomb.removal_frontier_id);
        out.id(&tomb.tombstone_node_id);
    }
    Ok(out.finish())
}

//! Schema for local history range-node secret rows and tombstones.
//!
//! Secret rows are keyed by
//! `(workspace_id, removal_frontier_id, range_start, range_width, bit_depth,
//!   event_id_prefix)`. The full key disambiguates time-tree internals
//! (`bit_depth=0, event_id_prefix=0`), minute_nodes (`bit_depth=0,
//! range_width=1`), trie internals (`1..=255`), and trie leaves (`256`).
//!
//! Tombstone rows map retired node ids to replacement node ids. These are
//! local retention and derivation aids, not shared removal facts.

use crate::core::crypto::XCHACHA20_POLY1305_KEY_BYTES;
use crate::core::store::{Schema, Store, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::{Reader, Writer};

use super::super::local_key_secret;
use super::types::{
    is_leaf_row, is_minute_node_row, mask_prefix_to_depth, row_covers, AncestorSource,
    LocalHistoryNodeSecret, LocalHistoryNodeSecretRow, LocalHistoryNodeTombstoneRow,
    TIME_TREE_BIT_DEPTH, TRIE_LEAF_BIT_DEPTH,
};

pub const LOCAL_HISTORY_NODE_SECRETS: TableName =
    TableName::new("encryption.local_history_node_secrets");
pub const LOCAL_HISTORY_NODE_TOMBSTONES: TableName =
    TableName::new("encryption.local_history_node_tombstones");

pub const SCHEMAS: &[Schema] = &[
    Schema::durable_row_table(
        "encryption.local_history_node_secrets.v3",
        LOCAL_HISTORY_NODE_SECRETS,
    ),
    Schema::durable_row_table(
        "encryption.local_history_node_tombstones.v1",
        LOCAL_HISTORY_NODE_TOMBSTONES,
    ),
];

/// Length of the encoded `local_history_node_secrets` row key:
/// `workspace_id (32) || removal_frontier_id (32) || range_start (8)
///   || range_width (8) || bit_depth (2) || event_id_prefix (32)`.
pub const LOCAL_HISTORY_NODE_SECRET_KEY_LEN: usize = 32 + 32 + 8 + 8 + 2 + 32;

pub fn local_history_node_secret_row(
    local_history_node_secret_id: EventId,
    event: &LocalHistoryNodeSecret,
) -> TableRow {
    TableRow {
        table: LOCAL_HISTORY_NODE_SECRETS,
        key: local_history_node_secret_key(
            event.workspace_id,
            event.removal_frontier_id,
            event.range_start,
            event.range_width,
            event.bit_depth,
            event.event_id_prefix,
        ),
        value: encode_secret_value(local_history_node_secret_id, event),
    }
}

pub fn local_history_node_tombstone_row(
    event: &LocalHistoryNodeSecret,
    replacement_node_id: EventId,
    tombstone_node_id: EventId,
) -> TableRow {
    TableRow {
        table: LOCAL_HISTORY_NODE_TOMBSTONES,
        key: local_history_node_tombstone_key(
            event.workspace_id,
            event.removal_frontier_id,
            tombstone_node_id,
        ),
        value: encode_tombstone_value(replacement_node_id),
    }
}

pub fn local_history_node_secret_key(
    workspace_id: EventId,
    removal_frontier_id: EventId,
    range_start: u64,
    range_width: u64,
    bit_depth: u16,
    event_id_prefix: EventId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(LOCAL_HISTORY_NODE_SECRET_KEY_LEN);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&removal_frontier_id);
    key.extend_from_slice(&range_start.to_be_bytes());
    key.extend_from_slice(&range_width.to_be_bytes());
    key.extend_from_slice(&bit_depth.to_be_bytes());
    key.extend_from_slice(&mask_prefix_to_depth(event_id_prefix, bit_depth));
    key
}

pub fn local_history_node_tombstone_key(
    workspace_id: EventId,
    removal_frontier_id: EventId,
    tombstone_node_id: EventId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(96);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&removal_frontier_id);
    key.extend_from_slice(&tombstone_node_id);
    key
}

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

/// Return all materialized trie leaves in a single minute under one frontier.
/// Used by retirement to compute trie divergence depths against survivors.
pub fn list_leaves_in_minute(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    unix_minute: u64,
) -> Result<Vec<LocalHistoryNodeSecretRow>, String> {
    Ok(list_for_frontier(store, workspace_id, removal_frontier_id)?
        .into_iter()
        .filter(|row| {
            row.range_start == unix_minute
                && row.range_width == 1
                && row.bit_depth == TRIE_LEAF_BIT_DEPTH
        })
        .collect())
}

/// Find the closest source-of-derivation for the leaf at
/// `(unix_minute, event_id_in_minute)` under this frontier. Falls back to the
/// frontier root (`local_key_secret`) when no materialized internal covers
/// the position. When `exclude_leaf` is true, skip the leaf-being-retired
/// itself (it cannot be its own ancestor).
///
/// Specificity ranks first by smaller `range_width`, then by larger
/// `bit_depth`. The returned `AncestorSource` carries the secret material
/// and identity needed to resume derivation toward the leaf.
pub fn closest_ancestor(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    unix_minute: u64,
    event_id_in_minute: EventId,
    exclude_leaf: bool,
) -> Result<AncestorSource, String> {
    let root = local_key_secret::schema::get(store, workspace_id, removal_frontier_id)?
        .ok_or_else(|| "local key secret is missing for removal frontier".to_string())?;
    let mut best = AncestorSource::Root {
        secret_id: root.local_key_secret_id,
        secret: root.key_secret,
    };
    let mut best_range_width = u64::MAX;
    let mut best_bit_depth = TIME_TREE_BIT_DEPTH;

    for row in list_for_frontier(store, workspace_id, removal_frontier_id)? {
        if !row_covers(&row, unix_minute, event_id_in_minute) {
            continue;
        }
        if exclude_leaf
            && row.bit_depth == TRIE_LEAF_BIT_DEPTH
            && row.event_id_prefix == event_id_in_minute
        {
            continue;
        }
        let better = matches!(best, AncestorSource::Root { .. })
            || row.range_width < best_range_width
            || (row.range_width == best_range_width && row.bit_depth > best_bit_depth);
        if !better {
            continue;
        }
        best_range_width = row.range_width;
        best_bit_depth = row.bit_depth;
        best = if row.range_width > 1 {
            AncestorSource::TimeInternal {
                secret_id: row.local_history_node_secret_id,
                secret: row.node_secret,
                range_start: row.range_start,
                range_width: row.range_width,
            }
        } else {
            AncestorSource::InMinute {
                secret_id: row.local_history_node_secret_id,
                secret: row.node_secret,
                range_start: row.range_start,
                bit_depth: row.bit_depth,
                event_id_prefix: row.event_id_prefix,
            }
        };
    }
    Ok(best)
}

/// Canonical, workspace-independent encoding of every retained node-secret
/// coordinate in this store.
///
/// The encoding is deliberately stable and platform-agnostic:
///
/// ```text
/// "topo cover summary v3"
/// || u32_be(rows.len())
/// || (for each row, sorted by (frontier_id, range_start, range_width,
///                              bit_depth, event_id_prefix):
///       removal_frontier_id (32B)
///       || u64_be(range_start)
///       || u64_be(range_width)
///       || u16_be(bit_depth)
///       || event_id_prefix (32B; masked to bit_depth)
///   )
/// ```
///
/// Each row encodes 32 + 8 + 8 + 2 + 32 = **82 bytes**; total summary length
/// is `21 + 4 + 82 * rows.len()` and therefore O(materialized_rows).
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
    let mut out = Writer::with_capacity(
        b"topo cover summary v3".len() + 4 + rows.len() * COVER_SUMMARY_ROW_LEN,
    );
    out.raw(b"topo cover summary v3");
    let len = u32::try_from(rows.len()).unwrap_or(u32::MAX);
    out.raw(&len.to_be_bytes());
    for row in &rows {
        out.id(&row.removal_frontier_id);
        out.raw(&row.range_start.to_be_bytes());
        out.raw(&row.range_width.to_be_bytes());
        out.raw(&row.bit_depth.to_be_bytes());
        out.id(&mask_prefix_to_depth(row.event_id_prefix, row.bit_depth));
    }
    Ok(out.finish())
}

/// Bytes per row in the `cover_summary` encoding.
pub const COVER_SUMMARY_ROW_LEN: usize = 32 + 8 + 8 + 2 + 32;

pub fn decode_local_history_node_secret_row(
    key: &[u8],
    value: &[u8],
) -> Result<LocalHistoryNodeSecretRow, String> {
    if key.len() != LOCAL_HISTORY_NODE_SECRET_KEY_LEN {
        return Err("local history node secret row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut removal_frontier_id = [0; 32];
    removal_frontier_id.copy_from_slice(&key[32..64]);
    let range_start = u64::from_be_bytes(
        key[64..72]
            .try_into()
            .map_err(|_| "local history node range start malformed".to_string())?,
    );
    let range_width = u64::from_be_bytes(
        key[72..80]
            .try_into()
            .map_err(|_| "local history node range width malformed".to_string())?,
    );
    let bit_depth = u16::from_be_bytes(
        key[80..82]
            .try_into()
            .map_err(|_| "local history node bit depth malformed".to_string())?,
    );
    let mut event_id_prefix = [0; 32];
    event_id_prefix.copy_from_slice(&key[82..114]);

    let mut reader = Reader::new(value, "local history node secret row");
    let local_history_node_secret_id = reader.id()?;
    let source_secret_id = reader.id()?;
    let tombstone_node_id = reader.id()?;
    let node_secret_bytes = reader.bytes(XCHACHA20_POLY1305_KEY_BYTES)?;
    reader.finish()?;
    let node_secret: [u8; XCHACHA20_POLY1305_KEY_BYTES] = node_secret_bytes
        .try_into()
        .map_err(|_| "local history node secret row material length mismatch".to_string())?;
    if node_secret.iter().all(|byte| *byte == 0) {
        return Err("local history node secret row material cannot be empty".to_string());
    }
    Ok(LocalHistoryNodeSecretRow {
        workspace_id,
        removal_frontier_id,
        local_history_node_secret_id,
        source_secret_id,
        range_start,
        range_width,
        bit_depth,
        event_id_prefix,
        tombstone_node_id: (!is_zero(&tombstone_node_id)).then_some(tombstone_node_id),
        node_secret,
    })
}

pub fn decode_local_history_node_tombstone_row(
    key: &[u8],
    value: &[u8],
) -> Result<LocalHistoryNodeTombstoneRow, String> {
    if key.len() != 96 {
        return Err("local history node tombstone row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut removal_frontier_id = [0; 32];
    removal_frontier_id.copy_from_slice(&key[32..64]);
    let mut tombstone_node_id = [0; 32];
    tombstone_node_id.copy_from_slice(&key[64..96]);
    let mut reader = Reader::new(value, "local history node tombstone row");
    let replacement_node_id = reader.id()?;
    reader.finish()?;
    Ok(LocalHistoryNodeTombstoneRow {
        workspace_id,
        removal_frontier_id,
        tombstone_node_id,
        replacement_node_id,
    })
}

fn encode_secret_value(
    local_history_node_secret_id: EventId,
    event: &LocalHistoryNodeSecret,
) -> Vec<u8> {
    let mut out = Writer::with_capacity(32 + 32 + 32 + XCHACHA20_POLY1305_KEY_BYTES);
    out.id(&local_history_node_secret_id);
    out.id(&event.source_secret_id);
    out.id(&event.tombstone_node_id.unwrap_or([0; 32]));
    out.raw(&event.node_secret);
    out.finish()
}

fn encode_tombstone_value(replacement_node_id: EventId) -> Vec<u8> {
    let mut out = Writer::with_capacity(32);
    out.id(&replacement_node_id);
    out.finish()
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

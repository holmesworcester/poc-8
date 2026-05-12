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

use super::types::{
    is_leaf_row, is_minute_node_row, mask_prefix_to_depth, LocalHistoryNodeSecret,
    LocalHistoryNodeSecretRow, LocalHistoryNodeTombstoneRow,
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
        "encryption.local_history_node_tombstones.v2",
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
        value: encode_tombstone_value(replacement_node_id, event.range_start, event.range_width),
    }
}

/// Build a tombstone row directly from `(workspace_id, removal_frontier_id,
/// tombstone_node_id, replacement_node_id, range_start, range_width)`.
///
/// Used by the retire walk and the chop walk in the encryption worker, where
/// tombstones are written without an admitting `LocalHistoryNodeSecret` event
/// (the wiped node is gone, only its event id survives as a marker).
///
/// `range_start + range_width` together name the time-axis interval the
/// tombstoned node covers; the chop GC uses this to decide which subsumed
/// per-leaf tombstones to exact-delete in the same transaction as the chop
/// wipe.
pub fn local_history_node_tombstone_row_by_id(
    workspace_id: EventId,
    removal_frontier_id: EventId,
    tombstone_node_id: EventId,
    replacement_node_id: EventId,
    range_start: u64,
    range_width: u64,
) -> TableRow {
    TableRow {
        table: LOCAL_HISTORY_NODE_TOMBSTONES,
        key: local_history_node_tombstone_key(
            workspace_id,
            removal_frontier_id,
            tombstone_node_id,
        ),
        value: encode_tombstone_value(replacement_node_id, range_start, range_width),
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
            + rows.len() * COVER_SUMMARY_ROW_LEN
            + 4
            + tombstones.len() * COVER_SUMMARY_TOMBSTONE_LEN,
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

/// Bytes per node-secret row in the `cover_summary` encoding.
pub const COVER_SUMMARY_ROW_LEN: usize = 32 + 8 + 8 + 2 + 32;

/// Bytes per tombstone in the `cover_summary` encoding.
pub const COVER_SUMMARY_TOMBSTONE_LEN: usize = 32 + 32;

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
    let range_start = reader.u64()?;
    let range_width = reader.u64()?;
    reader.finish()?;
    Ok(LocalHistoryNodeTombstoneRow {
        workspace_id,
        removal_frontier_id,
        tombstone_node_id,
        replacement_node_id,
        range_start,
        range_width,
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

fn encode_tombstone_value(
    replacement_node_id: EventId,
    range_start: u64,
    range_width: u64,
) -> Vec<u8> {
    let mut out = Writer::with_capacity(32 + 8 + 8);
    out.id(&replacement_node_id);
    out.u64(range_start);
    out.u64(range_width);
    out.finish()
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

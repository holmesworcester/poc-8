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
//!
//! Read views over these rows (single-row lookups, prefix scans, the
//! `cover_summary` fingerprint) live in `queries.rs`.

use crate::core::crypto::XCHACHA20_POLY1305_KEY_BYTES;
use crate::core::store::{Schema, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::{Reader, Writer};

use super::types::{mask_prefix_to_depth, LocalHistoryNodeSecret, LocalHistoryNodeSecretRow,
    LocalHistoryNodeTombstoneRow};

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

/// Bytes per node-secret row in the `cover_summary` encoding.
pub const COVER_SUMMARY_ROW_LEN: usize = 32 + 8 + 8 + 2 + 32;

/// Bytes per tombstone in the `cover_summary` encoding.
pub const COVER_SUMMARY_TOMBSTONE_LEN: usize = 32 + 32;

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

//! Schema for local history range-node secret rows and tombstones.
//!
//! Secret rows are keyed by workspace, frontier, range start, and range width so
//! workers can find the current local node for a content-history interval.
//! Tombstone rows map retired node ids to replacement node ids. These are local
//! retention and derivation aids, not shared removal facts.

use crate::core::crypto::XCHACHA20_POLY1305_KEY_BYTES;
use crate::core::store::{Schema, Store, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::{Reader, Writer};

use super::types::{
    LocalHistoryNodeSecret, LocalHistoryNodeSecretRow, LocalHistoryNodeTombstoneRow,
};

pub const LOCAL_HISTORY_NODE_SECRETS: TableName =
    TableName::new("encryption.local_history_node_secrets");
pub const LOCAL_HISTORY_NODE_TOMBSTONES: TableName =
    TableName::new("encryption.local_history_node_tombstones");

pub const SCHEMAS: &[Schema] = &[
    Schema::durable_row_table(
        "encryption.local_history_node_secrets.v1",
        LOCAL_HISTORY_NODE_SECRETS,
    ),
    Schema::durable_row_table(
        "encryption.local_history_node_tombstones.v1",
        LOCAL_HISTORY_NODE_TOMBSTONES,
    ),
];

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
) -> Vec<u8> {
    let mut key = Vec::with_capacity(80);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&removal_frontier_id);
    key.extend_from_slice(&range_start.to_be_bytes());
    key.extend_from_slice(&range_width.to_be_bytes());
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

pub fn get(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    range_start: u64,
    range_width: u64,
) -> Result<Option<LocalHistoryNodeSecretRow>, String> {
    let key =
        local_history_node_secret_key(workspace_id, removal_frontier_id, range_start, range_width);
    store
        .table_row(LOCAL_HISTORY_NODE_SECRETS, &key)
        .map_err(|err| format!("load local history node secret: {err}"))?
        .map(|value| decode_local_history_node_secret_row(&key, &value))
        .transpose()
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

pub fn decode_local_history_node_secret_row(
    key: &[u8],
    value: &[u8],
) -> Result<LocalHistoryNodeSecretRow, String> {
    if key.len() != 80 {
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

//! Schema for local key-secret rows.
//!
//! Rows are keyed by `workspace_id || removal_frontier_id`, enforcing one local
//! content key for each frontier in this node's store. The value carries the
//! deterministic local event id plus secret bytes. This schema is local storage
//! shape only; commands/projectors decide when the row may exist.

use crate::core::crypto::XCHACHA20_POLY1305_KEY_BYTES;
use crate::core::store::{Schema, Store, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::{Reader, Writer};

use super::types::{LocalKeySecret, LocalKeySecretRow};

pub const LOCAL_KEY_SECRETS: TableName = TableName::new("encryption.local_key_secrets");

pub const SCHEMAS: &[Schema] = &[Schema::durable_row_table(
    "encryption.local_key_secrets.v1",
    LOCAL_KEY_SECRETS,
)];

pub fn local_key_secret_row(local_key_secret_id: EventId, event: &LocalKeySecret) -> TableRow {
    TableRow {
        table: LOCAL_KEY_SECRETS,
        key: local_key_secret_key(event.workspace_id, event.removal_frontier_id),
        value: encode_value(local_key_secret_id, event),
    }
}

pub fn local_key_secret_key(workspace_id: EventId, removal_frontier_id: EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&removal_frontier_id);
    key
}

pub fn get(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
) -> Result<Option<LocalKeySecretRow>, String> {
    let key = local_key_secret_key(workspace_id, removal_frontier_id);
    store
        .table_row(LOCAL_KEY_SECRETS, &key)
        .map_err(|err| format!("load local key secret: {err}"))?
        .map(|value| decode_local_key_secret_row(&key, &value))
        .transpose()
}

pub fn list_for_workspace(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<LocalKeySecretRow>, String> {
    store
        .table_rows_with_key_prefix(LOCAL_KEY_SECRETS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load local key secrets: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_local_key_secret_row(&key, &value))
        .collect()
}

pub fn decode_local_key_secret_row(key: &[u8], value: &[u8]) -> Result<LocalKeySecretRow, String> {
    if key.len() != 64 {
        return Err("local key secret row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut removal_frontier_id = [0; 32];
    removal_frontier_id.copy_from_slice(&key[32..64]);

    let mut reader = Reader::new(value, "local key secret row");
    let local_key_secret_id = reader.id()?;
    let key_secret_bytes = reader.bytes(XCHACHA20_POLY1305_KEY_BYTES)?;
    reader.finish()?;
    let key_secret: [u8; XCHACHA20_POLY1305_KEY_BYTES] = key_secret_bytes
        .try_into()
        .map_err(|_| "local key secret row material length mismatch".to_string())?;
    if key_secret.iter().all(|byte| *byte == 0) {
        return Err("local key secret row material cannot be empty".to_string());
    }
    Ok(LocalKeySecretRow {
        workspace_id,
        removal_frontier_id,
        local_key_secret_id,
        key_secret,
    })
}

fn encode_value(local_key_secret_id: EventId, event: &LocalKeySecret) -> Vec<u8> {
    let mut out = Writer::with_capacity(32 + XCHACHA20_POLY1305_KEY_BYTES);
    out.id(&local_key_secret_id);
    out.raw(&event.key_secret);
    out.finish()
}

#[cfg(test)]
mod tests {
    use crate::core::store::Store;

    use super::super::commands;
    use super::*;

    #[test]
    fn row_key_enforces_one_secret_per_frontier() {
        let left = commands::from_key_secret([1; 32], [2; 32], [7; 32])
            .expect("left")
            .value;
        let right = commands::from_key_secret([1; 32], [2; 32], [8; 32])
            .expect("right")
            .value;
        let store = Store::open_memory_with_schemas(SCHEMAS).expect("store");
        store
            .insert_table_rows(vec![local_key_secret_row(
                left.local_key_secret_id,
                &left.event,
            )])
            .expect("insert left");

        let err = store
            .insert_table_rows(vec![local_key_secret_row(
                right.local_key_secret_id,
                &right.event,
            )])
            .expect_err("conflicting frontier secret must fail");

        assert!(err.to_string().contains("conflicting row for"));
    }
}

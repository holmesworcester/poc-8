//! Schema for key-wrap rows.
//!
//! `KEY_WRAPS` is keyed by `workspace_id || removal_frontier_id ||
//! recipient_key_id`, making "can this recipient open this frontier?" an exact
//! lookup. `KEY_SECRET_COMMITMENTS` records the local key-secret id committed by
//! a frontier so command-side wrap construction cannot substitute different
//! secret bytes. `PENDING_KEY_UNWRAPS` is the projected worker queue: the
//! projector writes it when a valid shared wrap appears, and the encryption
//! worker drains it to create the local-only key-secret event.

use crate::core::crypto::XCHACHA20_POLY1305_NONCE_BYTES;
use crate::core::store::{Schema, Store, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::{Reader, Writer};

use super::types::{KeyWrapEvent, KeyWrapRow, PendingKeyUnwrapRow, KEY_WRAP_CIPHERTEXT_BYTES};

pub const KEY_WRAPS: TableName = TableName::new("encryption.key_wraps");
pub const KEY_SECRET_COMMITMENTS: TableName = TableName::new("encryption.key_secret_commitments");
pub const PENDING_KEY_UNWRAPS: TableName = TableName::new("encryption.pending_key_unwraps");

pub const SCHEMAS: &[Schema] = &[
    Schema::durable_row_table("encryption.key_wraps.v1", KEY_WRAPS),
    Schema::durable_row_table(
        "encryption.key_secret_commitments.v1",
        KEY_SECRET_COMMITMENTS,
    ),
    Schema::durable_row_table("encryption.pending_key_unwraps.v1", PENDING_KEY_UNWRAPS),
];

pub fn key_wrap_row(
    key_wrap_id: EventId,
    signer_endpoint_shared_id: EventId,
    signer_public_key: EventId,
    event: &KeyWrapEvent,
) -> TableRow {
    TableRow {
        table: KEY_WRAPS,
        key: key_wrap_key(
            event.workspace_id,
            event.removal_frontier_id,
            event.recipient_key_id,
        ),
        value: encode_value(
            key_wrap_id,
            signer_endpoint_shared_id,
            signer_public_key,
            event,
        ),
    }
}

pub fn key_secret_commitment_row(event: &KeyWrapEvent) -> TableRow {
    TableRow {
        table: KEY_SECRET_COMMITMENTS,
        key: key_secret_commitment_key(event.workspace_id, event.removal_frontier_id),
        value: event.local_key_secret_id.to_vec(),
    }
}

pub fn pending_key_unwrap_row(key_wrap_id: EventId, event: &KeyWrapEvent) -> TableRow {
    TableRow {
        table: PENDING_KEY_UNWRAPS,
        key: key_wrap_key(
            event.workspace_id,
            event.removal_frontier_id,
            event.recipient_key_id,
        ),
        value: key_wrap_id.to_vec(),
    }
}

pub fn key_wrap_key(
    workspace_id: EventId,
    removal_frontier_id: EventId,
    recipient_key_id: EventId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(96);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&removal_frontier_id);
    key.extend_from_slice(&recipient_key_id);
    key
}

pub fn key_secret_commitment_key(workspace_id: EventId, removal_frontier_id: EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&removal_frontier_id);
    key
}

pub fn list_all(store: &Store) -> Result<Vec<KeyWrapRow>, String> {
    store
        .table_rows_with_key_prefix(KEY_WRAPS, &[], usize::MAX)
        .map_err(|err| format!("load key wraps: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_key_wrap_row(&key, &value))
        .collect()
}

pub fn list_for_workspace(store: &Store, workspace_id: EventId) -> Result<Vec<KeyWrapRow>, String> {
    store
        .table_rows_with_key_prefix(KEY_WRAPS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load key wraps: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_key_wrap_row(&key, &value))
        .collect()
}

pub fn list_pending_unwraps(
    store: &Store,
    limit: usize,
) -> Result<Vec<PendingKeyUnwrapRow>, String> {
    store
        .table_rows_with_key_prefix(PENDING_KEY_UNWRAPS, &[], limit)
        .map_err(|err| format!("load pending key unwraps: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_pending_key_unwrap_row(key, &value))
        .collect()
}

pub fn key_wrap_for_pending(
    store: &Store,
    pending: &PendingKeyUnwrapRow,
) -> Result<Option<KeyWrapRow>, String> {
    store
        .table_row(KEY_WRAPS, &pending.key)
        .map_err(|err| format!("load pending key wrap: {err}"))?
        .map(|value| decode_key_wrap_row(&pending.key, &value))
        .transpose()
}

pub fn delete_pending_unwraps(store: &Store, pending_keys: Vec<Vec<u8>>) -> Result<usize, String> {
    if pending_keys.is_empty() {
        return Ok(0);
    }
    store
        .delete_table_rows(PENDING_KEY_UNWRAPS, pending_keys)
        .map_err(|err| format!("delete pending key unwraps: {err}"))
}

pub fn decode_key_wrap_row(key: &[u8], value: &[u8]) -> Result<KeyWrapRow, String> {
    if key.len() != 96 {
        return Err("key wrap row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut removal_frontier_id = [0; 32];
    removal_frontier_id.copy_from_slice(&key[32..64]);
    let mut recipient_key_id = [0; 32];
    recipient_key_id.copy_from_slice(&key[64..96]);

    let mut reader = Reader::new(value, "key wrap row");
    let key_wrap_id = reader.id()?;
    let created_at_ms = reader.u64()?;
    let signer_endpoint_shared_id = reader.id()?;
    let signer_public_key = reader.id()?;
    let local_key_secret_id = reader.id()?;
    let sender_wrap_public_key = reader.id()?;
    let nonce = reader
        .bytes(XCHACHA20_POLY1305_NONCE_BYTES)?
        .try_into()
        .map_err(|_| "key wrap row nonce length mismatch".to_string())?;
    let ciphertext = reader
        .bytes(KEY_WRAP_CIPHERTEXT_BYTES)?
        .try_into()
        .map_err(|_| "key wrap row ciphertext length mismatch".to_string())?;
    reader.finish()?;
    Ok(KeyWrapRow {
        workspace_id,
        removal_frontier_id,
        recipient_key_id,
        key_wrap_id,
        created_at_ms,
        signer_endpoint_shared_id,
        signer_public_key,
        local_key_secret_id,
        sender_wrap_public_key,
        nonce,
        ciphertext,
    })
}

pub fn decode_pending_key_unwrap_row(
    key: Vec<u8>,
    value: &[u8],
) -> Result<PendingKeyUnwrapRow, String> {
    if key.len() != 96 {
        return Err("pending key unwrap row key is malformed".to_string());
    }
    if value.len() != 32 {
        return Err("pending key unwrap row value is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut removal_frontier_id = [0; 32];
    removal_frontier_id.copy_from_slice(&key[32..64]);
    let mut recipient_key_id = [0; 32];
    recipient_key_id.copy_from_slice(&key[64..96]);
    let mut key_wrap_id = [0; 32];
    key_wrap_id.copy_from_slice(value);
    Ok(PendingKeyUnwrapRow {
        key,
        workspace_id,
        removal_frontier_id,
        recipient_key_id,
        key_wrap_id,
    })
}

fn encode_value(
    key_wrap_id: EventId,
    signer_endpoint_shared_id: EventId,
    signer_public_key: EventId,
    event: &KeyWrapEvent,
) -> Vec<u8> {
    let mut out = Writer::with_capacity(
        32 + 8 + 32 + 32 + 32 + 32 + XCHACHA20_POLY1305_NONCE_BYTES + KEY_WRAP_CIPHERTEXT_BYTES,
    );
    out.id(&key_wrap_id);
    out.u64(event.created_at_ms);
    out.id(&signer_endpoint_shared_id);
    out.id(&signer_public_key);
    out.id(&event.local_key_secret_id);
    out.id(&event.sender_wrap_public_key);
    out.raw(&event.nonce);
    out.raw(&event.ciphertext);
    out.finish()
}

#[cfg(test)]
mod tests {
    use crate::core::store::Store;

    use super::*;

    fn event(local_key_secret_id: EventId) -> KeyWrapEvent {
        KeyWrapEvent {
            workspace_id: [1; 32],
            created_at_ms: 1,
            removal_frontier_id: [2; 32],
            local_key_secret_id,
            recipient_key_id: [3; 32],
            sender_wrap_public_key: [4; 32],
            nonce: [5; XCHACHA20_POLY1305_NONCE_BYTES],
            ciphertext: [6; KEY_WRAP_CIPHERTEXT_BYTES],
        }
    }

    #[test]
    fn commitment_row_enforces_one_key_secret_per_frontier() {
        let store = Store::open_memory_with_schemas(SCHEMAS).expect("store");
        store
            .insert_table_rows(vec![key_secret_commitment_row(&event([7; 32]))])
            .expect("insert first commitment");

        let err = store
            .insert_table_rows(vec![key_secret_commitment_row(&event([8; 32]))])
            .expect_err("conflicting commitment must fail");

        assert!(err.to_string().contains("conflicting row for"));
    }
}

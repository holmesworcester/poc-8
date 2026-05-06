//! Schema for local recipient key rows.
//!
//! Rows are keyed by `workspace_id || local_recipient_key_id` so workers can
//! find local private material for one workspace without scanning unrelated
//! workspaces.

use crate::core::crypto::{self, X25519PrivateKey, X25519PublicKey};
use crate::core::store::{Schema, Store, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::{Reader, Writer};

use super::types::{LocalRecipientKey, LocalRecipientKeyRow};

pub const LOCAL_RECIPIENT_KEYS: TableName = TableName::new("encryption.local_recipient_keys");

pub const SCHEMAS: &[Schema] = &[Schema::durable_row_table(
    "encryption.local_recipient_keys.v1",
    LOCAL_RECIPIENT_KEYS,
)];

pub fn local_recipient_key_row(
    local_recipient_key_id: EventId,
    event: &LocalRecipientKey,
) -> TableRow {
    TableRow {
        table: LOCAL_RECIPIENT_KEYS,
        key: local_recipient_key_key(event.workspace_id, local_recipient_key_id),
        value: encode_value(event.recipient_key, event.recipient_secret),
    }
}

pub fn local_recipient_key_key(workspace_id: EventId, local_recipient_key_id: EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&local_recipient_key_id);
    key
}

pub fn decode_local_recipient_key_row(
    key: &[u8],
    value: &[u8],
) -> Result<LocalRecipientKeyRow, String> {
    if key.len() != 64 {
        return Err("local recipient key row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut local_recipient_key_id = [0; 32];
    local_recipient_key_id.copy_from_slice(&key[32..64]);

    let mut reader = Reader::new(value, "local recipient key row");
    let recipient_key = reader.id()?;
    let recipient_secret = reader.id()?;
    reader.finish()?;
    if recipient_secret.iter().all(|byte| *byte == 0) {
        return Err("local recipient key row secret cannot be empty".to_string());
    }
    if crypto::x25519_public_key(&recipient_secret) != recipient_key {
        return Err("local recipient key row secret does not match public key".to_string());
    }
    Ok(LocalRecipientKeyRow {
        workspace_id,
        local_recipient_key_id,
        recipient_key,
        recipient_secret,
    })
}

pub fn list_for_workspace(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<LocalRecipientKeyRow>, String> {
    store
        .table_rows_with_key_prefix(LOCAL_RECIPIENT_KEYS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load local recipient keys: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_local_recipient_key_row(&key, &value))
        .collect()
}

fn encode_value(recipient_key: X25519PublicKey, recipient_secret: X25519PrivateKey) -> Vec<u8> {
    let mut out = Writer::with_capacity(64);
    out.id(&recipient_key);
    out.id(&recipient_secret);
    out.finish()
}

#[cfg(test)]
mod tests {
    use super::super::commands;
    use super::*;

    #[test]
    fn decode_row_rejects_mismatched_secret() {
        let good = commands::create([1; 32]).expect("create good").value;
        let bad = commands::create([1; 32]).expect("create bad").value;
        let value = encode_value(good.recipient_key, bad.recipient_secret);

        let err = decode_local_recipient_key_row(
            &local_recipient_key_key(good.workspace_id, [2; 32]),
            &value,
        )
        .expect_err("mismatched row must fail");

        assert_eq!(
            err,
            "local recipient key row secret does not match public key"
        );
    }
}

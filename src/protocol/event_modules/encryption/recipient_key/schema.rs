//! Schema for shared recipient key rows.
//!
//! Rows are keyed by `workspace_id || recipient_key_id` so workers can scan
//! public recipient keys for a workspace when deriving wrap obligations. This
//! schema stores public shared facts only; local private key rows live under
//! `local_recipient_key`.

use crate::core::crypto::X25519PublicKey;
use crate::core::store::{Schema, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::{Reader, Writer};

use super::types::{RecipientKeyEvent, RecipientKeyRow};

pub const RECIPIENT_KEYS: TableName = TableName::new("encryption.recipient_keys");

pub const SCHEMAS: &[Schema] = &[Schema::durable_row_table(
    "encryption.recipient_keys.v1",
    RECIPIENT_KEYS,
)];

pub fn recipient_key_row(
    recipient_key_id: EventId,
    event: &RecipientKeyEvent,
) -> Result<TableRow, String> {
    Ok(TableRow {
        table: RECIPIENT_KEYS,
        key: recipient_key_key(event.workspace_id, recipient_key_id),
        value: encode_value(event)?,
    })
}

pub fn recipient_key_key(workspace_id: EventId, recipient_key_id: EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&recipient_key_id);
    key
}

pub fn decode_recipient_key_row(key: &[u8], value: &[u8]) -> Result<RecipientKeyRow, String> {
    if key.len() != 64 {
        return Err("recipient key row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut recipient_key_id = [0; 32];
    recipient_key_id.copy_from_slice(&key[32..64]);

    let mut reader = Reader::new(value, "recipient key row");
    let created_at_ms = reader.u64()?;
    let endpoint_shared_id = reader.id()?;
    let recipient_key = reader.id()?;
    reader.finish()?;
    validate_public_key(&recipient_key)?;
    Ok(RecipientKeyRow {
        workspace_id,
        recipient_key_id,
        created_at_ms,
        endpoint_shared_id,
        recipient_key,
    })
}

fn encode_value(event: &RecipientKeyEvent) -> Result<Vec<u8>, String> {
    validate_public_key(&event.recipient_key)?;
    let mut out = Writer::with_capacity(8 + 32 + 32);
    out.u64(event.created_at_ms);
    out.id(&event.endpoint_shared_id);
    out.id(&event.recipient_key);
    Ok(out.finish())
}

fn validate_public_key(recipient_key: &X25519PublicKey) -> Result<(), String> {
    if recipient_key.iter().all(|byte| *byte == 0) {
        return Err("recipient key row public key cannot be empty".to_string());
    }
    Ok(())
}

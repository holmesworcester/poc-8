//! Schema for recipient key tombstone rows.
//!
//! Rows are keyed by `workspace_id || old_recipient_key_id`, making retirement
//! an exact lookup for a public key. The value stores the tombstone event id,
//! endpoint membership, and replacement key id. This schema records the shared
//! fact only; it does not erase local recipient private material.

use crate::core::store::{Schema, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::{Reader, Writer};

use super::types::{RecipientKeyTombstoneEvent, RecipientKeyTombstoneRow};

pub const RECIPIENT_KEY_TOMBSTONES: TableName =
    TableName::new("encryption.recipient_key_tombstones");

pub const SCHEMAS: &[Schema] = &[Schema::durable_row_table(
    "encryption.recipient_key_tombstones.v1",
    RECIPIENT_KEY_TOMBSTONES,
)];

pub fn recipient_key_tombstone_row(
    tombstone_id: EventId,
    event: &RecipientKeyTombstoneEvent,
) -> TableRow {
    TableRow {
        table: RECIPIENT_KEY_TOMBSTONES,
        key: recipient_key_tombstone_key(event.workspace_id, event.old_recipient_key_id),
        value: encode_value(tombstone_id, event),
    }
}

pub fn recipient_key_tombstone_key(
    workspace_id: EventId,
    old_recipient_key_id: EventId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&old_recipient_key_id);
    key
}

pub fn decode_recipient_key_tombstone_row(
    key: &[u8],
    value: &[u8],
) -> Result<RecipientKeyTombstoneRow, String> {
    if key.len() != 64 {
        return Err("recipient key tombstone row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut old_recipient_key_id = [0; 32];
    old_recipient_key_id.copy_from_slice(&key[32..64]);

    let mut reader = Reader::new(value, "recipient key tombstone row");
    let tombstone_id = reader.id()?;
    let created_at_ms = reader.u64()?;
    let endpoint_shared_id = reader.id()?;
    let new_recipient_key_id = reader.id()?;
    reader.finish()?;
    if old_recipient_key_id == new_recipient_key_id {
        return Err("recipient key tombstone row must name different keys".to_string());
    }
    Ok(RecipientKeyTombstoneRow {
        workspace_id,
        old_recipient_key_id,
        tombstone_id,
        created_at_ms,
        endpoint_shared_id,
        new_recipient_key_id,
    })
}

fn encode_value(tombstone_id: EventId, event: &RecipientKeyTombstoneEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(32 + 8 + 32 + 32);
    out.id(&tombstone_id);
    out.u64(event.created_at_ms);
    out.id(&event.endpoint_shared_id);
    out.id(&event.new_recipient_key_id);
    out.finish()
}

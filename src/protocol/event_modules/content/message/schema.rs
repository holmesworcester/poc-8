//! Message projection rows.
//!
//! Rows are keyed by `workspace_id || message_id` so list queries can scan all
//! messages in one workspace with a bounded prefix scan. Author and signer ids
//! are stored alongside the text so display queries can join with users without
//! re-decoding canonical bytes.

use crate::core::store::{Schema, Store, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::{Reader, Writer};

use super::codec;
use super::types::{MessagePlaintext, MessageRow, MESSAGE_TEXT_BYTES};

pub const MESSAGES: TableName = TableName::new("content.messages");
pub const MESSAGE_TOMBSTONES: TableName = TableName::new("content.message_tombstones");

pub const SCHEMAS: &[Schema] = &[
    Schema::durable_row_table("content.messages.v1", MESSAGES),
    Schema::durable_row_table("content.message_tombstones.v1", MESSAGE_TOMBSTONES),
];

pub fn message_row(
    message_id: EventId,
    signer_endpoint_shared_id: EventId,
    event: &MessagePlaintext,
) -> Result<TableRow, String> {
    Ok(TableRow {
        table: MESSAGES,
        key: message_key(event.workspace_id, message_id),
        value: encode_value(signer_endpoint_shared_id, event)?,
    })
}

pub fn message_key(workspace_id: EventId, message_id: EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&message_id);
    key
}

pub fn message_tombstone_row(
    workspace_id: EventId,
    message_id: EventId,
    author_user_id: EventId,
) -> TableRow {
    TableRow {
        table: MESSAGE_TOMBSTONES,
        key: message_key(workspace_id, message_id),
        value: author_user_id.to_vec(),
    }
}

pub fn message_tombstone_exists(
    store: &Store,
    workspace_id: EventId,
    message_id: EventId,
) -> Result<bool, String> {
    let key = message_key(workspace_id, message_id);
    store
        .table_row(MESSAGE_TOMBSTONES, &key)
        .map(|row| row.is_some())
        .map_err(|err| format!("load message tombstone: {err}"))
}

pub fn decode_message_row(key: &[u8], value: &[u8]) -> Result<MessageRow, String> {
    if key.len() != 64 {
        return Err("message row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut message_id = [0; 32];
    message_id.copy_from_slice(&key[32..64]);

    let mut reader = Reader::new(value, "message row");
    let created_at_ms = reader.u64()?;
    let author_user_id = reader.id()?;
    let signer_endpoint_shared_id = reader.id()?;
    let text = codec::decode_text_slot(reader.slice(MESSAGE_TEXT_BYTES)?)?;
    reader.finish()?;

    Ok(MessageRow {
        workspace_id,
        message_id,
        created_at_ms,
        author_user_id,
        signer_endpoint_shared_id,
        text,
    })
}

pub fn list_for_workspace(store: &Store, workspace_id: EventId) -> Result<Vec<MessageRow>, String> {
    let mut rows = store
        .table_rows_with_key_prefix(MESSAGES, &workspace_id, usize::MAX)
        .map_err(|err| format!("load messages: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_message_row(&key, &value))
        .collect::<Result<Vec<_>, _>>()?;
    rows.sort_by(|a, b| {
        a.created_at_ms
            .cmp(&b.created_at_ms)
            .then_with(|| a.message_id.cmp(&b.message_id))
    });
    Ok(rows)
}

pub fn count_for_workspace(store: &Store, workspace_id: EventId) -> Result<usize, String> {
    store
        .table_rows_with_key_prefix(MESSAGES, &workspace_id, usize::MAX)
        .map(|rows| rows.len())
        .map_err(|err| format!("count messages: {err}"))
}

pub fn message_by_id(
    store: &Store,
    workspace_id: EventId,
    message_id: EventId,
) -> Result<Option<MessageRow>, String> {
    let key = message_key(workspace_id, message_id);
    store
        .table_row(MESSAGES, &key)
        .map_err(|err| format!("load message: {err}"))?
        .map(|value| decode_message_row(&key, &value))
        .transpose()
}

fn encode_value(
    signer_endpoint_shared_id: EventId,
    event: &MessagePlaintext,
) -> Result<Vec<u8>, String> {
    let text = codec::encode_text_slot(&event.text)?;
    let mut out = Writer::with_capacity(8 + 32 + 32 + MESSAGE_TEXT_BYTES);
    out.u64(event.created_at_ms);
    out.id(&event.author_user_id);
    out.id(&signer_endpoint_shared_id);
    out.raw(&text);
    Ok(out.finish())
}

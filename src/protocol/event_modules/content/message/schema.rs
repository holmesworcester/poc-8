//! Message projection rows.
//!
//! Rows are keyed by `workspace_id || message_id` so list queries can scan all
//! messages in one workspace with a bounded prefix scan. Author and signer ids
//! are stored alongside the text so display queries can join with users without
//! re-decoding canonical bytes.
//!
//! Reads (lookups, scans, tombstone-existence queries) live in
//! `queries.rs`. The receive-side admit gate lives in `projector.rs`.

use crate::core::store::{Schema, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::{Reader, Writer};

use super::codec;
use super::types::{
    MessageCiphertext, MessageEvent, MessagePlaintext, MessageRow, MESSAGE_CIPHERTEXT_BYTES,
    MESSAGE_TEXT_BYTES,
};

pub const MESSAGES: TableName = TableName::new("content.messages");
pub const SEALED_MESSAGES: TableName = TableName::new("content.sealed_messages");
pub const MESSAGE_TOMBSTONES: TableName = TableName::new("content.message_tombstones");

pub const SCHEMAS: &[Schema] = &[
    Schema::durable_row_table("content.messages.v2", MESSAGES),
    Schema::durable_row_table("content.sealed_messages.v4", SEALED_MESSAGES),
    Schema::durable_row_table("content.message_tombstones.v2", MESSAGE_TOMBSTONES),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedMessageRow {
    pub workspace_id: EventId,
    pub message_id: EventId,
    pub created_at_ms: u64,
    pub author_user_id: EventId,
    pub signer_endpoint_shared_id: EventId,
    pub removal_frontier_id: EventId,
    pub local_history_node_secret_id: EventId,
    /// Authoring-time expiry stamped into canonical bytes; surfaces here so
    /// the disappearing-minute worker can enumerate expired minutes and the
    /// projector can reject expired-at-receive messages.
    pub expires_at_minute: u64,
    /// Reference to the disappearing-messages policy this message was
    /// authored under. Either a signed `disappearing_messages_setting`
    /// event id or the workspace event id (slice-1 fallback).
    pub disappearing_setting_id: EventId,
    pub nonce: crate::core::crypto::XChaCha20Poly1305Nonce,
    pub ciphertext: MessageCiphertext,
}

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

pub fn sealed_message_row(
    message_id: EventId,
    signer_endpoint_shared_id: EventId,
    event: &MessageEvent,
) -> Result<TableRow, String> {
    Ok(TableRow {
        table: SEALED_MESSAGES,
        key: message_key(event.workspace_id, message_id),
        value: encode_sealed_value(signer_endpoint_shared_id, event),
    })
}

pub fn decode_sealed_message_row(key: &[u8], value: &[u8]) -> Result<SealedMessageRow, String> {
    if key.len() != 64 {
        return Err("sealed message row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut message_id = [0; 32];
    message_id.copy_from_slice(&key[32..64]);

    let mut reader = Reader::new(value, "sealed message row");
    let created_at_ms = reader.u64()?;
    let author_user_id = reader.id()?;
    let signer_endpoint_shared_id = reader.id()?;
    let removal_frontier_id = reader.id()?;
    let local_history_node_secret_id = reader.id()?;
    let expires_at_minute = reader.u64()?;
    let disappearing_setting_id = reader.id()?;
    let nonce = reader
        .bytes(crate::core::crypto::XCHACHA20_POLY1305_NONCE_BYTES)?
        .try_into()
        .map_err(|_| "sealed message row nonce length mismatch".to_string())?;
    let ciphertext = reader
        .bytes(MESSAGE_CIPHERTEXT_BYTES)?
        .try_into()
        .map_err(|_| "sealed message row ciphertext length mismatch".to_string())?;
    reader.finish()?;
    Ok(SealedMessageRow {
        workspace_id,
        message_id,
        created_at_ms,
        author_user_id,
        signer_endpoint_shared_id,
        removal_frontier_id,
        local_history_node_secret_id,
        expires_at_minute,
        disappearing_setting_id,
        nonce,
        ciphertext,
    })
}

pub fn message_tombstone_row(
    workspace_id: EventId,
    message_id: EventId,
    author_user_id: EventId,
    authored_minute: u64,
) -> TableRow {
    let mut value = Vec::with_capacity(32 + 8);
    value.extend_from_slice(&author_user_id);
    value.extend_from_slice(&authored_minute.to_be_bytes());
    TableRow {
        table: MESSAGE_TOMBSTONES,
        key: message_key(workspace_id, message_id),
        value,
    }
}

/// Decoded view of a `MESSAGE_TOMBSTONES` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageTombstoneRow {
    pub workspace_id: EventId,
    pub message_id: EventId,
    pub author_user_id: EventId,
    /// Authoring minute = `created_at_ms / UNIX_MINUTE_MS`. Stored so the
    /// chop GC can decide whether this tombstone is subsumed by a new
    /// chop floor.
    pub authored_minute: u64,
}

pub fn decode_message_tombstone_row(
    key: &[u8],
    value: &[u8],
) -> Result<MessageTombstoneRow, String> {
    if key.len() != 64 {
        return Err("message tombstone row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut message_id = [0; 32];
    message_id.copy_from_slice(&key[32..64]);
    if value.len() != 40 {
        return Err(format!(
            "message tombstone row value length {} expected 40",
            value.len()
        ));
    }
    let mut author_user_id = [0; 32];
    author_user_id.copy_from_slice(&value[..32]);
    let authored_minute = u64::from_be_bytes(
        value[32..40]
            .try_into()
            .map_err(|_| "message tombstone authored minute malformed".to_string())?,
    );
    Ok(MessageTombstoneRow {
        workspace_id,
        message_id,
        author_user_id,
        authored_minute,
    })
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

fn encode_sealed_value(signer_endpoint_shared_id: EventId, event: &MessageEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(
        8 + 32
            + 32
            + 32
            + 32
            + 8
            + 32
            + crate::core::crypto::XCHACHA20_POLY1305_NONCE_BYTES
            + MESSAGE_CIPHERTEXT_BYTES,
    );
    out.u64(event.created_at_ms);
    out.id(&event.author_user_id);
    out.id(&signer_endpoint_shared_id);
    out.id(&event.removal_frontier_id);
    out.id(&event.local_history_node_secret_id);
    out.u64(event.expires_at_minute);
    out.id(&event.disappearing_setting_id);
    out.raw(&event.nonce);
    out.raw(&event.ciphertext);
    out.finish()
}

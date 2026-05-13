//! File descriptor projection rows.
//!
//! Sealed rows are keyed by `workspace_id || file_event_id`. Two indexes live
//! in their own tables: `(workspace_id || message_id || file_event_id)` for
//! "files for this message", and `(workspace_id || file_id || file_event_id)`
//! for "the descriptor for this slice's file_id". Both indexes carry the
//! canonical `file_event_id` as the value so workers/queries can dereference
//! the primary row without scanning the full table. The sealed row carries
//! every clear-text field the projector saw plus the AEAD nonce + ciphertext;
//! the read-side CLI opens the slot using the local key-secret named by
//! `local_history_node_secret_id` to reveal filename and mime.

use crate::core::store::{Schema, Store, TableName, TableRow};
use crate::protocol::event_modules::content::message;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::AdmitDecision;
use crate::protocol::wire::{Reader, Writer};

use super::codec;
use super::types::{FileEvent, SealedFileRow, FILE_DESCRIPTOR_CIPHERTEXT_BYTES};
use crate::core::crypto::XCHACHA20_POLY1305_NONCE_BYTES;

/// Receive-side admission gate for signed file descriptors.
///
/// Drops the file event if its parent message is already tombstoned.
/// Mirrors the cascade predicate the content_purge worker uses for files
/// when the parent message is later tombstoned.
pub fn admit_check_received(store: &Store, bytes: &[u8]) -> Result<AdmitDecision, String> {
    let envelope = codec::decode_signed(bytes)?;
    let file = codec::decode(&envelope.payload)?;
    if message::queries::message_tombstone_exists(store, file.workspace_id, file.message_id)? {
        return Ok(AdmitDecision::Drop);
    }
    Ok(AdmitDecision::Admit)
}

pub const FILES: TableName = TableName::new("content.files");
pub const FILES_BY_MESSAGE: TableName = TableName::new("content.files_by_message");
pub const FILES_BY_FILE_ID: TableName = TableName::new("content.files_by_file_id");

pub const SCHEMAS: &[Schema] = &[
    Schema::durable_row_table("content.files.v2", FILES),
    Schema::durable_row_table("content.files_by_message.v2", FILES_BY_MESSAGE),
    Schema::durable_row_table("content.files_by_file_id.v2", FILES_BY_FILE_ID),
];

pub fn file_rows(
    file_event_id: EventId,
    signer_endpoint_shared_id: EventId,
    event: &FileEvent,
) -> Result<Vec<TableRow>, String> {
    Ok(vec![
        sealed_file_row(file_event_id, signer_endpoint_shared_id, event),
        file_by_message_row(file_event_id, event),
        file_by_file_id_row(file_event_id, event),
    ])
}

pub fn sealed_file_row(
    file_event_id: EventId,
    signer_endpoint_shared_id: EventId,
    event: &FileEvent,
) -> TableRow {
    TableRow {
        table: FILES,
        key: file_key(event.workspace_id, file_event_id),
        value: encode_sealed_value(signer_endpoint_shared_id, event),
    }
}

pub fn file_by_message_row(file_event_id: EventId, event: &FileEvent) -> TableRow {
    TableRow {
        table: FILES_BY_MESSAGE,
        key: file_by_message_key(event.workspace_id, event.message_id, file_event_id),
        value: file_event_id.to_vec(),
    }
}

pub fn file_by_file_id_row(file_event_id: EventId, event: &FileEvent) -> TableRow {
    TableRow {
        table: FILES_BY_FILE_ID,
        key: file_by_file_id_key(event.workspace_id, event.file_id, file_event_id),
        value: file_event_id.to_vec(),
    }
}

pub fn file_key(workspace_id: EventId, file_event_id: EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&file_event_id);
    key
}

pub fn file_by_message_key(
    workspace_id: EventId,
    message_id: EventId,
    file_event_id: EventId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(96);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&message_id);
    key.extend_from_slice(&file_event_id);
    key
}

pub fn file_by_file_id_key(
    workspace_id: EventId,
    file_id: EventId,
    file_event_id: EventId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(96);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&file_id);
    key.extend_from_slice(&file_event_id);
    key
}

pub fn file_by_message_prefix(workspace_id: EventId, message_id: EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&message_id);
    key
}

pub fn file_by_file_id_prefix(workspace_id: EventId, file_id: EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&file_id);
    key
}

pub fn decode_sealed_file_row(key: &[u8], value: &[u8]) -> Result<SealedFileRow, String> {
    if key.len() != 64 {
        return Err("file row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut file_event_id = [0; 32];
    file_event_id.copy_from_slice(&key[32..64]);

    let mut reader = Reader::new(value, "file row");
    let created_at_ms = reader.u64()?;
    let message_id = reader.id()?;
    let author_user_id = reader.id()?;
    let signer_endpoint_shared_id = reader.id()?;
    let file_id = reader.id()?;
    let blob_bytes = reader.u64()?;
    let total_slices = reader.u32()?;
    let slice_bytes = reader.u32()?;
    let root_hash = reader.id()?;
    let removal_frontier_id = reader.id()?;
    let local_history_node_secret_id = reader.id()?;
    let nonce = reader
        .bytes(XCHACHA20_POLY1305_NONCE_BYTES)?
        .try_into()
        .map_err(|_| "file row nonce length mismatch".to_string())?;
    let ciphertext = reader
        .bytes(FILE_DESCRIPTOR_CIPHERTEXT_BYTES)?
        .try_into()
        .map_err(|_| "file row ciphertext length mismatch".to_string())?;
    reader.finish()?;
    Ok(SealedFileRow {
        workspace_id,
        file_event_id,
        message_id,
        file_id,
        author_user_id,
        signer_endpoint_shared_id,
        created_at_ms,
        blob_bytes,
        total_slices,
        slice_bytes,
        root_hash,
        removal_frontier_id,
        local_history_node_secret_id,
        nonce,
        ciphertext,
    })
}

fn encode_sealed_value(signer_endpoint_shared_id: EventId, event: &FileEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(
        8 + 32
            + 32
            + 32
            + 32
            + 8
            + 4
            + 4
            + 32
            + 32
            + 32
            + XCHACHA20_POLY1305_NONCE_BYTES
            + FILE_DESCRIPTOR_CIPHERTEXT_BYTES,
    );
    out.u64(event.created_at_ms);
    out.id(&event.message_id);
    out.id(&event.author_user_id);
    out.id(&signer_endpoint_shared_id);
    out.id(&event.file_id);
    out.u64(event.blob_bytes);
    out.u32(event.total_slices as usize);
    out.u32(event.slice_bytes as usize);
    out.id(&event.root_hash);
    out.id(&event.removal_frontier_id);
    out.id(&event.local_history_node_secret_id);
    out.raw(&event.nonce);
    out.raw(&event.ciphertext);
    out.finish()
}

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
//! `local_key_secret_id` to reveal filename and mime.

use std::collections::BTreeMap;

use crate::core::store::{Schema, Store, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::{Reader, Writer};

use super::types::{
    FileEvent, SealedFileRow, FILE_DESCRIPTOR_CIPHERTEXT_BYTES,
};
use crate::core::crypto::XCHACHA20_POLY1305_NONCE_BYTES;

pub const FILES: TableName = TableName::new("content.files");
pub const FILES_BY_MESSAGE: TableName = TableName::new("content.files_by_message");
pub const FILES_BY_FILE_ID: TableName = TableName::new("content.files_by_file_id");

pub const SCHEMAS: &[Schema] = &[
    Schema::durable_row_table("content.files.v1", FILES),
    Schema::durable_row_table("content.files_by_message.v1", FILES_BY_MESSAGE),
    Schema::durable_row_table("content.files_by_file_id.v1", FILES_BY_FILE_ID),
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
    let local_key_secret_id = reader.id()?;
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
        local_key_secret_id,
        nonce,
        ciphertext,
    })
}

pub fn list_sealed_for_workspace(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<SealedFileRow>, String> {
    let mut rows = store
        .table_rows_with_key_prefix(FILES, &workspace_id, usize::MAX)
        .map_err(|err| format!("load files: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_sealed_file_row(&key, &value))
        .collect::<Result<Vec<_>, _>>()?;
    rows.sort_by(|a, b| {
        a.created_at_ms
            .cmp(&b.created_at_ms)
            .then_with(|| a.file_event_id.cmp(&b.file_event_id))
    });
    Ok(rows)
}

pub fn count_for_workspace(store: &Store, workspace_id: EventId) -> Result<usize, String> {
    store
        .table_rows_with_key_prefix(FILES, &workspace_id, usize::MAX)
        .map(|rows| rows.len())
        .map_err(|err| format!("count files: {err}"))
}

/// Group sealed file rows by their parent message id so callers can join
/// files into message listings without scanning the descriptor table per
/// message.
pub fn sealed_files_grouped_by_message(
    store: &Store,
    workspace_id: EventId,
) -> Result<BTreeMap<EventId, Vec<SealedFileRow>>, String> {
    let rows = list_sealed_for_workspace(store, workspace_id)?;
    let mut grouped: BTreeMap<EventId, Vec<SealedFileRow>> = BTreeMap::new();
    for row in rows {
        grouped.entry(row.message_id).or_default().push(row);
    }
    Ok(grouped)
}

pub fn file_event_id_for_file_id(
    store: &Store,
    workspace_id: EventId,
    file_id: EventId,
) -> Result<Option<EventId>, String> {
    let rows = store
        .table_rows_with_key_prefix(
            FILES_BY_FILE_ID,
            &file_by_file_id_prefix(workspace_id, file_id),
            usize::MAX,
        )
        .map_err(|err| format!("load file_by_file_id: {err}"))?;
    let mut chosen: Option<(EventId, EventId)> = None;
    for (key, value) in rows {
        if value.len() != 32 {
            return Err("file_by_file_id row value is malformed".to_string());
        }
        if key.len() != 96 {
            return Err("file_by_file_id row key is malformed".to_string());
        }
        let mut event_id = [0; 32];
        event_id.copy_from_slice(&value);
        match chosen {
            Some((existing, _)) if existing != event_id => {
                return Err("ambiguous file descriptor for file_id".to_string());
            }
            None => {
                let mut key_event_id = [0; 32];
                key_event_id.copy_from_slice(&key[64..96]);
                chosen = Some((event_id, key_event_id));
            }
            _ => {}
        }
    }
    Ok(chosen.map(|(event_id, _)| event_id))
}

pub fn sealed_file_row_by_id(
    store: &Store,
    workspace_id: EventId,
    file_event_id: EventId,
) -> Result<Option<SealedFileRow>, String> {
    let key = file_key(workspace_id, file_event_id);
    let value = store
        .table_row(FILES, &key)
        .map_err(|err| format!("load file: {err}"))?;
    match value {
        Some(value) => Ok(Some(decode_sealed_file_row(&key, &value)?)),
        None => Ok(None),
    }
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
    out.id(&event.local_key_secret_id);
    out.raw(&event.nonce);
    out.raw(&event.ciphertext);
    out.finish()
}

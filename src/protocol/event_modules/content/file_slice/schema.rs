//! File slice projection rows.
//!
//! Slot rows are keyed by `workspace_id || file_id || slice_number(BE)` so a
//! single bounded prefix scan returns slices in order. The value carries the
//! event id, signer, timestamp, the local-key-secret reference needed to
//! decrypt at read time, the plaintext length, and the BAO-verified
//! ciphertext bytes. Queries reassemble a file by scanning the prefix and
//! decrypting each slice with the parent message's content key.

use crate::core::crypto::XCHACHA20_POLY1305_TAG_BYTES;
use crate::core::store::{Schema, Store, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::{Reader, Writer};

use super::types::{FileSliceEvent, FileSliceRow};

pub const FILE_SLICES: TableName = TableName::new("content.file_slices");

pub const SCHEMAS: &[Schema] = &[Schema::durable_row_table(
    "content.file_slices.v2",
    FILE_SLICES,
)];

pub fn file_slice_row(
    slice_event_id: EventId,
    signer_endpoint_shared_id: EventId,
    event: &FileSliceEvent,
    verified_ciphertext: Vec<u8>,
) -> Result<TableRow, String> {
    let expected_len = (event.plaintext_len as usize)
        .checked_add(XCHACHA20_POLY1305_TAG_BYTES)
        .ok_or_else(|| "file slice plaintext_len overflows ciphertext length".to_string())?;
    if verified_ciphertext.len() != expected_len {
        return Err("file slice ciphertext length does not match plaintext_len + tag".to_string());
    }
    Ok(TableRow {
        table: FILE_SLICES,
        key: file_slice_key(event.workspace_id, event.file_id, event.slice_number),
        value: encode_value(
            slice_event_id,
            signer_endpoint_shared_id,
            event.created_at_ms,
            event.local_history_node_secret_id,
            event.plaintext_len,
            &verified_ciphertext,
        ),
    })
}

pub fn file_slice_key(workspace_id: EventId, file_id: EventId, slice_number: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(68);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&file_id);
    key.extend_from_slice(&slice_number.to_be_bytes());
    key
}

pub fn file_slice_prefix(workspace_id: EventId, file_id: EventId) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(64);
    prefix.extend_from_slice(&workspace_id);
    prefix.extend_from_slice(&file_id);
    prefix
}

pub fn decode_file_slice_row(key: &[u8], value: &[u8]) -> Result<FileSliceRow, String> {
    if key.len() != 68 {
        return Err("file slice row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut file_id = [0; 32];
    file_id.copy_from_slice(&key[32..64]);
    let mut slice_number_bytes = [0; 4];
    slice_number_bytes.copy_from_slice(&key[64..68]);
    let slice_number = u32::from_be_bytes(slice_number_bytes);

    let mut reader = Reader::new(value, "file slice row");
    let slice_event_id = reader.id()?;
    let created_at_ms = reader.u64()?;
    let signer_endpoint_shared_id = reader.id()?;
    let local_history_node_secret_id = reader.id()?;
    let plaintext_len = reader.u32()?;
    let ciphertext = reader.sized_bytes()?;
    reader.finish()?;
    Ok(FileSliceRow {
        workspace_id,
        file_id,
        slice_number,
        slice_event_id,
        created_at_ms,
        signer_endpoint_shared_id,
        local_history_node_secret_id,
        plaintext_len,
        ciphertext,
    })
}

pub fn list_for_file(
    store: &Store,
    workspace_id: EventId,
    file_id: EventId,
) -> Result<Vec<FileSliceRow>, String> {
    let rows = store
        .table_rows_with_key_prefix(
            FILE_SLICES,
            &file_slice_prefix(workspace_id, file_id),
            usize::MAX,
        )
        .map_err(|err| format!("load file slices: {err}"))?;
    let mut decoded = rows
        .into_iter()
        .map(|(key, value)| decode_file_slice_row(&key, &value))
        .collect::<Result<Vec<_>, _>>()?;
    decoded.sort_by_key(|row| row.slice_number);
    Ok(decoded)
}

pub fn count_for_workspace(store: &Store, workspace_id: EventId) -> Result<usize, String> {
    store
        .table_rows_with_key_prefix(FILE_SLICES, &workspace_id, usize::MAX)
        .map(|rows| rows.len())
        .map_err(|err| format!("count file slices: {err}"))
}

fn encode_value(
    slice_event_id: EventId,
    signer_endpoint_shared_id: EventId,
    created_at_ms: u64,
    local_history_node_secret_id: EventId,
    plaintext_len: u32,
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut out = Writer::with_capacity(32 + 8 + 32 + 32 + 4 + 4 + ciphertext.len());
    out.id(&slice_event_id);
    out.u64(created_at_ms);
    out.id(&signer_endpoint_shared_id);
    out.id(&local_history_node_secret_id);
    out.u32(plaintext_len as usize);
    out.sized_bytes(ciphertext);
    out.finish()
}

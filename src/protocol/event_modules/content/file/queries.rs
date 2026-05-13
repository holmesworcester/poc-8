//! Read-only views over the file-descriptor projection tables.
//!
//! Sealed rows are keyed by `workspace_id || file_event_id`; the two
//! indexes (`FILES_BY_MESSAGE`, `FILES_BY_FILE_ID`) carry the canonical
//! `file_event_id` as value so workers and queries can dereference the
//! primary row without scanning the full table.

use std::collections::BTreeMap;

use crate::core::store::Store;
use crate::protocol::event_modules::types::EventId;

use super::schema::{
    decode_sealed_file_row, file_by_file_id_prefix, file_key, FILES, FILES_BY_FILE_ID,
};
use super::types::SealedFileRow;

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

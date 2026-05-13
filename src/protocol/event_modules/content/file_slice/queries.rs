//! Read-only views over the file-slice projection table.
//!
//! Scope: bounded prefix scans that reassemble per-file slice rows in
//! `slice_number` order, and a workspace-scoped count for the CLI
//! summary. Mutations to `FILE_SLICES` (writing verified ciphertext,
//! deleting slices for purged files) stay in their owning projector and
//! worker — the queries here only read.

use crate::core::store::Store;
use crate::protocol::event_modules::types::EventId;

use super::schema::{decode_file_slice_row, file_slice_prefix, FILE_SLICES};
use super::types::FileSliceRow;

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

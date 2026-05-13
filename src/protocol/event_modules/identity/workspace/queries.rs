//! Read-only views over the workspace projection table.

use crate::core::store::Store;

use super::schema::{decode_workspace_row, WORKSPACES};
use super::types::WorkspaceRow;

pub fn list_all(store: &Store) -> Result<Vec<WorkspaceRow>, String> {
    store
        .table_rows_with_key_prefix(WORKSPACES, &[], usize::MAX)
        .map_err(|err| format!("load workspaces: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_workspace_row(&key, &value))
        .collect()
}

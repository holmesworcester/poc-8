//! Read-only views over local key-secret rows.
//!
//! Scope: per-workspace prefix scans and exact-key lookups for the
//! encryption worker and CLI summaries. Mutations to `LOCAL_KEY_SECRETS`
//! only happen in the projector when a new secret is admitted; the
//! per-frontier uniqueness invariant is enforced by the schema row
//! shape, not by these queries.

use crate::core::store::Store;
use crate::protocol::event_modules::types::EventId;

use super::schema::{decode_local_key_secret_row, local_key_secret_key, LOCAL_KEY_SECRETS};
use super::types::LocalKeySecretRow;

pub fn get(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
) -> Result<Option<LocalKeySecretRow>, String> {
    let key = local_key_secret_key(workspace_id, removal_frontier_id);
    store
        .table_row(LOCAL_KEY_SECRETS, &key)
        .map_err(|err| format!("load local key secret: {err}"))?
        .map(|value| decode_local_key_secret_row(&key, &value))
        .transpose()
}

pub fn list_for_workspace(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<LocalKeySecretRow>, String> {
    store
        .table_rows_with_key_prefix(LOCAL_KEY_SECRETS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load local key secrets: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_local_key_secret_row(&key, &value))
        .collect()
}

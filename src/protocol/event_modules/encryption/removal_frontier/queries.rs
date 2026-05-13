//! Read-only views over removal-frontier rows.
//!
//! Scope: per-workspace prefix scans and exact-key lookups for the
//! encryption worker, sync worker, and CLI status views. Rotation
//! policy and admin authority validation stay in projector and worker;
//! mutations to `REMOVAL_FRONTIERS` only happen during projection.

use crate::core::store::Store;
use crate::protocol::event_modules::types::EventId;

use super::schema::{decode_removal_frontier_row, removal_frontier_key, REMOVAL_FRONTIERS};
use super::types::RemovalFrontierRow;

pub fn get(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
) -> Result<Option<RemovalFrontierRow>, String> {
    let key = removal_frontier_key(workspace_id, removal_frontier_id);
    store
        .table_row(REMOVAL_FRONTIERS, &key)
        .map_err(|err| format!("load removal frontier: {err}"))?
        .map(|value| decode_removal_frontier_row(&key, &value))
        .transpose()
}

pub fn list_for_workspace(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<RemovalFrontierRow>, String> {
    store
        .table_rows_with_key_prefix(REMOVAL_FRONTIERS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load removal frontiers: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_removal_frontier_row(&key, &value))
        .collect()
}

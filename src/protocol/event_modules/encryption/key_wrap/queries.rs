//! Read-only views over the key-wrap projection tables.
//!
//! The encryption worker drains `PENDING_KEY_UNWRAPS` to materialize new
//! local key-secret events. Queries here surface the same rows as
//! decoded structs so the worker can match wraps against pending unwrap
//! rows without re-encoding keys. Schema retains the row constructors
//! and the per-row decoders these queries delegate to; mutations stay
//! in projectors and the encryption worker.

use crate::core::store::Store;
use crate::protocol::event_modules::types::EventId;

use super::schema::{
    decode_key_wrap_row, decode_pending_key_unwrap_row, KEY_WRAPS, PENDING_KEY_UNWRAPS,
};
use super::types::{KeyWrapRow, PendingKeyUnwrapRow};

pub fn list_all(store: &Store) -> Result<Vec<KeyWrapRow>, String> {
    store
        .table_rows_with_key_prefix(KEY_WRAPS, &[], usize::MAX)
        .map_err(|err| format!("load key wraps: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_key_wrap_row(&key, &value))
        .collect()
}

pub fn list_for_workspace(store: &Store, workspace_id: EventId) -> Result<Vec<KeyWrapRow>, String> {
    store
        .table_rows_with_key_prefix(KEY_WRAPS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load key wraps: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_key_wrap_row(&key, &value))
        .collect()
}

pub fn list_pending_unwraps(
    store: &Store,
    limit: usize,
) -> Result<Vec<PendingKeyUnwrapRow>, String> {
    store
        .table_rows_with_key_prefix(PENDING_KEY_UNWRAPS, &[], limit)
        .map_err(|err| format!("load pending key unwraps: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_pending_key_unwrap_row(key, &value))
        .collect()
}

pub fn key_wrap_for_pending(
    store: &Store,
    pending: &PendingKeyUnwrapRow,
) -> Result<Option<KeyWrapRow>, String> {
    store
        .table_row(KEY_WRAPS, &pending.key)
        .map_err(|err| format!("load pending key wrap: {err}"))?
        .map(|value| decode_key_wrap_row(&pending.key, &value))
        .transpose()
}

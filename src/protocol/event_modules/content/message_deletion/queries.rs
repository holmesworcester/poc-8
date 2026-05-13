//! Read-only views over the deletion-purge queue.
//!
//! Scope: the cheap presence-check the post-admission hook uses to
//! decide whether to drain the content-purge worker before returning.
//! The drain itself (consuming the queue) belongs to the worker, which
//! holds the transaction context for the cascade.

use crate::core::store::Store;

use super::schema::CONTENT_PURGE_PENDING;

pub fn has_purge_pending(store: &Store) -> Result<bool, String> {
    let any = store
        .table_rows_with_key_prefix(CONTENT_PURGE_PENDING, &[], 1)
        .map_err(|err| format!("load purge pending: {err}"))?;
    Ok(!any.is_empty())
}

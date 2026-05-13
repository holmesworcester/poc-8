//! Read-only views over shared recipient-key rows.
//!
//! Scope: per-workspace prefix scans the encryption worker uses to
//! enumerate wrap obligations. Public recipient keys are shared facts;
//! mutations to `RECIPIENT_KEYS` only happen in the projector.

use crate::core::store::Store;
use crate::protocol::event_modules::types::EventId;

use super::schema::{decode_recipient_key_row, RECIPIENT_KEYS};
use super::types::RecipientKeyRow;

pub fn list_for_workspace(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<RecipientKeyRow>, String> {
    store
        .table_rows_with_key_prefix(RECIPIENT_KEYS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load recipient keys: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_recipient_key_row(&key, &value))
        .collect()
}

//! Read-only views over local recipient-key rows.
//!
//! Scope: per-workspace prefix scans surfacing the keys the local
//! encryption worker can decrypt for. The private bytes never leave
//! this module; mutations to `LOCAL_RECIPIENT_KEYS` only happen in the
//! projector when an admitted shared `recipient_key` event matches a
//! locally-known wrap-key id.

use crate::core::store::Store;
use crate::protocol::event_modules::types::EventId;

use super::schema::{decode_local_recipient_key_row, LOCAL_RECIPIENT_KEYS};
use super::types::LocalRecipientKeyRow;

pub fn list_for_workspace(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<LocalRecipientKeyRow>, String> {
    store
        .table_rows_with_key_prefix(LOCAL_RECIPIENT_KEYS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load local recipient keys: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_local_recipient_key_row(&key, &value))
        .collect()
}

//! Read-only views over recipient-key tombstone rows.
//!
//! Scope: per-workspace prefix scans and exact-key lookups for the
//! encryption worker. Tombstones are a shared retirement fact;
//! mutations to `RECIPIENT_KEY_TOMBSTONES` only happen in the projector.

use crate::core::store::Store;
use crate::protocol::event_modules::types::EventId;

use super::schema::{
    decode_recipient_key_tombstone_row, recipient_key_tombstone_key, RECIPIENT_KEY_TOMBSTONES,
};
use super::types::RecipientKeyTombstoneRow;

pub fn get(
    store: &Store,
    workspace_id: EventId,
    old_recipient_key_id: EventId,
) -> Result<Option<RecipientKeyTombstoneRow>, String> {
    let key = recipient_key_tombstone_key(workspace_id, old_recipient_key_id);
    store
        .table_row(RECIPIENT_KEY_TOMBSTONES, &key)
        .map_err(|err| format!("load recipient key tombstone: {err}"))?
        .map(|value| decode_recipient_key_tombstone_row(&key, &value))
        .transpose()
}

pub fn list_for_workspace(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<RecipientKeyTombstoneRow>, String> {
    store
        .table_rows_with_key_prefix(RECIPIENT_KEY_TOMBSTONES, &workspace_id, usize::MAX)
        .map_err(|err| format!("load recipient key tombstones: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_recipient_key_tombstone_row(&key, &value))
        .collect()
}

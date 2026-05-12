//! Read-only views over the message tables.
//!
//! Three projection tables share the message key shape (`workspace_id ||
//! message_id`): `MESSAGES` (opened read-model rows), `SEALED_MESSAGES`
//! (the encrypted projection written by `project()`), and
//! `MESSAGE_TOMBSTONES` (deletion markers, either author-driven or
//! TTL-driven). Queries here compose bounded prefix scans into the
//! lookups the worker, projector, CLI, and receive-side admit gate
//! need.

use crate::core::store::Store;
use crate::protocol::event_modules::types::EventId;

use super::schema::{
    decode_message_row, decode_message_tombstone_row, decode_sealed_message_row, message_key,
    MessageTombstoneRow, SealedMessageRow, MESSAGES, MESSAGE_TOMBSTONES, SEALED_MESSAGES,
};
use super::types::MessageRow;

pub fn list_sealed(store: &Store, limit: usize) -> Result<Vec<SealedMessageRow>, String> {
    store
        .table_rows_with_key_prefix(SEALED_MESSAGES, &[], limit)
        .map_err(|err| format!("load sealed messages: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_sealed_message_row(&key, &value))
        .collect()
}

/// Count sealed message rows scoped to one workspace. Sealed rows are
/// the receive-side projection; opening one to a `MessageRow` requires
/// the matching local key material. The CLI's `messages` listing folds
/// sealed + opened rows together, so callers building a "live message"
/// status display should sum this count with `count_for_workspace` to
/// get the same total.
pub fn count_sealed_for_workspace(
    store: &Store,
    workspace_id: EventId,
) -> Result<usize, String> {
    store
        .table_rows_with_key_prefix(SEALED_MESSAGES, &workspace_id, usize::MAX)
        .map(|rows| rows.len())
        .map_err(|err| format!("count sealed messages: {err}"))
}

/// Iterate sealed-message rows within one workspace. Surfaces the
/// per-row `created_at_ms` so a status view can count rows whose
/// authored minute falls below a deletion floor.
pub fn list_sealed_for_workspace(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<SealedMessageRow>, String> {
    store
        .table_rows_with_key_prefix(SEALED_MESSAGES, &workspace_id, usize::MAX)
        .map_err(|err| format!("load sealed messages: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_sealed_message_row(&key, &value))
        .collect()
}

pub fn message_tombstone_exists(
    store: &Store,
    workspace_id: EventId,
    message_id: EventId,
) -> Result<bool, String> {
    let key = message_key(workspace_id, message_id);
    store
        .table_row(MESSAGE_TOMBSTONES, &key)
        .map(|row| row.is_some())
        .map_err(|err| format!("load message tombstone: {err}"))
}

pub fn list_message_tombstones_for_workspace(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<MessageTombstoneRow>, String> {
    store
        .table_rows_with_key_prefix(MESSAGE_TOMBSTONES, &workspace_id, usize::MAX)
        .map_err(|err| format!("load message tombstones: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_message_tombstone_row(&key, &value))
        .collect()
}

pub fn list_for_workspace(store: &Store, workspace_id: EventId) -> Result<Vec<MessageRow>, String> {
    let mut rows = store
        .table_rows_with_key_prefix(MESSAGES, &workspace_id, usize::MAX)
        .map_err(|err| format!("load messages: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_message_row(&key, &value))
        .collect::<Result<Vec<_>, _>>()?;
    rows.sort_by(|a, b| {
        a.created_at_ms
            .cmp(&b.created_at_ms)
            .then_with(|| a.message_id.cmp(&b.message_id))
    });
    Ok(rows)
}

pub fn count_for_workspace(store: &Store, workspace_id: EventId) -> Result<usize, String> {
    store
        .table_rows_with_key_prefix(MESSAGES, &workspace_id, usize::MAX)
        .map(|rows| rows.len())
        .map_err(|err| format!("count messages: {err}"))
}

pub fn message_by_id(
    store: &Store,
    workspace_id: EventId,
    message_id: EventId,
) -> Result<Option<MessageRow>, String> {
    let key = message_key(workspace_id, message_id);
    store
        .table_row(MESSAGES, &key)
        .map_err(|err| format!("load message: {err}"))?
        .map(|value| decode_message_row(&key, &value))
        .transpose()
}


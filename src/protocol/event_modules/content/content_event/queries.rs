//! Read-only views over the content-event projection table.
//!
//! Scope: per-workspace summaries (count, payload bytes, max timestamp)
//! used by the message CLI for stamping authoring timestamps. Mutations
//! to `CONTENT_EVENTS` happen in the projector only.

use crate::core::store::Store;
use crate::protocol::event_modules::types::EventId;

use super::schema::{decode_content_event_row, CONTENT_EVENTS};

pub fn count_for_workspace(store: &Store, workspace_id: EventId) -> Result<usize, String> {
    store
        .table_rows_with_key_prefix(CONTENT_EVENTS, &workspace_id, usize::MAX)
        .map(|rows| rows.len())
        .map_err(|err| format!("count content events: {err}"))
}

pub fn payload_bytes_for_workspace(store: &Store, workspace_id: EventId) -> Result<usize, String> {
    store
        .table_rows_with_key_prefix(CONTENT_EVENTS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load content events: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_content_event_row(&key, &value).map(|row| row.payload_bytes))
        .sum()
}

pub fn max_timestamp_for_workspace(store: &Store, workspace_id: EventId) -> Result<u64, String> {
    store
        .table_rows_with_key_prefix(CONTENT_EVENTS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load content events: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_content_event_row(&key, &value).map(|row| row.timestamp))
        .try_fold(0, |max, timestamp| {
            timestamp.map(|timestamp| max.max(timestamp))
        })
}

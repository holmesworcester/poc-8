//! Read-only views over the common event-pipeline tables.
//!
//! Scope: status counts and bounded scans used by the CLI for `status`
//! summaries and by workers (sync, content purge, transit, connection)
//! for ordinary read paths. Mutations to `EVENTS`, `READY_EVENTS`, and
//! the dependency tables stay in `workers::pipeline_helpers::event_lifecycle`
//! and the event-admission worker.

use crate::core::store::Store;
use crate::protocol::event_modules::types::{
    EventId, EventIndexEntry, EventStatus, EventStatusCounts,
};

use super::schema::{
    self, decode_stored_event_index, read_event, BLOCKED_EVENTS_BY_MISSING_DEP, EVENTS,
    EVENT_LABELS,
};

const MAX_LABELS_PER_EVENT: usize = 4096;

pub fn max_timestamp(store: &Store) -> rusqlite::Result<u64> {
    let mut max = 0u64;
    for (_, value) in store.table_rows(EVENTS)? {
        let event = decode_stored_event_index(&value)?;
        if event.scope.is_shared() && event.timestamp > max {
            max = event.timestamp;
        }
    }
    Ok(max)
}

pub fn event_count(store: &Store) -> rusqlite::Result<usize> {
    let mut count = 0;
    for (_, value) in store.table_rows(EVENTS)? {
        let event = decode_stored_event_index(&value)?;
        if event.scope.is_shared() {
            count += 1;
        }
    }
    Ok(count)
}

pub fn status_counts(store: &Store) -> rusqlite::Result<EventStatusCounts> {
    let mut counts = EventStatusCounts::default();
    for (_, value) in store.table_rows(EVENTS)? {
        let event = decode_stored_event_index(&value)?;
        if !event.scope.is_shared() {
            continue;
        }
        match event.status {
            EventStatus::Ready => counts.ready += 1,
            EventStatus::Blocked => counts.blocked += 1,
            EventStatus::Applied => counts.applied += 1,
            EventStatus::Rejected => counts.rejected += 1,
        }
    }
    counts.blocked_edges = store.table_row_count(BLOCKED_EVENTS_BY_MISSING_DEP)?;
    Ok(counts)
}

pub fn body_bytes(store: &Store) -> rusqlite::Result<usize> {
    schema::shared_body_bytes(store)
}

pub fn event_index_entries_in_timestamp_range(
    store: &Store,
    start_timestamp: u64,
    end_timestamp: u64,
) -> rusqlite::Result<Vec<EventIndexEntry>> {
    schema::event_index_entries_in_timestamp_range(store, start_timestamp, end_timestamp)
}

pub fn has_shared_event_in_workspaces(
    store: &Store,
    event_id: &EventId,
    workspace_ids: &[EventId],
) -> rusqlite::Result<bool> {
    let Some(event) = read_event(store, event_id)? else {
        return Ok(false);
    };
    Ok(event.scope.is_shared()
        && event.workspace_id.is_some_and(|workspace_id| {
            workspace_ids.iter().any(|allowed| allowed == &workspace_id)
        }))
}

pub fn has_event(store: &Store, event_id: &EventId) -> rusqlite::Result<bool> {
    store.table_row(EVENTS, event_id).map(|row| row.is_some())
}

pub fn has_shared_event(store: &Store, event_id: &EventId) -> rusqlite::Result<bool> {
    read_event(store, event_id)
        .map(|event| event.map(|event| event.scope.is_shared()).unwrap_or(false))
}

pub fn event_bytes(store: &Store, event_id: &EventId) -> rusqlite::Result<Option<Vec<u8>>> {
    read_event(store, event_id).map(|event| event.map(|event| event.canonical_bytes))
}

pub fn event_labels(store: &Store, event_id: &EventId) -> Result<Vec<Vec<u8>>, String> {
    store
        .table_rows_with_key_prefix(EVENT_LABELS, event_id, MAX_LABELS_PER_EVENT)
        .map_err(|err| format!("load event labels: {err}"))
        .map(|rows| rows.into_iter().map(|(_, label)| label).collect())
}

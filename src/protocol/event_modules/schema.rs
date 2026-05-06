//! Protocol-wide schema and row helpers for the common event pipeline.
//!
//! Core storage deliberately does not know about Topo events. This file is the
//! protocol side of that boundary: it names row tables, encodes protocol
//! facts into `TableRow`s, and offers narrow query helpers for workers and CLI
//! commands. Keep new protocol meaning here or in a scoped event-module
//! `schema.rs`; do not push it down into `core::store`.
//!
//! The common worker relies on small generic indexes. `EVENTS` stores canonical
//! durable bytes and a compact header. `READY_EVENTS` and the two missing-dep
//! edge tables make admission incremental: inserting a newly applied dependency
//! only has to inspect events known to be waiting on that dependency.
//! `TIMESTAMP_EVENTS` gives sync a timestamp-ordered feed of shared event ids
//! without teaching core what an event is. Operational worker queues live under
//! `src/workers/schema.rs`. Labels are generic, bounded context for projectors;
//! richer read models belong in scoped module schema files.

use crate::core::store::{Schema, Store, TableName, TableRow};
use crate::protocol::event_modules::types::{
    event_id, EventId, EventIndexEntry, EventRecord, EventScope, EventStatus, EventStatusCounts,
};

pub const EVENTS: TableName = TableName::new("event_modules.events");
pub const READY_EVENTS: TableName = TableName::new("event_modules.ready_events");
pub const TIMESTAMP_EVENTS: TableName = TableName::new("event_modules.timestamp_events");
pub const BLOCKED_EVENTS_BY_MISSING_DEP: TableName =
    TableName::new("event_modules.blocked_events_by_missing_dep");
pub const MISSING_DEPS_BY_BLOCKED_EVENT: TableName =
    TableName::new("event_modules.missing_deps_by_blocked_event");
pub const EVENT_LABELS: TableName = TableName::new("event_modules.labels");

pub const SCHEMAS: &[Schema] = &[
    Schema::durable_row_table("event_modules.events.v1", EVENTS),
    Schema::durable_row_table("event_modules.ready_events.v1", READY_EVENTS),
    Schema::durable_row_table("event_modules.timestamp_events.v1", TIMESTAMP_EVENTS),
    Schema::durable_row_table(
        "event_modules.blocked_events_by_missing_dep.v1",
        BLOCKED_EVENTS_BY_MISSING_DEP,
    ),
    Schema::durable_row_table(
        "event_modules.missing_deps_by_blocked_event.v1",
        MISSING_DEPS_BY_BLOCKED_EVENT,
    ),
    Schema::durable_row_table("event_modules.labels.v1", EVENT_LABELS),
];

const EVENT_ROW_HEADER_BYTES: usize = 8 + 8 + 1 + 1 + 1 + 1 + 32;
const MAX_LABELS_PER_EVENT: usize = 4096;
const MAX_DEPENDENCY_ROWS_PER_EVENT: usize = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventLabel {
    pub event_id: EventId,
    pub label: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredEvent {
    timestamp: u64,
    body_len: usize,
    partition: u8,
    scope: EventScope,
    status: EventStatus,
    workspace_id: Option<EventId>,
    canonical_bytes: Vec<u8>,
}

pub fn insert_event(
    store: &Store,
    event: &EventRecord,
    status: EventStatus,
) -> rusqlite::Result<bool> {
    // The event id is the row key, so admission is naturally idempotent. The
    // header is enough for scans and counts; callers load full bytes only when
    // they need to decode or send the event.
    let id = event_id(&event.canonical_bytes);
    if store.table_row(EVENTS, &id)?.is_some() {
        return Ok(false);
    }

    let mut rows = vec![event_row(&id, event, status)?];
    if status == EventStatus::Ready {
        rows.push(ready_row(event.timestamp, &id));
    }
    if event.scope.is_shared() {
        rows.push(timestamp_row(event.timestamp, event.workspace_id, &id));
    }
    store.insert_table_rows_in_tx(rows)?;
    Ok(true)
}

pub fn event_is_applied(store: &Store, event_id: &EventId) -> rusqlite::Result<bool> {
    read_event(store, event_id).map(|event| {
        event
            .map(|event| event.status == EventStatus::Applied)
            .unwrap_or(false)
    })
}

pub fn insert_blocked_event_missing_dep(
    store: &Store,
    missing_dep_id: &EventId,
    blocked_event_id: &EventId,
) -> rusqlite::Result<bool> {
    // Maintain both directions of the wait graph. The forward table answers
    // "what can this newly-applied dependency unblock?" and the reverse table
    // answers "does this event still have any missing dependency?"
    let primary = edge_row(
        BLOCKED_EVENTS_BY_MISSING_DEP,
        missing_dep_id,
        blocked_event_id,
    );
    let inserted = store.insert_table_rows_in_tx(vec![primary])? > 0;
    store.insert_table_rows_in_tx(vec![edge_row(
        MISSING_DEPS_BY_BLOCKED_EVENT,
        blocked_event_id,
        missing_dep_id,
    )])?;
    Ok(inserted)
}

pub fn next_ready_event(store: &Store) -> rusqlite::Result<Option<EventId>> {
    let mut rows = store.table_rows_with_key_prefix(READY_EVENTS, &[], 1)?;
    let Some((_, value)) = rows.pop() else {
        return Ok(None);
    };
    vec_to_id(value).map(Some)
}

pub fn set_event_status(
    store: &Store,
    event_id: &EventId,
    from: EventStatus,
    to: EventStatus,
) -> rusqlite::Result<bool> {
    let Some(mut event) = read_event(store, event_id)? else {
        return Ok(false);
    };
    if event.status != from {
        return Ok(false);
    }

    let old_ready_key = (from == EventStatus::Ready).then(|| ready_key(event.timestamp, event_id));
    event.status = to;
    let mut rows = vec![stored_event_row(event_id, &event)?];
    if to == EventStatus::Ready {
        rows.push(ready_row(event.timestamp, event_id));
    }

    store.replace_table_rows_in_tx(rows)?;
    if let Some(key) = old_ready_key {
        store.delete_table_rows_in_tx(READY_EVENTS, vec![key])?;
    }
    Ok(true)
}

pub fn delete_blocked_events_by_missing_dep(
    store: &Store,
    missing_dep_id: &EventId,
) -> rusqlite::Result<usize> {
    // Removing a dependency edge must remove the reverse edge in the same
    // transaction. Otherwise an event could look permanently blocked even after
    // all of its dependencies were applied.
    let rows = store.table_rows_with_key_prefix(
        BLOCKED_EVENTS_BY_MISSING_DEP,
        missing_dep_id,
        MAX_DEPENDENCY_ROWS_PER_EVENT,
    )?;
    let mut blocked_keys = Vec::with_capacity(rows.len());
    let mut reverse_keys = Vec::with_capacity(rows.len());
    for (key, _) in rows {
        let (missing_dep, blocked_event_id) = split_edge_key(&key)?;
        blocked_keys.push(key);
        reverse_keys.push(edge_key(&blocked_event_id, &missing_dep));
    }
    let deleted = store.delete_table_rows_in_tx(BLOCKED_EVENTS_BY_MISSING_DEP, blocked_keys)?;
    store.delete_table_rows_in_tx(MISSING_DEPS_BY_BLOCKED_EVENT, reverse_keys)?;
    Ok(deleted)
}

pub fn blocked_events_by_missing_dep(
    store: &Store,
    missing_dep_id: &EventId,
) -> rusqlite::Result<Vec<EventId>> {
    store
        .table_rows_with_key_prefix(
            BLOCKED_EVENTS_BY_MISSING_DEP,
            missing_dep_id,
            MAX_DEPENDENCY_ROWS_PER_EVENT,
        )?
        .into_iter()
        .map(|(key, _)| split_edge_key(&key).map(|(_, blocked_event_id)| blocked_event_id))
        .collect()
}

pub fn blocked_event_has_missing_deps(
    store: &Store,
    blocked_event_id: &EventId,
) -> rusqlite::Result<bool> {
    store
        .table_rows_with_key_prefix(MISSING_DEPS_BY_BLOCKED_EVENT, blocked_event_id, 1)
        .map(|rows| !rows.is_empty())
}

pub fn max_timestamp(store: &Store) -> rusqlite::Result<u64> {
    Ok(shared_events(store)?
        .into_iter()
        .map(|(_, event)| event.timestamp)
        .max()
        .unwrap_or(0))
}

pub fn event_count(store: &Store) -> rusqlite::Result<usize> {
    shared_events(store).map(|events| events.len())
}

pub fn status_counts(store: &Store) -> rusqlite::Result<EventStatusCounts> {
    let mut counts = EventStatusCounts::default();
    for (_, event) in shared_events(store)? {
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
    Ok(shared_events(store)?
        .into_iter()
        .map(|(_, event)| event.body_len)
        .sum())
}

pub fn event_index_entries_in_timestamp_range(
    store: &Store,
    start_timestamp: u64,
    end_timestamp: u64,
) -> rusqlite::Result<Vec<EventIndexEntry>> {
    let lower = timestamp_range_lower_key(start_timestamp);
    let upper = timestamp_range_upper_key(end_timestamp);
    store
        .table_rows_in_key_range(
            TIMESTAMP_EVENTS,
            &lower,
            upper.as_deref(),
            MAX_DEPENDENCY_ROWS_PER_EVENT,
        )?
        .into_iter()
        .map(|(key, value)| {
            let (timestamp, event_id) = split_timestamp_key(&key)?;
            let workspace_id = decode_workspace_index_value(&value)?;
            Ok(EventIndexEntry {
                event_id,
                timestamp,
                workspace_id,
            })
        })
        .collect()
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

pub fn purge_event(store: &Store, event_id: &EventId) -> rusqlite::Result<bool> {
    let Some(event) = read_event(store, event_id)? else {
        return Ok(false);
    };

    let mut deleted_any = false;
    if event.status == EventStatus::Ready {
        deleted_any |= store
            .delete_table_rows_in_tx(READY_EVENTS, vec![ready_key(event.timestamp, event_id)])?
            > 0;
    }
    if event.scope.is_shared() {
        deleted_any |= store.delete_table_rows_in_tx(
            TIMESTAMP_EVENTS,
            vec![timestamp_key(event.timestamp, event_id)],
        )? > 0;
    }

    let missing_edges = store.table_rows_with_key_prefix(
        MISSING_DEPS_BY_BLOCKED_EVENT,
        event_id,
        MAX_DEPENDENCY_ROWS_PER_EVENT,
    )?;
    let mut reverse_keys = Vec::with_capacity(missing_edges.len());
    let mut forward_keys = Vec::with_capacity(missing_edges.len());
    for (key, _) in missing_edges {
        let (blocked_event_id, missing_dep_id) = split_edge_key(&key)?;
        reverse_keys.push(key);
        forward_keys.push(edge_key(&missing_dep_id, &blocked_event_id));
    }
    deleted_any |= store.delete_table_rows_in_tx(MISSING_DEPS_BY_BLOCKED_EVENT, reverse_keys)? > 0;
    deleted_any |= store.delete_table_rows_in_tx(BLOCKED_EVENTS_BY_MISSING_DEP, forward_keys)? > 0;
    deleted_any |= store.delete_table_rows_in_tx(EVENTS, vec![event_id.to_vec()])? > 0;
    Ok(deleted_any)
}

pub fn event_label_rows(labels: Vec<EventLabel>) -> Vec<TableRow> {
    labels
        .into_iter()
        .map(|label| TableRow {
            table: EVENT_LABELS,
            key: event_label_key(&label.event_id, &label.label),
            value: label.label,
        })
        .collect()
}

pub fn event_labels(store: &Store, event_id: &EventId) -> Result<Vec<Vec<u8>>, String> {
    store
        .table_rows_with_key_prefix(EVENT_LABELS, event_id, MAX_LABELS_PER_EVENT)
        .map_err(|err| format!("load event labels: {err}"))
        .map(|rows| rows.into_iter().map(|(_, label)| label).collect())
}

fn shared_events(store: &Store) -> rusqlite::Result<Vec<(EventId, StoredEvent)>> {
    store
        .table_rows(EVENTS)?
        .into_iter()
        .filter_map(|(key, value)| match decode_event_row_value(&value) {
            Ok(event) if event.scope.is_shared() => Some(vec_to_id(key).map(|id| (id, event))),
            Ok(_) => None,
            Err(err) => Some(Err(err)),
        })
        .collect()
}

fn read_event(store: &Store, event_id: &EventId) -> rusqlite::Result<Option<StoredEvent>> {
    store
        .table_row(EVENTS, event_id)?
        .map(|value| decode_event_row_value(&value))
        .transpose()
}

fn event_row(
    event_id: &EventId,
    event: &EventRecord,
    status: EventStatus,
) -> rusqlite::Result<TableRow> {
    Ok(TableRow {
        table: EVENTS,
        key: event_id.to_vec(),
        value: encode_event_row_value(
            event.timestamp,
            event.body_len,
            event_id[0],
            event.scope,
            status,
            event.workspace_id,
            &event.canonical_bytes,
        )?,
    })
}

fn stored_event_row(event_id: &EventId, event: &StoredEvent) -> rusqlite::Result<TableRow> {
    Ok(TableRow {
        table: EVENTS,
        key: event_id.to_vec(),
        value: encode_event_row_value(
            event.timestamp,
            event.body_len,
            event.partition,
            event.scope,
            event.status,
            event.workspace_id,
            &event.canonical_bytes,
        )?,
    })
}

fn ready_row(timestamp: u64, event_id: &EventId) -> TableRow {
    TableRow {
        table: READY_EVENTS,
        key: ready_key(timestamp, event_id),
        value: event_id.to_vec(),
    }
}

fn timestamp_row(timestamp: u64, workspace_id: Option<EventId>, event_id: &EventId) -> TableRow {
    TableRow {
        table: TIMESTAMP_EVENTS,
        key: timestamp_key(timestamp, event_id),
        value: encode_workspace_index_value(workspace_id),
    }
}

fn edge_row(table: TableName, first: &EventId, second: &EventId) -> TableRow {
    TableRow {
        table,
        key: edge_key(first, second),
        value: Vec::new(),
    }
}

fn encode_event_row_value(
    timestamp: u64,
    body_len: usize,
    partition: u8,
    scope: EventScope,
    status: EventStatus,
    workspace_id: Option<EventId>,
    canonical_bytes: &[u8],
) -> rusqlite::Result<Vec<u8>> {
    // Keep the header fixed width so count/status scans can avoid parsing the
    // event body. The canonical bytes follow unchanged.
    let mut out = Vec::with_capacity(EVENT_ROW_HEADER_BYTES + canonical_bytes.len());
    out.extend_from_slice(&timestamp.to_be_bytes());
    out.extend_from_slice(&(body_len as u64).to_be_bytes());
    out.push(partition);
    out.push(scope.durable_tag().map_err(table_error)?);
    out.push(status.as_u8());
    match workspace_id {
        Some(workspace_id) => {
            out.push(1);
            out.extend_from_slice(&workspace_id);
        }
        None => {
            out.push(0);
            out.extend_from_slice(&[0; 32]);
        }
    }
    out.extend_from_slice(canonical_bytes);
    Ok(out)
}

fn decode_event_row_value(value: &[u8]) -> rusqlite::Result<StoredEvent> {
    if value.len() < EVENT_ROW_HEADER_BYTES {
        return Err(table_error(format!(
            "event row is truncated: {} bytes",
            value.len()
        )));
    }
    let mut offset = 0;
    let timestamp = read_u64(value, &mut offset)?;
    let body_len = read_u64(value, &mut offset)? as usize;
    let partition = read_u8(value, &mut offset)?;
    let scope = EventScope::from_durable_tag(read_u8(value, &mut offset)?).map_err(table_error)?;
    let status = EventStatus::from_u8(read_u8(value, &mut offset)?).map_err(table_error)?;
    let workspace_id = read_optional_id(value, &mut offset)?;
    let canonical_bytes = value[offset..].to_vec();
    Ok(StoredEvent {
        timestamp,
        body_len,
        partition,
        scope,
        status,
        workspace_id,
        canonical_bytes,
    })
}

fn read_u64(bytes: &[u8], offset: &mut usize) -> rusqlite::Result<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| table_error("event row offset overflow".to_string()))?;
    let value = bytes
        .get(*offset..end)
        .ok_or_else(|| table_error("event row is truncated".to_string()))?
        .try_into()
        .expect("slice length checked");
    *offset = end;
    Ok(u64::from_be_bytes(value))
}

fn read_u8(bytes: &[u8], offset: &mut usize) -> rusqlite::Result<u8> {
    let value = *bytes
        .get(*offset)
        .ok_or_else(|| table_error("event row is truncated".to_string()))?;
    *offset += 1;
    Ok(value)
}

fn read_optional_id(bytes: &[u8], offset: &mut usize) -> rusqlite::Result<Option<EventId>> {
    let has_id = read_u8(bytes, offset)?;
    let id = read_id(bytes, offset)?;
    match has_id {
        0 => Ok(None),
        1 => Ok(Some(id)),
        other => Err(table_error(format!("unknown workspace flag {other}"))),
    }
}

fn read_id(bytes: &[u8], offset: &mut usize) -> rusqlite::Result<EventId> {
    let end = offset
        .checked_add(32)
        .ok_or_else(|| table_error("event row offset overflow".to_string()))?;
    let value = bytes
        .get(*offset..end)
        .ok_or_else(|| table_error("event row is truncated".to_string()))?;
    let mut out = [0; 32];
    out.copy_from_slice(value);
    *offset = end;
    Ok(out)
}

fn ready_key(timestamp: u64, event_id: &EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(8 + event_id.len());
    key.extend_from_slice(&timestamp.to_be_bytes());
    key.extend_from_slice(event_id);
    key
}

fn timestamp_key(timestamp: u64, event_id: &EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(8 + event_id.len());
    key.extend_from_slice(&timestamp.to_be_bytes());
    key.extend_from_slice(event_id);
    key
}

fn timestamp_range_lower_key(timestamp: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(40);
    key.extend_from_slice(&timestamp.to_be_bytes());
    key.extend_from_slice(&[0; 32]);
    key
}

fn timestamp_range_upper_key(timestamp: u64) -> Option<Vec<u8>> {
    timestamp.checked_add(1).map(timestamp_range_lower_key)
}

fn split_timestamp_key(key: &[u8]) -> rusqlite::Result<(u64, EventId)> {
    if key.len() != 40 {
        return Err(table_error(format!(
            "timestamp key should be 40 bytes, got {}",
            key.len()
        )));
    }
    let timestamp = u64::from_be_bytes(key[..8].try_into().expect("slice length checked"));
    Ok((timestamp, vec_to_id(key[8..].to_vec())?))
}

fn encode_workspace_index_value(workspace_id: Option<EventId>) -> Vec<u8> {
    let mut out = Vec::with_capacity(33);
    match workspace_id {
        Some(workspace_id) => {
            out.push(1);
            out.extend_from_slice(&workspace_id);
        }
        None => {
            out.push(0);
            out.extend_from_slice(&[0; 32]);
        }
    }
    out
}

fn decode_workspace_index_value(value: &[u8]) -> rusqlite::Result<Option<EventId>> {
    if value.len() != 33 {
        return Err(table_error(format!(
            "workspace index value should be 33 bytes, got {}",
            value.len()
        )));
    }
    let mut offset = 0;
    read_optional_id(value, &mut offset)
}

fn edge_key(first: &EventId, second: &EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(first);
    key.extend_from_slice(second);
    key
}

fn split_edge_key(key: &[u8]) -> rusqlite::Result<(EventId, EventId)> {
    if key.len() != 64 {
        return Err(table_error(format!(
            "dependency key should be 64 bytes, got {}",
            key.len()
        )));
    }
    Ok((
        vec_to_id(key[..32].to_vec())?,
        vec_to_id(key[32..].to_vec())?,
    ))
}

fn event_label_key(event_id: &EventId, label: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(event_id.len() + label.len());
    key.extend_from_slice(event_id);
    key.extend_from_slice(label);
    key
}

fn vec_to_id(bytes: Vec<u8>) -> rusqlite::Result<EventId> {
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        table_error(format!("expected 32-byte event id, got {}", bytes.len()))
    })
}

fn table_error(err: String) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(err)
}

//! Worker-owned lifecycle operations for the generic event store.
//!
//! Protocol schema declares tables and pure row encoders. This module owns the
//! active mechanics that change event lifecycle: idempotent insertion, ready
//! claiming, status transitions, and dependency-edge maintenance. Keeping those
//! verbs here prevents schema modules from becoming hidden workers while still
//! letting the common event pipeline share one audited implementation.
//!
//! The invariant is that lifecycle changes remain generic. This module may move
//! durable event rows between `Ready`, `Blocked`, and `Applied`; it may maintain
//! protocol-wide dependency indexes; it may not decode event families, decide
//! domain deletion policy, write module read models, or enqueue transport.

use crate::core::store::Store;
use crate::protocol::event_modules::schema;
use crate::protocol::event_modules::types::{event_id, EventId, EventRecord, EventStatus};

/// Insert a durable event and the generic indexes that make it schedulable.
pub(crate) fn insert_event(
    store: &Store,
    event: &EventRecord,
    status: EventStatus,
) -> rusqlite::Result<bool> {
    let id = event_id(&event.canonical_bytes);
    if store.table_row(schema::EVENTS, &id)?.is_some() {
        return Ok(false);
    }

    let mut rows = vec![schema::event_row(&id, event, status)?];
    if status == EventStatus::Ready {
        rows.push(schema::ready_row(event.timestamp, &id));
    }
    if event.scope.is_shared() {
        rows.push(schema::timestamp_row(
            event.timestamp,
            event.workspace_id,
            &id,
        ));
    }
    store.insert_table_rows_in_tx(rows)?;
    Ok(true)
}

/// Return whether an event has reached the generic Applied lifecycle state.
pub(crate) fn event_is_applied(store: &Store, event_id: &EventId) -> rusqlite::Result<bool> {
    schema::read_event(store, event_id).map(|event| {
        event
            .map(|event| event.status == EventStatus::Applied)
            .unwrap_or(false)
    })
}

/// Record one missing dependency edge in both lookup directions.
pub(crate) fn insert_blocked_event_missing_dep(
    store: &Store,
    missing_dep_id: &EventId,
    blocked_event_id: &EventId,
) -> rusqlite::Result<bool> {
    let primary = schema::edge_row(
        schema::BLOCKED_EVENTS_BY_MISSING_DEP,
        missing_dep_id,
        blocked_event_id,
    );
    let inserted = store.insert_table_rows_in_tx(vec![primary])? > 0;
    store.insert_table_rows_in_tx(vec![schema::edge_row(
        schema::MISSING_DEPS_BY_BLOCKED_EVENT,
        blocked_event_id,
        missing_dep_id,
    )])?;
    Ok(inserted)
}

/// Claim the oldest ready event id without mutating state.
pub(crate) fn next_ready_event(store: &Store) -> rusqlite::Result<Option<EventId>> {
    let mut rows = store.table_rows_with_key_prefix(schema::READY_EVENTS, &[], 1)?;
    let Some((_, value)) = rows.pop() else {
        return Ok(None);
    };
    vec_to_id(value).map(Some)
}

/// Move an event between lifecycle statuses if it is currently in `from`.
pub(crate) fn set_event_status(
    store: &Store,
    event_id: &EventId,
    from: EventStatus,
    to: EventStatus,
) -> rusqlite::Result<bool> {
    let Some(mut event) = schema::read_event(store, event_id)? else {
        return Ok(false);
    };
    if event.status != from {
        return Ok(false);
    }

    let old_ready_key =
        (from == EventStatus::Ready).then(|| schema::ready_key(event.timestamp, event_id));
    event.status = to;
    let mut rows = vec![schema::stored_event_row(event_id, &event)?];
    if to == EventStatus::Ready {
        rows.push(schema::ready_row(event.timestamp, event_id));
    }

    store.replace_table_rows_in_tx(rows)?;
    if let Some(key) = old_ready_key {
        store.delete_table_rows_in_tx(schema::READY_EVENTS, vec![key])?;
    }
    Ok(true)
}

/// Delete every blocker edge waiting on one newly applied dependency.
pub(crate) fn delete_blocked_events_by_missing_dep(
    store: &Store,
    missing_dep_id: &EventId,
) -> rusqlite::Result<usize> {
    let rows = store.table_rows_with_key_prefix(
        schema::BLOCKED_EVENTS_BY_MISSING_DEP,
        missing_dep_id,
        schema::MAX_DEPENDENCY_ROWS_PER_EVENT,
    )?;
    let mut blocked_keys = Vec::with_capacity(rows.len());
    let mut reverse_keys = Vec::with_capacity(rows.len());
    for (key, _) in rows {
        let (missing_dep, blocked_event_id) = schema::split_edge_key(&key)?;
        blocked_keys.push(key);
        reverse_keys.push(schema::edge_key(&blocked_event_id, &missing_dep));
    }
    let deleted =
        store.delete_table_rows_in_tx(schema::BLOCKED_EVENTS_BY_MISSING_DEP, blocked_keys)?;
    store.delete_table_rows_in_tx(schema::MISSING_DEPS_BY_BLOCKED_EVENT, reverse_keys)?;
    Ok(deleted)
}

/// List events currently blocked on a specific missing dependency.
pub(crate) fn blocked_events_by_missing_dep(
    store: &Store,
    missing_dep_id: &EventId,
) -> rusqlite::Result<Vec<EventId>> {
    store
        .table_rows_with_key_prefix(
            schema::BLOCKED_EVENTS_BY_MISSING_DEP,
            missing_dep_id,
            schema::MAX_DEPENDENCY_ROWS_PER_EVENT,
        )?
        .into_iter()
        .map(|(key, _)| schema::split_edge_key(&key).map(|(_, blocked_event_id)| blocked_event_id))
        .collect()
}

/// Return whether a blocked event still has unresolved dependency edges.
pub(crate) fn blocked_event_has_missing_deps(
    store: &Store,
    blocked_event_id: &EventId,
) -> rusqlite::Result<bool> {
    store
        .table_rows_with_key_prefix(schema::MISSING_DEPS_BY_BLOCKED_EVENT, blocked_event_id, 1)
        .map(|rows| !rows.is_empty())
}

fn vec_to_id(bytes: Vec<u8>) -> rusqlite::Result<EventId> {
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        rusqlite::Error::InvalidParameterName(format!(
            "expected 32-byte event id, got {}",
            bytes.len()
        ))
    })
}

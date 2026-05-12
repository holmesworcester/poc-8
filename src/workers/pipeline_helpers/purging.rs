//! Worker-owned local retention cleanup.
//!
//! Retention is an operational concern, not event syntax. This module owns the
//! concrete act of removing locally retained canonical event bytes and their
//! generic event-store indexes after a domain worker has proved those bytes are
//! no longer needed for local service. It relies on protocol schema helpers only
//! for table names and row-key encoding; it does not define protocol-visible
//! deletion facts, decide domain deletion policy, or synthesize replacement
//! events.
//!
//! The enforced invariant is narrow: a purge removes only local storage rows that
//! make an event replayable or schedulable by the generic event pipeline. Labels
//! and domain read-model rows are left alone because they are protocol facts or
//! module-owned indexes. A caller that needs semantic deletion must project a
//! real event before scheduling retention cleanup here.

use crate::core::store::Store;
use crate::protocol::event_modules::schema;
use crate::protocol::event_modules::types::{EventId, EventStatus};

/// Remove one event's locally retained bytes and generic event-store indexes.
///
/// This is local retention cleanup only. It is not a protocol deletion event,
/// does not create or remove semantic deletion facts, and must be called only
/// after a domain worker has verified that the protocol-visible state no longer
/// needs the canonical bytes.
pub(crate) fn purge_event_storage_in_tx(
    store: &Store,
    event_id: &EventId,
) -> rusqlite::Result<bool> {
    let Some(value) = store.table_row(schema::EVENTS, event_id)? else {
        return Ok(false);
    };
    let event = schema::decode_stored_event_index(&value)?;

    let mut deleted_any = false;
    if event.status == EventStatus::Ready {
        deleted_any |= store.delete_table_rows_in_tx(
            schema::READY_EVENTS,
            vec![schema::ready_key(event.timestamp, event_id)],
        )? > 0;
    }
    if event.scope.is_shared() {
        deleted_any |= store.delete_table_rows_in_tx(
            schema::TIMESTAMP_EVENTS,
            vec![schema::timestamp_key(event.timestamp, event_id)],
        )? > 0;
    }

    let missing_edges = store.table_rows_with_key_prefix(
        schema::MISSING_DEPS_BY_BLOCKED_EVENT,
        event_id,
        schema::MAX_DEPENDENCY_ROWS_PER_EVENT,
    )?;
    let mut reverse_keys = Vec::with_capacity(missing_edges.len());
    let mut forward_keys = Vec::with_capacity(missing_edges.len());
    for (key, _) in missing_edges {
        let (blocked_event_id, missing_dep_id) = schema::split_edge_key(&key)?;
        reverse_keys.push(key);
        forward_keys.push(schema::edge_key(&missing_dep_id, &blocked_event_id));
    }
    deleted_any |=
        store.delete_table_rows_in_tx(schema::MISSING_DEPS_BY_BLOCKED_EVENT, reverse_keys)? > 0;
    deleted_any |=
        store.delete_table_rows_in_tx(schema::BLOCKED_EVENTS_BY_MISSING_DEP, forward_keys)? > 0;
    deleted_any |= store.delete_table_rows_in_tx(schema::EVENTS, vec![event_id.to_vec()])? > 0;
    Ok(deleted_any)
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::schema::{self as event_schema, EventLabel};
    use crate::protocol::event_modules::types::{event_id, EventRecord, EventScope};
    use crate::protocol::Protocol;
    use crate::workers::pipeline_helpers::event_lifecycle;

    use super::*;

    #[test]
    fn purge_event_storage_removes_local_retention_rows_but_keeps_labels() {
        let store = Protocol::open_memory_store().expect("store");
        let workspace_id = [1; 32];
        let missing_dep_id = [2; 32];
        let record = EventRecord {
            timestamp: 42,
            body_len: 12,
            canonical_bytes: b"purge-target".to_vec(),
            dependencies: Vec::new(),
            workspace_id: Some(workspace_id),
            scope: EventScope::Shared,
        };
        let target_id = event_id(&record.canonical_bytes);
        let label = b"local-retention-proof".to_vec();

        event_lifecycle::insert_event(&store, &record, EventStatus::Ready).expect("insert event");
        event_lifecycle::insert_blocked_event_missing_dep(&store, &missing_dep_id, &target_id)
            .expect("insert missing dependency edge");
        store
            .insert_table_rows(event_schema::event_label_rows(vec![EventLabel {
                event_id: target_id,
                label: label.clone(),
            }]))
            .expect("insert label");

        let purged = store
            .write_transaction(|store| purge_event_storage_in_tx(store, &target_id))
            .expect("purge event storage");

        assert!(purged);
        assert!(event_schema::event_bytes(&store, &target_id)
            .expect("event bytes")
            .is_none());
        assert_eq!(
            event_schema::event_index_entries_in_timestamp_range(&store, 0, u64::MAX)
                .expect("timestamp index"),
            Vec::new()
        );
        assert_eq!(
            event_lifecycle::blocked_events_by_missing_dep(&store, &missing_dep_id)
                .expect("forward deps"),
            Vec::<EventId>::new()
        );
        assert!(
            !event_lifecycle::blocked_event_has_missing_deps(&store, &target_id)
                .expect("reverse deps")
        );
        assert_eq!(
            event_schema::event_labels(&store, &target_id).expect("labels"),
            vec![label]
        );
    }

    #[test]
    fn purge_event_storage_reports_missing_event_as_noop() {
        let store = Protocol::open_memory_store().expect("store");
        let missing_id = [9; 32];

        let purged = store
            .write_transaction(|store| purge_event_storage_in_tx(store, &missing_id))
            .expect("purge missing event");

        assert!(!purged);
    }
}

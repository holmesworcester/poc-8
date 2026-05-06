//! Sync domain.
//!
//! Sync is modeled as connection-scoped compare/have/need events plus a domain
//! command layer and worker. Projectors use connection scope metadata, not
//! event-body direction fields: locally proposed sync events go to the
//! transit out queue by id, while received sync events go to sync-owned in
//! rows. Commands decide what follow-up ids to propose from explicit read
//! context. The worker owns queue draining and the process-local sync index.
//!
//! This module owns sync event syntax, projection, and command logic.
//! `crate::workers::sync` owns scheduling, queue consumption, and worker state.

pub mod cli;
pub mod commands;
pub mod compare;
pub mod have_id;
pub mod need_id;
pub use crate::workers::sync as worker;
pub use crate::workers::sync::SyncIndex;

use crate::protocol::event_modules::connection;
use crate::protocol::event_modules::types::EventRecord;
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

pub fn project_record(event: &EventWithContext<'_>) -> Result<Option<ProjectionOutput>, String> {
    let bytes = &event.record.canonical_bytes;
    if compare::codec::is_event(bytes) {
        return Ok(Some(compare::projector::project(event)?));
    }
    if have_id::codec::is_event(bytes) {
        return Ok(Some(have_id::projector::project(event)?));
    }
    if need_id::codec::is_event(bytes) {
        return Ok(Some(need_id::projector::project(event)?));
    }
    Ok(None)
}

pub fn is_connection_scoped_event(bytes: &[u8]) -> bool {
    compare::codec::is_event(bytes)
        || have_id::codec::is_event(bytes)
        || need_id::codec::is_event(bytes)
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    if compare::codec::is_event(&bytes) {
        return compare::codec::record_from_bytes(bytes);
    }
    if have_id::codec::is_event(&bytes) {
        return have_id::codec::record_from_bytes(bytes);
    }
    if need_id::codec::is_event(&bytes) {
        return need_id::codec::record_from_bytes(bytes);
    }
    Err("not a sync event".to_string())
}

pub fn inbound_record_from_connection_bytes(
    connection_id: connection::types::ConnectionId,
    bytes: Vec<u8>,
) -> Result<EventRecord, String> {
    if compare::codec::is_event(&bytes) {
        let record = compare::codec::inbound_record_from_wire(bytes)?;
        ensure_record_connection(connection_id, &record)?;
        return Ok(record);
    }
    if have_id::codec::is_event(&bytes) {
        let record = have_id::codec::inbound_record_from_wire(bytes)?;
        ensure_record_connection(connection_id, &record)?;
        return Ok(record);
    }
    if need_id::codec::is_event(&bytes) {
        let record = need_id::codec::inbound_record_from_wire(bytes)?;
        ensure_record_connection(connection_id, &record)?;
        return Ok(record);
    }
    Err("not a sync event".to_string())
}

fn ensure_record_connection(
    expected: connection::types::ConnectionId,
    record: &EventRecord,
) -> Result<(), String> {
    let actual = match record.scope {
        crate::protocol::event_modules::types::EventScope::Connection(scope) => {
            scope.connection_id()
        }
        _ => return Err("sync event did not carry connection scope".to_string()),
    };
    if actual == expected {
        Ok(())
    } else {
        Err("sync event used a different connection id".to_string())
    }
}

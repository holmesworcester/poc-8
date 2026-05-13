//! Stateless event-module registry.
//!
//! `Modules` is the bridge between the generic `EventRegistry` trait and the
//! free functions in `event_modules`. All registry state (sync index,
//! connection peers, etc.) lives on `Protocol` and `cli::Context`; this
//! struct exists only so callers can hold a `dyn EventRegistry` without
//! naming the concrete protocol shell.

use crate::core::store::Store;
use crate::protocol::event_modules::connection;
use crate::protocol::event_modules::content;
use crate::protocol::event_modules::encryption;
use crate::protocol::event_modules::event_from_bytes::event_from_bytes;
use crate::protocol::event_modules::identity;
use crate::protocol::event_modules::sync;
use crate::protocol::event_modules::test_events;
use crate::protocol::event_modules::types::{EventRecord, ReceiveMetadata};
use crate::protocol::event_modules::worker::{
    AdmitDecision, EventRegistry, EventWithContext, ProjectionOutput, ReceivedRecord,
};
use crate::workers::schema::TransitProvenance;

#[derive(Debug, Clone, Copy, Default)]
pub struct Modules;

impl Modules {
    pub fn new() -> Self {
        Self
    }
}

impl EventRegistry for Modules {
    fn event_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        event_from_bytes(bytes)
    }

    fn record_from_canonical_in(
        &self,
        store: &Store,
        bytes: Vec<u8>,
        receive: Option<ReceiveMetadata>,
        provenance: Option<TransitProvenance>,
    ) -> Result<ReceivedRecord, String> {
        canonical_in(store, bytes, receive, provenance)
    }

    fn project_record(
        &self,
        store: &Store,
        event: &EventWithContext<'_>,
    ) -> Result<ProjectionOutput, String> {
        project_record(store, event)
    }

    fn admit_received_record(
        &self,
        store: &Store,
        record: &EventRecord,
    ) -> Result<AdmitDecision, String> {
        // Only the content domain currently has receive-side admission
        // gates (drop re-deliveries of tombstoned messages and their
        // dependents). Other domains opt in by adding a branch here.
        content::admit_check_received(store, record)
    }

    fn post_admission_hook(&self, store: &Store) -> Result<(), String> {
        // Bounded post-admission drains for this protocol live in the worker
        // catalog. The catalog observes projector-emitted indicator rows and
        // dispatches to the right worker, so this registry stays narrow: it
        // does not branch on event type or own worker dispatch logic.
        crate::workers::drain_post_admission_purge_pending(store, self)
    }
}

/// Project an admitted event into the rows its domain owns. Each branch
/// hands control immediately to the owning domain so this dispatch stays
/// shallow.
pub fn project_record(
    _store: &Store,
    event: &EventWithContext<'_>,
) -> Result<ProjectionOutput, String> {
    let bytes = &event.record.canonical_bytes;
    if let Some(output) = identity::project_record(event)? {
        return Ok(output);
    }
    if connection::is_projection_record(bytes) {
        return connection::project_record(event);
    }
    if let Some(output) = sync::project_record(event)? {
        return Ok(output);
    }
    if let Some(output) = content::project_record(event)? {
        return Ok(output);
    }
    if let Some(output) = encryption::project_record(event)? {
        return Ok(output);
    }
    if let Some(output) = test_events::project_record(bytes)? {
        return Ok(output);
    }
    let tag = bytes.first().copied().unwrap_or_default();
    Err(format!("unknown event type {tag}"))
}

/// Decode an admitted record from canonical bytes plus optional receive
/// context. When transit provenance is present, the connection domain
/// owns the recovery path; otherwise this is straight tag-leading decode.
pub fn canonical_in(
    store: &Store,
    bytes: Vec<u8>,
    receive: Option<ReceiveMetadata>,
    provenance: Option<TransitProvenance>,
) -> Result<ReceivedRecord, String> {
    match provenance {
        Some(provenance) => {
            connection::transit::projector::record_from_transit_canonical_in(store, bytes, provenance)
        }
        None => {
            let record = event_from_bytes(bytes)?;
            Ok(match receive {
                Some(receive) => ReceivedRecord::with_receive(record, receive),
                None => ReceivedRecord::new(record),
            })
        }
    }
}

/// Aggregate every event-module schema. Storage ownership stays explicit so
/// adding a new module-owned table is one line here plus the actual
/// declaration in that module's `schema.rs`.
pub fn schemas() -> Vec<crate::core::store::Schema> {
    use crate::protocol::event_modules::schema;
    let mut out = Vec::new();
    out.extend_from_slice(schema::SCHEMAS);
    out.extend_from_slice(identity::admin::schema::SCHEMAS);
    out.extend_from_slice(identity::device_invite::schema::SCHEMAS);
    out.extend_from_slice(identity::endpoint::schema::SCHEMAS);
    out.extend_from_slice(identity::endpoint_shared::schema::SCHEMAS);
    out.extend_from_slice(identity::invite::schema::SCHEMAS);
    out.extend_from_slice(identity::invite_accepted::schema::SCHEMAS);
    out.extend_from_slice(identity::invite_server::schema::SCHEMAS);
    out.extend_from_slice(identity::user::schema::SCHEMAS);
    out.extend_from_slice(identity::user_invite::schema::SCHEMAS);
    out.extend_from_slice(identity::workspace::schema::SCHEMAS);
    out.extend_from_slice(content::content_event::schema::SCHEMAS);
    out.extend_from_slice(content::message::schema::SCHEMAS);
    out.extend_from_slice(content::message_deletion::schema::SCHEMAS);
    out.extend_from_slice(content::reaction::schema::SCHEMAS);
    out.extend_from_slice(content::file::schema::SCHEMAS);
    out.extend_from_slice(content::file_slice::schema::SCHEMAS);
    out.extend_from_slice(encryption::disappearing_messages_setting::schema::SCHEMAS);
    out.extend_from_slice(encryption::key_wrap::schema::SCHEMAS);
    out.extend_from_slice(encryption::local_history_node_secret::schema::SCHEMAS);
    out.extend_from_slice(encryption::local_key_secret::schema::SCHEMAS);
    out.extend_from_slice(encryption::local_recipient_key::schema::SCHEMAS);
    out.extend_from_slice(encryption::recipient_key::schema::SCHEMAS);
    out.extend_from_slice(encryption::recipient_key_tombstone::schema::SCHEMAS);
    out.extend_from_slice(encryption::removal_frontier::schema::SCHEMAS);
    out.extend_from_slice(connection::schema::SCHEMAS);
    out.extend_from_slice(sync::schema::SCHEMAS);
    out.extend_from_slice(test_events::event_with_deps::schema::SCHEMAS);
    out
}

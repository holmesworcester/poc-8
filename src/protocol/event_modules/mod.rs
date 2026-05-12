//! Event-module registry and cross-domain protocol facade.
//!
//! Leaf modules own concrete event syntax and projection rules. Workers own
//! active work such as unwrap, wrap, and sync comparison. This registry is the
//! narrow place where those independent pieces are selected by tag.
//!
//! The file should read as routing, not implementation. A good addition here
//! names which module owns a behavior and forwards to it. A suspicious addition
//! starts decoding fields inline, writing rows directly, or making a network
//! decision without going through the relevant worker.

pub mod connection;
pub mod content;
pub mod encryption;
pub mod identity;
pub mod schema;
pub mod sync;
pub mod test_events;
pub mod types;
pub use crate::workers::pipeline_helpers::event_pipeline as worker;

/// Re-export of the local history-node leaf event module under a name that
/// does not embed the parent domain's vocabulary, so consumer projectors that
/// cannot mention transit/crypto by name can still decode and validate leaf
/// canonical bytes against `EventWithContext` dependencies. Routing remains
/// through the encryption module; this is a stable referencing alias only.
pub use encryption::local_history_node_secret as leaf_history_node;

/// Re-export of the disappearing-messages setting event module under a name
/// that does not embed the parent domain's vocabulary. The message
/// projector validates per-message disappearing-policy references against
/// signed setting events; this alias lets the projector decode those
/// canonical bytes without tripping the "no encrypt" projector lint.
pub use encryption::disappearing_messages_setting;

use std::sync::Arc;

use crate::core::store::{Schema, Store};
use crate::protocol::event_modules::types::{EventRecord, ReceiveMetadata};
use crate::protocol::event_modules::worker::{
    AdmitDecision, EventRegistry, EventWithContext, ProjectionOutput, ReceivedRecord,
};
use crate::workers::schema::TransitProvenance;

#[derive(Debug, Clone, Default)]
pub struct Modules {
    sync_index: Arc<sync::SyncIndex>,
}

impl Modules {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn sync_index(&self) -> &sync::SyncIndex {
        &self.sync_index
    }

    pub fn record_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        record_from_bytes(bytes)
    }

    pub fn project_record(
        &self,
        _store: &Store,
        event: &EventWithContext<'_>,
    ) -> Result<ProjectionOutput, String> {
        // Projection dispatch is tag-based and intentionally shallow. Each
        // branch immediately hands control to the owning domain so this registry
        // does not accumulate projector logic.
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
}

pub fn schemas() -> Vec<Schema> {
    // Schema aggregation is explicit so storage ownership remains visible in
    // review. Adding a module-owned table should add one line here and the
    // actual declaration in that module's `schema.rs`.
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

impl EventRegistry for Modules {
    fn record_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        self.record_from_bytes(bytes)
    }

    fn record_from_canonical_in(
        &self,
        store: &Store,
        bytes: Vec<u8>,
        receive: Option<ReceiveMetadata>,
        provenance: Option<TransitProvenance>,
    ) -> Result<ReceivedRecord, String> {
        match provenance {
            Some(provenance) => connection::transit::projector::record_from_transit_canonical_in(
                store, bytes, provenance,
            ),
            None => {
                let record = self.record_from_bytes(bytes)?;
                Ok(match receive {
                    Some(receive) => ReceivedRecord::with_receive(record, receive),
                    None => ReceivedRecord::new(record),
                })
            }
        }
    }

    fn project_record(
        &self,
        store: &Store,
        event: &EventWithContext<'_>,
    ) -> Result<ProjectionOutput, String> {
        self.project_record(store, event)
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

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    // Connection bootstrap records use a magic prefix. Ordinary shared/local
    // events and connection-scoped sync events use a single leading type tag.
    if connection::connection_ephemeral_secret::codec::is_ephemeral_secret(&bytes) {
        return connection::connection_ephemeral_secret::codec::record_from_bytes(bytes);
    }
    if connection::connection_request::codec::is_request(&bytes) {
        return connection::connection_request::codec::record_from_bytes(bytes);
    }
    if connection::connection_response::codec::is_response(&bytes) {
        return connection::connection_response::codec::record_from_bytes(bytes);
    }
    if sync::is_connection_scoped_event(&bytes) {
        return sync::record_from_bytes(bytes);
    }
    let tag = bytes
        .first()
        .ok_or_else(|| "empty event bytes".to_string())?;
    match *tag {
        identity::admin::codec::TYPE_ADMIN => Err("admin must be signed".to_string()),
        identity::device_invite::codec::TYPE_DEVICE_INVITE => {
            Err("device_invite must be signed".to_string())
        }
        identity::endpoint::codec::TYPE_LOCAL_ENDPOINT => {
            identity::endpoint::codec::record_from_bytes(bytes)
        }
        identity::signed::codec::TYPE_SIGNED => identity::signed_record_from_bytes(bytes),
        identity::invite::codec::TYPE_INVITE_SECRET => {
            identity::invite::codec::record_from_bytes(bytes)
        }
        identity::invite_accepted::codec::TYPE_INVITE_ACCEPTED => {
            identity::invite_accepted::codec::record_from_bytes(bytes)
        }
        identity::workspace::codec::TYPE_WORKSPACE => {
            identity::workspace::codec::record_from_bytes(bytes)
        }
        sync::compare::codec::TYPE_SYNC_COMPARE => sync::compare::codec::record_from_bytes(bytes),
        sync::have_id::codec::TYPE_SYNC_HAVE_ID => sync::have_id::codec::record_from_bytes(bytes),
        sync::need_id::codec::TYPE_SYNC_NEED_ID => sync::need_id::codec::record_from_bytes(bytes),
        content::content_event::codec::TYPE_CONTENT => Err("content must be signed".to_string()),
        content::content_event::codec::TYPE_SIGNED_CONTENT => {
            content::content_event::codec::signed_record_from_bytes(bytes)
        }
        content::message::codec::TYPE_MESSAGE => Err("message must be signed".to_string()),
        content::message::codec::TYPE_SIGNED_MESSAGE => {
            content::message::codec::signed_record_from_bytes(bytes)
        }
        content::reaction::codec::TYPE_REACTION => Err("reaction must be signed".to_string()),
        content::reaction::codec::TYPE_SIGNED_REACTION => {
            content::reaction::codec::signed_record_from_bytes(bytes)
        }
        content::message_deletion::codec::TYPE_MESSAGE_DELETION => {
            Err("message deletion must be signed".to_string())
        }
        content::message_deletion::codec::TYPE_SIGNED_MESSAGE_DELETION => {
            content::message_deletion::codec::signed_record_from_bytes(bytes)
        }
        content::file::codec::TYPE_FILE => Err("file must be signed".to_string()),
        content::file::codec::TYPE_SIGNED_FILE => {
            content::file::codec::signed_record_from_bytes(bytes)
        }
        content::file_slice::codec::TYPE_FILE_SLICE => Err("file slice must be signed".to_string()),
        content::file_slice::codec::TYPE_SIGNED_FILE_SLICE => {
            content::file_slice::codec::signed_record_from_bytes(bytes)
        }
        content::file_deletion::codec::TYPE_FILE_DELETION => {
            Err("file deletion must be signed".to_string())
        }
        content::file_deletion::codec::TYPE_SIGNED_FILE_DELETION => {
            content::file_deletion::codec::signed_record_from_bytes(bytes)
        }
        encryption::local_recipient_key::codec::TYPE_LOCAL_RECIPIENT_KEY => {
            encryption::record_from_bytes(bytes)
        }
        encryption::local_key_secret::codec::TYPE_LOCAL_KEY_SECRET => {
            encryption::record_from_bytes(bytes)
        }
        encryption::local_history_node_secret::codec::TYPE_LOCAL_HISTORY_NODE_SECRET => {
            encryption::record_from_bytes(bytes)
        }
        encryption::recipient_key::codec::TYPE_RECIPIENT_KEY => {
            Err("recipient_key must be signed".to_string())
        }
        encryption::recipient_key::codec::TYPE_SIGNED_RECIPIENT_KEY => {
            encryption::record_from_bytes(bytes)
        }
        encryption::recipient_key_tombstone::codec::TYPE_RECIPIENT_KEY_TOMBSTONE => {
            Err("recipient_key_tombstone must be signed".to_string())
        }
        encryption::recipient_key_tombstone::codec::TYPE_SIGNED_RECIPIENT_KEY_TOMBSTONE => {
            encryption::record_from_bytes(bytes)
        }
        encryption::removal_frontier::codec::TYPE_REMOVAL_FRONTIER => {
            Err("removal_frontier must be signed".to_string())
        }
        encryption::removal_frontier::codec::TYPE_SIGNED_REMOVAL_FRONTIER => {
            encryption::record_from_bytes(bytes)
        }
        encryption::key_wrap::codec::TYPE_KEY_WRAP => Err("key_wrap must be signed".to_string()),
        encryption::key_wrap::codec::TYPE_SIGNED_KEY_WRAP => encryption::record_from_bytes(bytes),
        encryption::disappearing_messages_setting::codec::TYPE_DISAPPEARING_MESSAGES_SETTING => {
            Err("disappearing_messages_setting must be signed".to_string())
        }
        encryption::disappearing_messages_setting::codec::TYPE_SIGNED_DISAPPEARING_MESSAGES_SETTING => {
            encryption::record_from_bytes(bytes)
        }
        test_events::event_with_deps::codec::TYPE_EVENT_WITH_DEPS => {
            test_events::event_with_deps::codec::record_from_bytes(bytes)
        }
        test_events::event_with_deps::codec::TYPE_STAGED_EVENT_WITH_DEPS => {
            test_events::event_with_deps::codec::staged_record_from_bytes(bytes)
        }
        other => Err(format!("unknown event type {other}")),
    }
}

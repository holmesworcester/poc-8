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

use std::sync::Arc;

use crate::core::store::{Schema, Store};
use crate::protocol::event_modules::types::{EventRecord, ReceiveMetadata};
use crate::protocol::event_modules::worker::{
    EventRegistry, EventWithContext, ProjectionOutput, ReceivedRecord,
};
use crate::workers::schema::{TransitProvenance, TransitUnwrap};

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
    out.extend_from_slice(encryption::key_wrap::schema::SCHEMAS);
    out.extend_from_slice(encryption::local_history_node_secret::schema::SCHEMAS);
    out.extend_from_slice(encryption::local_key_secret::schema::SCHEMAS);
    out.extend_from_slice(encryption::local_recipient_key::schema::SCHEMAS);
    out.extend_from_slice(encryption::recipient_key::schema::SCHEMAS);
    out.extend_from_slice(encryption::recipient_key_tombstone::schema::SCHEMAS);
    out.extend_from_slice(encryption::removal_frontier::schema::SCHEMAS);
    out.extend_from_slice(connection::schema::SCHEMAS);
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
            Some(provenance) => record_from_transit_canonical_in(store, bytes, provenance),
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

    fn post_admission_hook(&self, store: &Store) -> Result<(), String> {
        // Bounded post-admission drains for this protocol live in the worker
        // catalog. The catalog observes projector-emitted indicator rows and
        // dispatches to the right worker, so this registry stays narrow: it
        // does not branch on event type or own worker dispatch logic.
        crate::workers::drain_post_admission_purge_pending(store, self)
    }
}

fn record_from_transit_canonical_in(
    store: &Store,
    bytes: Vec<u8>,
    provenance: TransitProvenance,
) -> Result<ReceivedRecord, String> {
    match provenance.unwrapped_with {
        TransitUnwrap::Bootstrap => {
            if !connection::connection_request::codec::is_request(&bytes) {
                return Err(
                    "endpoint bootstrap transit only carries connection requests".to_string(),
                );
            }
            let record = connection::connection_request::codec::record_from_bytes(bytes)?;
            return Ok(ReceivedRecord::with_receive(
                record,
                ReceiveMetadata::bootstrap_invite(
                    provenance.origin,
                    provenance.local_endpoint,
                    provenance.sender_endpoint,
                    provenance.remember_route,
                ),
            ));
        }
        TransitUnwrap::InviteBootstrap { workspace_id, .. } => {
            let record = record_from_bytes(bytes)?;
            if !record.scope.is_shared() {
                return Err("invite bootstrap transit only accepts shared events".to_string());
            }
            if record.workspace_id != Some(workspace_id) {
                return Err(
                    "invite bootstrap transit rejected event outside invite workspace".to_string(),
                );
            }
            if !is_identity_bootstrap_event(&record.canonical_bytes)? {
                return Err(
                    "invite bootstrap transit only accepts identity bootstrap events".to_string(),
                );
            }
            return Ok(ReceivedRecord::new(record));
        }
        TransitUnwrap::Connection { connection_id } => {
            if connection::connection_request::codec::is_request(&bytes) {
                return Err("connection transit cannot carry connection requests".to_string());
            }
            if connection::connection_response::codec::is_response(&bytes) {
                let record = connection::connection_response::codec::record_from_bytes(bytes)?;
                return Ok(ReceivedRecord::with_receive(
                    record,
                    ReceiveMetadata::endpoint_receive(
                        provenance.origin,
                        provenance.local_endpoint,
                        provenance.sender_endpoint,
                        provenance.remember_route,
                    ),
                ));
            }
            if sync::is_connection_scoped_event(&bytes) {
                return sync::inbound_record_from_connection_bytes(connection_id, bytes)
                    .map(ReceivedRecord::new);
            }
        }
    }
    let TransitUnwrap::Connection { connection_id } = provenance.unwrapped_with else {
        return Err("transit provenance cannot admit this event".to_string());
    };
    let record = record_from_bytes(bytes)?;
    if !record.scope.is_shared() {
        return Err(
            "connection transit only accepts shared or connection-scoped events".to_string(),
        );
    }
    let workspace_id = record
        .workspace_id
        .ok_or_else(|| "transit shared in requires a workspace".to_string())?;
    let allowed_workspaces = identity::endpoint_shared::schema::mutual_workspace_ids(
        store,
        provenance.local_endpoint,
        provenance.sender_endpoint,
    )?;
    if allowed_workspaces
        .iter()
        .any(|allowed| allowed == &workspace_id)
        || connection::connection_request::registry_meta::invite_authorizes_shared_event(
            store,
            &record,
            provenance.local_endpoint,
            provenance.sender_endpoint,
            connection_id,
        )?
    {
        Ok(ReceivedRecord::new(record))
    } else {
        return Err("transit shared in rejected event outside sender workspace".to_string());
    }
}

pub(crate) fn is_identity_bootstrap_event(bytes: &[u8]) -> Result<bool, String> {
    match bytes.first().copied() {
        Some(identity::workspace::codec::TYPE_WORKSPACE) => Ok(true),
        Some(identity::signed::codec::TYPE_SIGNED) => {
            let envelope = identity::signed::codec::decode(bytes)?;
            Ok(matches!(
                envelope.inner_type,
                identity::admin::codec::TYPE_ADMIN
                    | identity::user_invite::codec::TYPE_USER_INVITE
                    | identity::invite_server::codec::TYPE_INVITE_SERVER
                    | identity::user::codec::TYPE_USER
                    | identity::device_invite::codec::TYPE_DEVICE_INVITE
                    | identity::endpoint_shared::codec::TYPE_ENDPOINT_SHARED
            ))
        }
        _ => Ok(false),
    }
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    // Connection bootstrap records use a magic prefix. Ordinary shared/local
    // events and connection-scoped sync events use a single leading type tag.
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
        test_events::event_with_deps::codec::TYPE_EVENT_WITH_DEPS => {
            test_events::event_with_deps::codec::record_from_bytes(bytes)
        }
        test_events::event_with_deps::codec::TYPE_STAGED_EVENT_WITH_DEPS => {
            test_events::event_with_deps::codec::staged_record_from_bytes(bytes)
        }
        other => Err(format!("unknown event type {other}")),
    }
}

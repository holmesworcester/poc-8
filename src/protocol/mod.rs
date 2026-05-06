//! Concrete Topo protocol assembly.
//!
//! This module is the protocol-facing counterpart to the generic core runner.
//! It has four jobs:
//!
//! - choose the event modules, worker queue schemas, and core IO schemas that
//!   belong to this protocol;
//! - expose a small `Protocol` registry for event decoding, projection, and
//!   shared worker state;
//! - implement the protocol traits that let core open a context, list CLI
//!   commands, and run daemon workers;
//! - avoid implementing event behavior directly. Codecs, projectors, command
//!   behavior, queries, and worker logic stay in their owning module scopes.
//!
//! Keeping those boundaries visible matters because the generic app and daemon
//! code should be able to run any protocol with the same shape. A new protocol
//! should mostly be another module like this one: select schemas, provide a
//! registry, and hand core a command list plus a worker catalog.

pub mod cli;
pub mod event_modules;
pub mod wire;

use std::path::Path;

use crate::core::{
    app::ProtocolSpec,
    cli::CliCommand,
    daemon::{DaemonProtocol, Worker},
    network_queues::{self, InboundNetworkRow},
    store::{Schema, Store},
};
use event_modules::types::{EventRecord, ReceiveMetadata};
use event_modules::worker::{EventRegistry, EventWithContext, ProjectionOutput, ReceivedRecord};
use event_modules::Modules;

#[derive(Debug, Clone, Default)]
pub struct Protocol {
    modules: Modules,
}

impl Protocol {
    pub fn new() -> Self {
        Self {
            modules: Modules::new(),
        }
    }

    pub fn open_store(path: impl AsRef<Path>) -> rusqlite::Result<Store> {
        Store::open_disk_with_schemas(path, &schemas())
    }

    pub fn open_memory_store() -> rusqlite::Result<Store> {
        Store::open_memory_with_schemas(&schemas())
    }

    pub(crate) fn sync_index(&self) -> &event_modules::sync::SyncIndex {
        self.modules.sync_index()
    }
}

pub fn schemas() -> Vec<Schema> {
    // The concrete protocol owns the full schema set. Core storage is generic;
    // it only receives these declarations during open.
    let mut schemas = event_modules::schemas();
    schemas.extend_from_slice(crate::core::logical_clock::SCHEMAS);
    schemas.extend_from_slice(crate::workers::schema::SCHEMAS);
    schemas.extend_from_slice(network_queues::SCHEMAS);
    schemas
}

// Workers use this trait boundary to decode/project events without depending
// on the concrete module registry layout.
impl EventRegistry for Protocol {
    fn record_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        self.modules.record_from_bytes(bytes)
    }

    fn project_network_in(
        &self,
        store: &Store,
        inbound: &InboundNetworkRow,
    ) -> Result<ProjectionOutput, String> {
        event_modules::connection::transit::projector::project_network_in(store, inbound, false)
    }

    fn record_from_canonical_in(
        &self,
        store: &Store,
        bytes: Vec<u8>,
        receive: Option<ReceiveMetadata>,
        provenance: Option<crate::workers::schema::TransitProvenance>,
    ) -> Result<ReceivedRecord, String> {
        self.modules
            .record_from_canonical_in(store, bytes, receive, provenance)
    }

    fn project_record(
        &self,
        store: &Store,
        event: &EventWithContext<'_>,
    ) -> Result<ProjectionOutput, String> {
        self.modules.project_record(store, event)
    }
}

// Core daemon integration: the runner owns scheduling and lifecycle, while the
// protocol supplies the context type and named worker catalog.
impl DaemonProtocol for Protocol {
    type Context = cli::Context;

    fn daemon_db_path(context: &Self::Context) -> &Path {
        &context.db_path
    }

    fn daemon_workers() -> Vec<Worker<Self::Context>> {
        crate::workers::daemon_workers()
    }
}

// Core app integration: the binary shell asks the selected protocol for its
// name, context opener, and pass-through CLI command registry.
impl ProtocolSpec for Protocol {
    const NAME: &'static str = "topo";

    fn open_context(db_path: impl AsRef<Path>) -> Result<Self::Context, String> {
        cli::Context::open(db_path)
    }

    fn commands() -> Vec<CliCommand<Self::Context>> {
        cli::commands()
    }
}

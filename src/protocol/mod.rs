//! Concrete Topo protocol assembly.
//!
//! `Protocol` is intentionally a small registry object. Core provides storage,
//! queues, TCP, and a Crux runner; event modules provide commands, codecs,
//! projectors, schema declarations, queries, and workers. This file wires those pieces
//! together without becoming another place where event semantics are
//! implemented.
//!
//! The main invariant is that every store opened for this protocol receives
//! schemas declared by the owning module scopes. If a new feature needs state,
//! add its schema beside the rows that encode it, then aggregate it here.

pub mod cli;
pub mod clock;
pub mod event_modules;
pub mod wire;

use std::path::Path;

use crate::core::{
    network_queues,
    store::{Schema, Store},
};
use event_modules::types::EventRecord;
use event_modules::worker::{EventRegistry, EventWithContext, ProjectionOutput};
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

    pub fn modules(&self) -> &Modules {
        &self.modules
    }

    pub fn open_store(path: impl AsRef<Path>) -> rusqlite::Result<Store> {
        Store::open_disk_with_schemas(path, &schemas())
    }

    pub fn open_memory_store() -> rusqlite::Result<Store> {
        Store::open_memory_with_schemas(&schemas())
    }
}

pub fn schemas() -> Vec<Schema> {
    // Core IO schemas are selected with the protocol because this binary uses
    // the core TCP queues. The queue tables remain core-owned; event module
    // schemas remain protocol-owned.
    let mut schemas = event_modules::schemas();
    schemas.extend_from_slice(clock::SCHEMAS);
    schemas.extend_from_slice(network_queues::SCHEMAS);
    schemas
}

impl EventRegistry for Protocol {
    fn record_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        self.modules.record_from_bytes(bytes)
    }

    fn project_record(
        &self,
        store: &Store,
        event: &EventWithContext<'_>,
    ) -> Result<ProjectionOutput, String> {
        self.modules.project_record(store, event)
    }
}

impl event_modules::connection::worker::ConnectionRegistry for Protocol {
    fn sync_index(&self) -> &event_modules::sync::worker::SyncIndex {
        self.modules.sync_index()
    }
}

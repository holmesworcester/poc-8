//! Sync protocol worker.
//!
//! Input queues: `sync.inbound_events` and explicit sync-start requests.
//! Owned state: per-connection sync comparison cursors plus the warm sync index.
//! Output queues: event ingress for sync protocol events and `connection.outbox`
//! for requested durable events.
//! Ack: inbound sync rows are deleted by the sync worker after handling.

use crate::core::store::Store;
use crate::workers::sync::{self, Output, SyncIndex, Work};

pub fn run(store: &Store, index: &SyncIndex, work: Work) -> Result<Output, String> {
    sync::run(store, index, work)
}

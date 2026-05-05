//! Event projection worker.
//!
//! Input queue: `event_modules.ready_events`.
//! Owned state: projector-owned rows, labels, event statuses.
//! Output queues: `event_modules.recently_valid_events` and
//! `event_modules.applied_shared_events`.
//! Ack: the Ready -> Applied status transition claims the ready row.

use crate::core::store::Store;
use crate::workers::events::{self, ApplyReadyReport, EventRegistry};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    Drain { limit: usize },
}

pub fn run<R>(store: &Store, registry: &R, work: Work) -> Result<ApplyReadyReport, String>
where
    R: EventRegistry,
{
    match work {
        Work::Drain { limit } => events::drain_ready_events(store, registry, limit),
    }
}

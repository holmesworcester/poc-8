//! Event admission worker.
//!
//! Input queue: `event_modules.event_ingress`.
//! Owned state: durable event rows plus missing-dependency edge indexes.
//! Output queues: `event_modules.ready_events` and blocked-edge indexes.
//! Ack: delete claimed ingress rows in the same transaction as admission.

use crate::core::store::Store;
use crate::workers::events::{self, AdmitReport, EventRegistry};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    Drain { limit: usize },
}

pub fn run<R>(store: &Store, registry: &R, work: Work) -> Result<AdmitReport, String>
where
    R: EventRegistry,
{
    match work {
        Work::Drain { limit } => events::drain_event_ingress(store, registry, limit),
    }
}

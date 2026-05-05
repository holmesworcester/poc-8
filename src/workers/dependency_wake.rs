//! Dependency wake worker.
//!
//! Input queue: `event_modules.recently_valid_events`.
//! Owned state: missing-dependency edge indexes.
//! Output queue: `event_modules.ready_events`.
//! Ack: delete claimed recently-valid rows after their blocker edges are cleared.

use crate::core::store::Store;
use crate::workers::events::{self, ApplyReadyReport};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    Drain { limit: usize },
}

pub fn run(store: &Store, work: Work) -> Result<ApplyReadyReport, String> {
    match work {
        Work::Drain { limit } => events::drain_recently_valid_events(store, limit),
    }
}

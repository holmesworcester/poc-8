//! Dependency unblock worker.
//!
//! Inputs: `event_modules.recently_valid_events`.
//! State: missing-dependency edge indexes.
//! Step: claim recently valid event ids, remove blocker edges for each id, and
//! detect blocked events whose dependency set is now empty.
//! Outputs: newly unblocked events become `event_modules.ready_events`.
//! Consume: claimed recently-valid rows are deleted after their blocker edges are
//! cleared.
//! Failure: transaction rollback preserves the unblock input and blocker edges.
//! Fairness: `Work::Drain { limit }` bounds one call.

use crate::core::daemon::{self, StepContext, Worker};
use crate::core::store::Store;
use crate::workers::pipeline_helpers::event_pipeline::{self as pipeline, ApplyReadyReport};
use crate::workers::DaemonWorkerContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    Drain { limit: usize },
}

pub fn run(store: &Store, work: Work) -> Result<ApplyReadyReport, String> {
    match work {
        Work::Drain { limit } => pipeline::drain_recently_valid_events(store, limit),
    }
}

pub(crate) fn daemon_worker<C>() -> Worker<C>
where
    C: DaemonWorkerContext,
{
    Worker {
        name: "dependency_unblock",
        run: daemon_step::<C>,
    }
}

fn daemon_step<C>(ctx: &mut StepContext<'_, C>) -> Result<(), String>
where
    C: DaemonWorkerContext,
{
    daemon::run_step(
        ctx,
        "unblock dependencies",
        |app, limit| run(app.store(), Work::Drain { limit }),
        |report, out| out.add("unblocked_events", report.unblocked_events),
    )
}

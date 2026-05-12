//! Event projection worker.
//!
//! Inputs: `event_modules.ready_events`.
//! State: event status, projector-owned rows, and generic event labels.
//! Step: claim ready events by moving Ready -> Applied, load dependency
//! context, and run exactly one event-module projector per event.
//! Outputs: projector rows and labels, `event_modules.recently_valid_events`,
//! and `event_modules.applied_shared_events` for shared events.
//! Consume: the Ready -> Applied status transition is the claim; failed projection
//! rolls the status change back.
//! Failure: projection errors abort the current event and leave it ready for a
//! later drain attempt.
//! Fairness: `Work::Drain { limit }` bounds one call.

use crate::core::daemon::{self, StepContext, Worker};
use crate::core::store::Store;
use crate::workers::common::event_pipeline::{self as pipeline, ApplyReadyReport, EventRegistry};
use crate::workers::DaemonWorkerContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    Drain { limit: usize },
}

pub fn run<R>(store: &Store, registry: &R, work: Work) -> Result<ApplyReadyReport, String>
where
    R: EventRegistry,
{
    match work {
        Work::Drain { limit } => pipeline::drain_ready_events(store, registry, limit),
    }
}

pub(crate) fn daemon_worker<C>() -> Worker<C>
where
    C: DaemonWorkerContext,
{
    Worker {
        name: "event_projection",
        run: daemon_step::<C>,
    }
}

fn daemon_step<C>(ctx: &mut StepContext<'_, C>) -> Result<(), String>
where
    C: DaemonWorkerContext,
{
    daemon::run_step(
        ctx,
        "project ready events",
        |app, limit| run(app.store(), app, Work::Drain { limit }),
        |report, out| {
            out.add("ready_events", report.applied_events);
            out.add("unblocked_events", report.unblocked_events);
        },
    )
}

//! Transport accept worker.
//!
//! Inputs: inbound TCP streams accepted from the daemon listener.
//! State: core network queues only; protocol transit state is deliberately not
//! read here.
//! Step: accept at most one available stream and stage each length-prefixed frame
//! as `core.network.inbound`.
//! Outputs: inbound network rows for `transit_in`.
//! Consume: the TCP stream is drained to EOF for the accepted peer; queued rows
//! remain durable until `transit_in` claims them.
//! Failure: socket or queue errors stop the turn after the failing stream/frame.
//! Fairness: one accepted stream per daemon tick.

use crate::core::daemon::{StepContext, Worker};
use crate::core::tcp::{self, StreamReport};
use crate::workers::DaemonWorkerContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    AcceptAvailable,
}

pub fn run<C>(
    ctx: &mut StepContext<'_, C>,
    work: Work,
) -> Result<tcp::AcceptReport<StreamReport>, String>
where
    C: DaemonWorkerContext,
{
    match work {
        Work::AcceptAvailable => ctx.listener.accept_available(ctx.app.store()),
    }
}

pub(crate) fn daemon_worker<C>() -> Worker<C>
where
    C: DaemonWorkerContext,
{
    Worker {
        name: "transport_accept",
        run: daemon_step::<C>,
    }
}

fn daemon_step<C>(ctx: &mut StepContext<'_, C>) -> Result<(), String>
where
    C: DaemonWorkerContext,
{
    let report =
        run(ctx, Work::AcceptAvailable).map_err(|err| format!("accept transport: {err}"))?;
    ctx.report
        .add("accepted_connections", report.accepted_connections);
    ctx.report
        .add("received_frames", report.value.received_frames);
    Ok(())
}

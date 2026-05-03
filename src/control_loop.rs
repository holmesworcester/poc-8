use crate::event_modules::Modules;
use crate::pipeline::{self, ApplyReadyReport};
use crate::store::Store;

pub const DEFAULT_READY_BATCH: usize = 4096;
pub const DEFAULT_JOB_BATCH: usize = 4096;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DrainReport {
    pub applied_events: usize,
    pub unblocked_events: usize,
    pub jobs_run: usize,
    pub inserted_events: usize,
    pub sent_events: usize,
    pub received_events: usize,
}

pub fn drain_ready(
    store: &Store,
    modules: &Modules,
    limit: usize,
) -> Result<ApplyReadyReport, String> {
    store
        .write_transaction(|store| {
            let mut total = ApplyReadyReport::default();
            while total.applied_events < limit {
                let Some(event_id) = store.next_ready_event()? else {
                    break;
                };
                let report = pipeline::apply_ready_event_in_tx(store, modules, &event_id)?;
                total.applied_events += report.applied_events;
                total.unblocked_events += report.unblocked_events;
            }
            Ok(total)
        })
        .map_err(|err| format!("drain ready events: {err}"))
}

pub fn drain_until_idle(
    store: &Store,
    modules: &Modules,
    batch_size: usize,
) -> Result<DrainReport, String> {
    let mut total = DrainReport::default();
    loop {
        let ready = drain_ready(store, modules, batch_size)?;
        total.applied_events += ready.applied_events;
        total.unblocked_events += ready.unblocked_events;

        let jobs = pipeline::drain_module_jobs(store, modules, DEFAULT_JOB_BATCH)?;
        total.jobs_run += jobs.jobs_run;
        total.inserted_events += jobs.inserted_events;
        total.applied_events += jobs.applied_events;
        total.sent_events += jobs.sent_events;
        total.received_events += jobs.received_events;

        if ready.applied_events == 0 && jobs.jobs_run == 0 {
            return Ok(total);
        }
    }
}

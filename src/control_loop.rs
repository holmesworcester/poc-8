use crate::event_modules::Modules;
use crate::pipeline::{self, ApplyReadyReport};
use crate::store::Store;

pub const DEFAULT_READY_BATCH: usize = 4096;

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
) -> Result<ApplyReadyReport, String> {
    let mut total = ApplyReadyReport::default();
    loop {
        let report = drain_ready(store, modules, batch_size)?;
        total.applied_events += report.applied_events;
        total.unblocked_events += report.unblocked_events;
        if report.applied_events == 0 {
            return Ok(total);
        }
    }
}

//! Sync index worker.
//!
//! Input queue: `event_modules.applied_shared_events`.
//! Owned state: process-local `SyncIndex` negentropy/hash structure.
//! Output queues: none.
//! Ack: delete claimed applied-shared rows after they are inserted into the
//! in-memory index. A cold worker may rebuild from durable event indexes before
//! draining this queue.

use crate::core::store::Store;
use crate::protocol::event_modules::schema as event_schema;
use crate::workers::sync::SyncIndex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    Drain { limit: usize },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Report {
    pub indexed_events: usize,
}

pub fn run(store: &Store, index: &SyncIndex, work: Work) -> Result<Report, String> {
    match work {
        Work::Drain { limit } => {
            let applied = event_schema::claim_applied_shared_events(store, limit)
                .map_err(|err| format!("claim applied shared events: {err}"))?;
            let keys = applied
                .iter()
                .map(|event| event.key.clone())
                .collect::<Vec<_>>();
            let mut report = Report::default();
            for event in applied {
                if index.insert_entry(event.entry)? {
                    report.indexed_events += 1;
                }
            }
            if !keys.is_empty() {
                store
                    .delete_table_rows(event_schema::APPLIED_SHARED_EVENTS, keys)
                    .map_err(|err| format!("ack applied shared events: {err}"))?;
            }
            Ok(report)
        }
    }
}

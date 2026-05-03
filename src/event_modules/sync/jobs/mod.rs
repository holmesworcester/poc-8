pub mod queries;
pub mod tables;
pub mod types;

use crate::store::{EventId, Store};

use self::types::{SyncJobOutput, SyncWork};

const INDEX_BATCH: usize = 4096;

pub fn queue_start(connection_id: EventId, required_index_seq: u64) -> crate::store::TableRow {
    types::encode(SyncWork::Start {
        connection_id,
        required_index_seq,
    })
}

pub fn queue_inbound_frame(
    connection_id: EventId,
    required_index_seq: u64,
    frame_bytes: Vec<u8>,
) -> crate::store::TableRow {
    types::encode(SyncWork::InboundFrame {
        connection_id,
        required_index_seq,
        frame_bytes,
    })
}

pub fn next(store: &Store) -> Result<Option<SyncJobOutput>, String> {
    if let Some(output) = catch_up_index(store)? {
        return Ok(Some(output));
    }

    let Some(queued) = queries::next_work(store)? else {
        return Ok(None);
    };
    let cursor = super::negentropy::queries::cursor(store)?;
    if cursor < queued.work.required_index_seq() {
        return Ok(None);
    }

    let mut output = run_work(store, queued.work)?;
    output.deleted_rows.push(crate::store::TableRowDeletion {
        table: tables::WORK,
        key: queued.key,
    });
    Ok(Some(output))
}

pub fn catch_up_index(store: &Store) -> Result<Option<SyncJobOutput>, String> {
    let cursor = super::negentropy::queries::cursor(store)?;
    let entries = store
        .applied_shared_entries_after(cursor, INDEX_BATCH)
        .map_err(|err| format!("load applied events for sync index: {err}"))?;
    let Some(last) = entries.last() else {
        return Ok(None);
    };

    let (cursor_delete, cursor_row) = super::negentropy::queries::cursor_update(last.apply_seq);
    let mut rows = super::negentropy::queries::index_rows(&entries);
    rows.push(cursor_row);
    Ok(Some(SyncJobOutput {
        rows,
        deleted_rows: vec![cursor_delete],
        ..SyncJobOutput::default()
    }))
}

fn run_work(store: &Store, work: SyncWork) -> Result<SyncJobOutput, String> {
    match work {
        SyncWork::Start { connection_id, .. } => start(store, connection_id),
        SyncWork::InboundFrame {
            connection_id,
            frame_bytes,
            ..
        } => ingest_frame(store, connection_id, &frame_bytes),
    }
}

fn start(store: &Store, connection_id: EventId) -> Result<SyncJobOutput, String> {
    let mut events = Vec::new();
    let report = super::compare::commands::start(store, connection_id, |bytes| {
        events.push(super::frame::codec::record_from_bytes(bytes)?);
        Ok(())
    })?;
    Ok(SyncJobOutput {
        events,
        sent_events: report.sent_events,
        received_events: report.received_events,
        received_event_bytes: report.received_event_bytes,
        ..SyncJobOutput::default()
    })
}

fn ingest_frame(
    store: &Store,
    connection_id: EventId,
    frame_bytes: &[u8],
) -> Result<SyncJobOutput, String> {
    let mut events = Vec::new();
    let report =
        super::compare::commands::ingest_frame(store, connection_id, frame_bytes, |bytes| {
            events.push(super::frame::codec::record_from_bytes(bytes)?);
            Ok(())
        })?;
    Ok(SyncJobOutput {
        events,
        sent_events: report.sent_events,
        received_events: report.received_events,
        received_event_bytes: report.received_event_bytes,
        ..SyncJobOutput::default()
    })
}

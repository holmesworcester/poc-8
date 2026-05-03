use crate::blocking;
use crate::event_modules::Modules;
use crate::store::{
    event_id, CommandOutput, EventId, EventRecord, EventScope, EventStatus, ProjectionOutput, Store,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameMetadata {
    pub origin: std::net::SocketAddr,
    pub remember_origin: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IngestResult {
    pub outgoing: Vec<Vec<u8>>,
    pub sent_outbox: Vec<Vec<u8>>,
    pub queued_route: Option<EventId>,
    pub established_routes: usize,
    pub sent_events: usize,
    pub received_events: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AdmitReport {
    pub inserted_events: usize,
    pub ready_events: usize,
    pub blocked_events: usize,
    pub blocked_edges: usize,
    pub applied_events: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ApplyReadyReport {
    pub applied_events: usize,
    pub unblocked_events: usize,
}

pub fn apply_changes(
    store: &Store,
    modules: &Modules,
    changes: ProjectionOutput,
) -> Result<AdmitReport, String> {
    store
        .write_transaction(|store| {
            let mut report = AdmitReport::default();
            apply_changes_in_tx(store, modules, changes, &mut report)?;
            Ok(report)
        })
        .map_err(|err| format!("apply state changes: {err}"))
}

pub fn run_command<T>(
    store: &Store,
    modules: &Modules,
    output: CommandOutput<T>,
) -> Result<(T, AdmitReport), String> {
    let report = apply_event_records(store, modules, output.events)?;
    Ok((output.value, report))
}

pub fn apply_event_records(
    store: &Store,
    modules: &Modules,
    records: Vec<EventRecord>,
) -> Result<AdmitReport, String> {
    store
        .write_transaction(|store| {
            let mut report = AdmitReport::default();
            for record in records {
                admit_and_apply_record_in_tx(store, modules, &record, &mut report)?;
            }
            Ok(report)
        })
        .map_err(|err| format!("apply events: {err}"))
}

fn apply_changes_in_tx(
    store: &Store,
    _modules: &Modules,
    changes: ProjectionOutput,
    _report: &mut AdmitReport,
) -> rusqlite::Result<()> {
    store.delete_table_rows_in_tx(changes.deleted_rows)?;
    store.insert_table_rows_in_tx(changes.rows)?;
    Ok(())
}

fn admit_and_apply_record_in_tx(
    store: &Store,
    modules: &Modules,
    record: &EventRecord,
    report: &mut AdmitReport,
) -> rusqlite::Result<()> {
    if record.scope == EventScope::Connection {
        if !record.dependencies.is_empty() {
            return Err(module_error(
                "transient events cannot wait on durable dependencies".to_string(),
            ));
        }
        let changes = modules
            .project_record(store, record)
            .map_err(module_error)?;
        apply_changes_in_tx(store, modules, changes, report)?;
        report.applied_events += 1;
        return Ok(());
    }

    let admitted = admit_record_in_tx(store, record, report)?;
    if admitted.inserted && admitted.ready {
        let apply = apply_ready_event_in_tx(store, modules, &admitted.event_id)?;
        report.applied_events += apply.applied_events;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Admission {
    event_id: EventId,
    inserted: bool,
    ready: bool,
}

fn admit_record_in_tx(
    store: &Store,
    record: &EventRecord,
    report: &mut AdmitReport,
) -> rusqlite::Result<Admission> {
    let id = event_id(&record.canonical_bytes);
    let missing = blocking::missing_dependencies(store, &record.dependencies)?;
    let status = if missing.is_empty() {
        EventStatus::Ready
    } else {
        EventStatus::Blocked
    };

    let inserted = store.insert_event(record, status)?;
    if inserted {
        report.inserted_events += 1;
        if missing.is_empty() {
            report.ready_events += 1;
        } else {
            report.blocked_events += 1;
            report.blocked_edges += blocking::write_blockers(store, &id, &missing)?;
        }
    }
    Ok(Admission {
        event_id: id,
        inserted,
        ready: missing.is_empty(),
    })
}

pub fn apply_ready_event_in_tx(
    store: &Store,
    modules: &Modules,
    event_id: &EventId,
) -> rusqlite::Result<ApplyReadyReport> {
    let mut report = ApplyReadyReport::default();
    if store.set_event_status(event_id, EventStatus::Ready, EventStatus::Applied)? {
        let bytes = store
            .event_bytes(event_id)?
            .ok_or(rusqlite::Error::QueryReturnedNoRows)?;
        let record = modules.record_from_bytes(bytes).map_err(module_error)?;
        let changes = modules
            .project_record(store, &record)
            .map_err(module_error)?;
        let mut admitted = AdmitReport::default();
        apply_changes_in_tx(store, modules, changes, &mut admitted)?;
        report.applied_events = 1;
        report.unblocked_events = blocking::unblock_dependents(store, event_id)?;
    }
    Ok(report)
}

pub fn ingest_frame(
    store: &Store,
    modules: &Modules,
    metadata: FrameMetadata,
    bytes: Vec<u8>,
) -> Result<IngestResult, String> {
    let mut report =
        modules.ingest_frame(store, metadata.origin, metadata.remember_origin, bytes)?;
    report.events.extend(received_event_records(
        modules,
        report.received_event_bytes,
    )?);
    let queued_route = report.queued_route;
    let _admitted = store
        .write_transaction(|store| {
            let mut admitted = AdmitReport::default();
            for record in report.events {
                admit_and_apply_record_in_tx(store, modules, &record, &mut admitted)?;
            }
            Ok(admitted)
        })
        .map_err(|err| format!("apply ingested frame: {err}"))?;
    Ok(IngestResult {
        outgoing: report.outgoing,
        sent_outbox: Vec::new(),
        queued_route,
        established_routes: report.established_routes,
        sent_events: report.sent_events,
        received_events: report.received_events,
    })
}

fn received_event_records(
    modules: &Modules,
    events: Vec<Vec<u8>>,
) -> Result<Vec<EventRecord>, String> {
    if events.is_empty() {
        return Ok(Vec::new());
    }
    let mut records = Vec::with_capacity(events.len());
    for bytes in events {
        records.push(modules.record_from_bytes(bytes)?);
    }
    Ok(records)
}

fn module_error(err: String) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(err)
}

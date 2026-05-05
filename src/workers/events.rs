//! Common event-module worker.
//!
//! This module is the narrow gate between canonical event bytes and projected
//! protocol state. It is intentionally boring: admit an event, wait for its
//! dependencies, call exactly one projector through the registry, and write the
//! row-shaped output the projector returned. That shape is the defense against
//! the kernel becoming a second protocol implementation.
//!
//! The worker does not know what any concrete event family means. Those meanings
//! live in event modules. The worker only knows the protocol-wide mechanics that
//! every canonical event shares:
//!
//! ```text
//! command -> ProposedEvent
//!          -> admit canonical bytes by deterministic event id
//!          -> block until dependency event ids are applied
//!          -> project ready events into rows and labels
//!          -> mark newly unblocked events ready
//! ```
//!
//! Network input follows the same rule from the other side. A domain worker
//! interprets opaque inbound bytes, and any surviving canonical event records
//! come back here for ordinary admission. Network output is kept outside
//! projection as well: projectors may write protocol queue rows, and a domain
//! worker later turns those rows into opaque transport rows.
//!
//! Future maintainers should be suspicious of changes that make this file more
//! knowledgeable. Domain-specific branching here is usually a sign that an event
//! module is missing a codec, projector, command, query, table, or domain worker.
//! The important invariant is not that this file stays tiny; it is that it stays
//! mechanical enough to audit.
//!
//! If you are trying to understand the code path, start with `run` and then
//! follow `run_admission_pipeline`. The heart of the file is
//! `process_event_in_tx`, the one-event pipeline:
//!
//! ```text
//! process_event_in_tx
//!   if transient:
//!     project_transient_event_in_tx
//!   else:
//!     store_durable_event_in_tx
//!     if newly inserted and ready:
//!       project_ready_event_in_tx
//!         -> load_event_context_in_tx
//!         -> write_projection_output_in_tx
//!         -> unblock_dependents
//! ```
//!
//! Every other helper exists to make one of those verbs precise. A good change
//! should make that call tree shorter, clearer, or more obviously correct. A
//! suspicious change adds a second path that stores, projects, unblocks, or sends
//! around this path.

use crate::core::store::{Store, TableRow};
use crate::protocol::event_modules::types::{
    event_id, EventId, EventRecord, EventStatus, ReceiveMetadata,
};

use crate::protocol::event_modules::schema;

/// Default upper bound for one ready-event drain.
///
/// This is a scheduling guard, not part of event semantics. A caller can choose
/// a smaller batch to improve fairness or a larger batch to reduce loop
/// overhead; the result must be the same as long as ready events are eventually
/// drained.
pub const DEFAULT_READY_BATCH: usize = 4096;

/// Canonical event proposed by a command before admission.
///
/// Commands are allowed to decide *what event should exist*. They are not
/// allowed to write event rows, projection rows, queue rows, or network rows.
/// `ProposedEvent` keeps the command boundary ergonomic while still making the
/// deterministic event id available immediately for command chaining and CLI
/// output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposedEvent {
    event_id: EventId,
    record: EventRecord,
    receive: Option<ReceiveMetadata>,
}

impl ProposedEvent {
    pub fn new(record: EventRecord) -> Self {
        Self {
            event_id: event_id(&record.canonical_bytes),
            record,
            receive: None,
        }
    }

    fn contextual(record: EventRecord, receive: Option<ReceiveMetadata>) -> Self {
        Self {
            event_id: event_id(&record.canonical_bytes),
            record,
            receive,
        }
    }

    pub fn event_id(&self) -> EventId {
        self.event_id
    }

    pub fn record(&self) -> &EventRecord {
        &self.record
    }

    fn receive(&self) -> Option<ReceiveMetadata> {
        self.receive
    }

    pub fn into_record(self) -> EventRecord {
        self.record
    }
}

impl From<EventRecord> for ProposedEvent {
    fn from(record: EventRecord) -> Self {
        Self::new(record)
    }
}

/// Declarative output of a projector.
///
/// A projector may only return rows in protocol-owned state: ordinary table rows
/// and generic event labels. It may not emit more events, call a worker, send
/// bytes, or query broad state. If projection appears to need one of those
/// powers, the event module should write a queue row and let its domain worker
/// perform the active step later.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectionOutput {
    pub rows: Vec<TableRow>,
    pub labels: Vec<schema::EventLabel>,
}

impl ProjectionOutput {
    pub fn rows(rows: Vec<TableRow>) -> Self {
        Self {
            rows,
            labels: Vec::new(),
        }
    }

    pub fn labels(labels: Vec<schema::EventLabel>) -> Self {
        Self {
            rows: Vec::new(),
            labels,
        }
    }

    pub fn rows_and_labels(rows: Vec<TableRow>, labels: Vec<schema::EventLabel>) -> Self {
        Self { rows, labels }
    }

    pub fn append(&mut self, mut other: Self) {
        self.rows.append(&mut other.rows);
        self.labels.append(&mut other.labels);
    }
}

/// One immediate dependency loaded as generic projector context.
///
/// Dependency context contains the event id and the decoded record. It is
/// intentionally shallow: only dependencies named by the event are loaded here.
/// Deeper walks belong in a domain worker or a module-owned indexed table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyContext {
    pub event_id: EventId,
    pub record: EventRecord,
}

/// Generic context every projector receives.
///
/// This is the default context promised by the protocol plan: the current event
/// id, its immediate dependency records, and bounded labels attached to the
/// current event id. If a projector seems to need arbitrary SQL, first ask
/// whether the needed fact should be a dependency, a label, or a module-owned
/// read model consumed by a worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventContext {
    pub event_id: EventId,
    pub dependencies: Vec<DependencyContext>,
    pub labels: Vec<Vec<u8>>,
    pub receive: Option<ReceiveMetadata>,
}

impl EventContext {
    pub fn dependency(&self, event_id: &EventId) -> Option<&EventRecord> {
        self.dependencies
            .iter()
            .find(|dependency| &dependency.event_id == event_id)
            .map(|dependency| &dependency.record)
    }

    pub fn has_label(&self, label: &[u8]) -> bool {
        self.labels.iter().any(|candidate| candidate == label)
    }
}

/// Event record plus the generic context fetched by the worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventWithContext<'a> {
    pub record: &'a EventRecord,
    pub context: EventContext,
}

/// Result of a command: a value for the caller plus proposed events to admit.
///
/// The value is command-local information such as a created id, a status report,
/// or bytes that are intentionally not canonical events. The events are the only
/// durable state change path. The API running a command is responsible for
/// admitting them through this worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput<T> {
    pub value: T,
    pub events: Vec<ProposedEvent>,
}

impl<T> CommandOutput<T> {
    pub fn new(value: T) -> Self {
        Self {
            value,
            events: Vec::new(),
        }
    }

    pub fn with_events(value: T, events: Vec<EventRecord>) -> Self {
        Self {
            value,
            events: events.into_iter().map(ProposedEvent::new).collect(),
        }
    }

    pub fn with_proposed_events(value: T, events: Vec<ProposedEvent>) -> Self {
        Self { value, events }
    }

    pub fn prepend_events(mut self, mut events: Vec<ProposedEvent>) -> Self {
        events.append(&mut self.events);
        self.events = events;
        self
    }
}

/// Protocol registry used by the common worker.
///
/// This trait is the only place where the generic admission/apply loop touches
/// concrete event modules. `record_from_bytes` chooses the module codec.
/// `project_record` chooses the module projector and receives the
/// `EventWithContext` already loaded by this worker. Keeping those decisions
/// behind the registry lets this worker enforce common mechanics without
/// learning event-type vocabulary.
pub trait EventRegistry {
    fn record_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String>;
    fn project_record(
        &self,
        store: &Store,
        event: &EventWithContext<'_>,
    ) -> Result<ProjectionOutput, String>;
}

/// Unit of work accepted by the worker runner.
///
/// Work values are small boundary objects: "admit these records", "drain ready
/// events", or another worker-specific wake. They keep callers from reaching into
/// helper functions and make the public entrypoint read like a scheduler.
pub trait Work<R: EventRegistry> {
    type Output;

    fn execute(self, store: &Store, registry: &R) -> Result<Self::Output, String>;
}

/// Admit already-decoded records through normal dependency handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmitRecords {
    pub records: Vec<EventRecord>,
}

/// Admit records with receive-boundary context.
///
/// Public commands admit canonical records. Connection worker is the boundary
/// that turns authenticated inbound bytes into receive context, so this work
/// item and its records are only constructible inside the crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmitReceivedRecords {
    pub(crate) records: Vec<ReceivedRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedRecord {
    record: EventRecord,
    receive: Option<ReceiveMetadata>,
}

impl ReceivedRecord {
    pub(crate) fn new(record: EventRecord) -> Self {
        Self {
            record,
            receive: None,
        }
    }

    pub(crate) fn with_receive(record: EventRecord, receive: ReceiveMetadata) -> Self {
        Self {
            record,
            receive: Some(receive),
        }
    }
}

/// Admit a command output and drain ready durable events after admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmitAndDrain<T> {
    pub output: CommandOutput<T>,
    pub batch_size: usize,
}

/// Drain ready durable events until no ready event remains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainUntilIdle {
    pub batch_size: usize,
}

/// Drain at most one batch of ready durable events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainReadyBatch {
    pub batch_size: usize,
}

/// Summary of event admission and any immediately-applied events.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdmitReport {
    pub event_ids: Vec<EventId>,
    pub inserted_events: usize,
    pub ready_events: usize,
    pub blocked_events: usize,
    pub blocked_edges: usize,
    pub applied_events: usize,
}

/// Summary of a ready-event drain.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ApplyReadyReport {
    pub applied_events: usize,
    pub unblocked_events: usize,
}

/// Summary of command admission followed by a ready-event drain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmitAndDrainReport<T> {
    pub value: T,
    pub admitted: AdmitReport,
    pub drained: ApplyReadyReport,
}

/// Run one common event-module worker action.
///
/// The single public function is deliberate. If a caller needs another behavior,
/// add a `Work` value that names the behavior instead of exporting a helper. This
/// keeps the admission/apply boundary small enough to reason about from tests and
/// static checks.
pub fn run<R, W>(store: &Store, registry: &R, work: W) -> Result<W::Output, String>
where
    R: EventRegistry,
    W: Work<R>,
{
    work.execute(store, registry)
}

impl<T, R> Work<R> for CommandOutput<T>
where
    R: EventRegistry,
{
    type Output = (T, AdmitReport);

    fn execute(self, store: &Store, registry: &R) -> Result<Self::Output, String> {
        admit_command_output(store, registry, self)
    }
}

impl<T, R> Work<R> for AdmitAndDrain<T>
where
    R: EventRegistry,
{
    type Output = AdmitAndDrainReport<T>;

    fn execute(self, store: &Store, registry: &R) -> Result<Self::Output, String> {
        let (value, admitted) = admit_command_output(store, registry, self.output)?;
        let drained = drain_until_idle(store, registry, self.batch_size)?;
        Ok(AdmitAndDrainReport {
            value,
            admitted,
            drained,
        })
    }
}

impl<R> Work<R> for AdmitRecords
where
    R: EventRegistry,
{
    type Output = AdmitReport;

    fn execute(self, store: &Store, registry: &R) -> Result<Self::Output, String> {
        admit_records(store, registry, self.records)
    }
}

impl<R> Work<R> for AdmitReceivedRecords
where
    R: EventRegistry,
{
    type Output = AdmitReport;

    fn execute(self, store: &Store, registry: &R) -> Result<Self::Output, String> {
        run_admission_pipeline(
            store,
            registry,
            self.records
                .into_iter()
                .map(|received| ProposedEvent::contextual(received.record, received.receive))
                .collect(),
        )
    }
}

impl<R> Work<R> for DrainUntilIdle
where
    R: EventRegistry,
{
    type Output = ApplyReadyReport;

    fn execute(self, store: &Store, registry: &R) -> Result<Self::Output, String> {
        drain_until_idle(store, registry, self.batch_size)
    }
}

impl<R> Work<R> for DrainReadyBatch
where
    R: EventRegistry,
{
    type Output = ApplyReadyReport;

    fn execute(self, store: &Store, registry: &R) -> Result<Self::Output, String> {
        drain_ready(store, registry, self.batch_size)
    }
}

// ---------------------------------------------------------------------------
// Canonical event pipeline
// ---------------------------------------------------------------------------

fn admit_command_output<T>(
    store: &Store,
    modules: &impl EventRegistry,
    output: CommandOutput<T>,
) -> Result<(T, AdmitReport), String> {
    let report = run_admission_pipeline(store, modules, output.events)?;
    Ok((output.value, report))
}

fn admit_records(
    store: &Store,
    modules: &impl EventRegistry,
    records: Vec<EventRecord>,
) -> Result<AdmitReport, String> {
    run_admission_pipeline(
        store,
        modules,
        records.into_iter().map(ProposedEvent::new).collect(),
    )
}

/// Run the batch-level admission pipeline in one store transaction.
///
/// This function gives callers the useful atomic unit: either all proposed
/// events in the batch are admitted/projected as far as their dependencies allow,
/// or none of the batch is. The per-event logic is intentionally delegated to
/// `process_event_in_tx`; this helper owns transaction shape, not event meaning.
///
/// SQLite reads its own writes within this transaction, and the worker relies on
/// that. A command may propose a parent followed by a child; the parent can be
/// inserted, projected, and made visible to the child's dependency check before
/// the batch commits. Splitting this into one transaction per event would be
/// simpler only superficially: it would give up atomic command output and add
/// commit overhead without improving the semantics.
fn run_admission_pipeline(
    store: &Store,
    modules: &impl EventRegistry,
    events: Vec<ProposedEvent>,
) -> Result<AdmitReport, String> {
    store
        .write_transaction(|store| {
            let mut report = AdmitReport::default();
            process_event_batch_in_tx(store, modules, events, &mut report)?;
            Ok(report)
        })
        .map_err(|err| format!("admit events: {err}"))
}

/// Process a caller-ordered event batch inside an existing transaction.
///
/// Order matters for command chaining: if a command proposes parent then child
/// in one output, the child sees the parent as already applied when possible.
fn process_event_batch_in_tx(
    store: &Store,
    modules: &impl EventRegistry,
    events: Vec<ProposedEvent>,
    report: &mut AdmitReport,
) -> rusqlite::Result<()> {
    for event in events {
        process_event_in_tx(store, modules, &event, report)?;
    }
    Ok(())
}

/// Process one proposed event.
///
/// This is the core pipeline. It has exactly two branches:
///
/// 1. Transient records are projected immediately and never inserted into the
///    durable event table.
/// 2. Durable records are inserted by deterministic id, blocked if dependencies
///    are missing, and projected only if this insertion made them ready.
///
/// Duplicate durable events stop after insertion returns `inserted = false`.
/// They do not re-project, rewrite blockers, or re-run module code.
fn process_event_in_tx(
    store: &Store,
    modules: &impl EventRegistry,
    event: &ProposedEvent,
    report: &mut AdmitReport,
) -> rusqlite::Result<()> {
    let record = event.record();
    report.event_ids.push(event.event_id());
    if !record.scope.is_durable() {
        project_transient_event_in_tx(store, modules, record, event.receive())?;
        report.applied_events += 1;
        return Ok(());
    }

    let stored = store_durable_event_in_tx(store, event, report)?;
    if stored.inserted && stored.ready {
        let apply = if event.receive().is_some() {
            project_ready_event_record_in_tx(
                store,
                modules,
                &stored.event_id,
                record,
                event.receive(),
            )?
        } else {
            project_ready_event_in_tx(store, modules, &stored.event_id)?
        };
        report.applied_events += apply.applied_events;
    }
    Ok(())
}

fn project_transient_event_in_tx(
    store: &Store,
    modules: &impl EventRegistry,
    record: &EventRecord,
    receive: Option<ReceiveMetadata>,
) -> rusqlite::Result<()> {
    // Transient events are canonical enough to project and dedupe inside the
    // current process, but they are not durable facts. Letting them wait on
    // durable dependencies would create hidden state that cannot be resumed
    // after a crash.
    if !record.dependencies.is_empty() {
        return Err(module_error(
            "transient events cannot wait on durable dependencies".to_string(),
        ));
    }
    let event_id = event_id(&record.canonical_bytes);
    let changes = project_event_with_context_in_tx(store, modules, &event_id, record, receive)?;
    write_projection_output_in_tx(store, changes)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StoredDurableEvent {
    event_id: EventId,
    inserted: bool,
    ready: bool,
}

/// Insert a durable event row and, if blocked, the exact missing-dependency rows.
///
/// This helper does not project. It only records whether the event is new and
/// whether it is ready, so the caller can decide if projection is allowed.
fn store_durable_event_in_tx(
    store: &Store,
    event: &ProposedEvent,
    report: &mut AdmitReport,
) -> rusqlite::Result<StoredDurableEvent> {
    let record = event.record();
    let id = event.event_id();
    let missing = missing_dependencies(store, &record.dependencies)?;
    if event.receive().is_some() && !missing.is_empty() {
        return Err(module_error(
            "durable receive metadata cannot be preserved while blocked".to_string(),
        ));
    }
    let status = if missing.is_empty() {
        EventStatus::Ready
    } else {
        EventStatus::Blocked
    };

    let inserted = schema::insert_event(store, record, status)?;
    if inserted {
        report.inserted_events += 1;
        if missing.is_empty() {
            report.ready_events += 1;
        } else {
            report.blocked_events += 1;
            report.blocked_edges += write_blockers(store, &id, &missing)?;
        }
    }
    Ok(StoredDurableEvent {
        event_id: id,
        inserted,
        ready: missing.is_empty(),
    })
}

/// Claim and project one ready durable event.
///
/// Projection is coupled to the Ready -> Applied status change. That makes the
/// operation idempotent under retry: if another caller already claimed the event,
/// this helper reports no work instead of running the projector twice.
///
/// The status change, context load, projector call, row writes, and dependent
/// unblocking all happen in the caller's transaction. If projection fails, the
/// Applied status rolls back, so failed events cannot become dependency context
/// for later projectors.
fn project_ready_event_in_tx(
    store: &Store,
    modules: &impl EventRegistry,
    event_id: &EventId,
) -> rusqlite::Result<ApplyReadyReport> {
    let mut report = ApplyReadyReport::default();
    if schema::set_event_status(store, event_id, EventStatus::Ready, EventStatus::Applied)? {
        // The status change is the claim. Projection runs only for the worker
        // that successfully moved Ready -> Applied, which keeps duplicate drain
        // attempts idempotent when callers retry.
        let bytes =
            schema::event_bytes(store, event_id)?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
        let record = modules.record_from_bytes(bytes).map_err(module_error)?;
        let changes = project_event_with_context_in_tx(store, modules, event_id, &record, None)?;
        write_projection_output_in_tx(store, changes)?;
        report.applied_events = 1;
        report.unblocked_events = unblock_dependents(store, event_id)?;
    }
    Ok(report)
}

fn project_ready_event_record_in_tx(
    store: &Store,
    modules: &impl EventRegistry,
    event_id: &EventId,
    record: &EventRecord,
    receive: Option<ReceiveMetadata>,
) -> rusqlite::Result<ApplyReadyReport> {
    let mut report = ApplyReadyReport::default();
    if schema::set_event_status(store, event_id, EventStatus::Ready, EventStatus::Applied)? {
        let changes = project_event_with_context_in_tx(store, modules, event_id, record, receive)?;
        write_projection_output_in_tx(store, changes)?;
        report.applied_events = 1;
        report.unblocked_events = unblock_dependents(store, event_id)?;
    }
    Ok(report)
}

/// Load generic context and call the registry projector.
///
/// This is the `get_context -> project` part of the pipeline. The worker always
/// loads the protocol-wide context first so leaf projectors can stay pure
/// functions over event bytes plus bounded facts.
fn project_event_with_context_in_tx(
    store: &Store,
    modules: &impl EventRegistry,
    event_id: &EventId,
    record: &EventRecord,
    receive: Option<ReceiveMetadata>,
) -> rusqlite::Result<ProjectionOutput> {
    let context = load_event_context_in_tx(store, modules, event_id, record, receive)?;
    let event = EventWithContext { record, context };
    modules.project_record(store, &event).map_err(module_error)
}

/// Fetch the generic context shared by all projectors.
///
/// The dependency list comes from the event itself and is safe to load here
/// because blocked durable events do not reach projection. Admission only marks
/// an event Ready after every dependency is Applied, so context never includes
/// merely stored or failed events. Labels are generic, bounded facts attached to
/// this event id by earlier projections.
fn load_event_context_in_tx(
    store: &Store,
    modules: &impl EventRegistry,
    event_id: &EventId,
    record: &EventRecord,
    receive: Option<ReceiveMetadata>,
) -> rusqlite::Result<EventContext> {
    let mut dependencies = Vec::with_capacity(record.dependencies.len());
    for dependency in unique_dependencies(&record.dependencies) {
        let bytes =
            schema::event_bytes(store, &dependency)?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
        let record = modules.record_from_bytes(bytes).map_err(module_error)?;
        dependencies.push(DependencyContext {
            event_id: dependency,
            record,
        });
    }
    Ok(EventContext {
        event_id: *event_id,
        dependencies,
        labels: schema::event_labels(store, event_id).map_err(module_error)?,
        receive,
    })
}

fn write_projection_output_in_tx(
    store: &Store,
    changes: ProjectionOutput,
) -> rusqlite::Result<usize> {
    let rows = store.insert_table_rows_in_tx(changes.rows)?;
    let labels = store.insert_table_rows_in_tx(schema::event_label_rows(changes.labels))?;
    Ok(rows + labels)
}

fn drain_ready(
    store: &Store,
    modules: &impl EventRegistry,
    limit: usize,
) -> Result<ApplyReadyReport, String> {
    store
        .write_transaction(|store| {
            let mut total = ApplyReadyReport::default();
            while total.applied_events < limit {
                let Some(event_id) = schema::next_ready_event(store)? else {
                    break;
                };
                let report = project_ready_event_in_tx(store, modules, &event_id)?;
                total.applied_events += report.applied_events;
                total.unblocked_events += report.unblocked_events;
            }
            Ok(total)
        })
        .map_err(|err| format!("drain ready events: {err}"))
}

fn drain_until_idle(
    store: &Store,
    modules: &impl EventRegistry,
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

fn module_error(err: String) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(err)
}

fn missing_dependencies(store: &Store, dependencies: &[EventId]) -> rusqlite::Result<Vec<EventId>> {
    let mut missing = Vec::new();
    for dependency in unique_dependencies(dependencies) {
        if !schema::event_is_applied(store, &dependency)? {
            missing.push(dependency);
        }
    }
    Ok(missing)
}

fn unique_dependencies(dependencies: &[EventId]) -> Vec<EventId> {
    let mut dependencies = dependencies.to_vec();
    dependencies.sort();
    dependencies.dedup();
    dependencies
}

fn write_blockers(
    store: &Store,
    event_id: &EventId,
    missing: &[EventId],
) -> rusqlite::Result<usize> {
    let mut inserted = 0;
    for dependency in missing {
        inserted += usize::from(schema::insert_blocked_event_missing_dep(
            store, dependency, event_id,
        )?);
    }
    Ok(inserted)
}

fn unblock_dependents(store: &Store, applied_event_id: &EventId) -> rusqlite::Result<usize> {
    let dependents = schema::blocked_events_by_missing_dep(store, applied_event_id)?;
    schema::delete_blocked_events_by_missing_dep(store, applied_event_id)?;

    let mut unblocked = 0;
    for dependent in dependents {
        // Unblocking only changes status. It does not recursively project the
        // newly unblocked event inside the same stack frame, which prevents a large
        // dependency cascade from becoming one unbounded transaction.
        if !schema::blocked_event_has_missing_deps(store, &dependent)?
            && schema::set_event_status(
                store,
                &dependent,
                EventStatus::Blocked,
                EventStatus::Ready,
            )?
        {
            unblocked += 1;
        }
    }
    Ok(unblocked)
}

//! Common event pipeline.
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
//! Transit input follows the same rule from the other side, but through an
//! explicit queue: `transit_in` interprets opaque inbound bytes with the
//! protocol registry and writes surviving canonical bytes to `canonical.in`.
//! The event-admission worker drains that queue back into the same one-event
//! helper used by local command batches. Network output is kept outside
//! projection as well: projectors may write protocol queue rows, and a domain
//! worker later turns those rows into opaque transport rows.
//!
//! Future maintainers should be suspicious of changes that make this file more
//! knowledgeable. Domain-specific branching here is usually a sign that an event
//! module is missing a codec, projector, command, query, table, or domain worker.
//! The important invariant is not that this file stays tiny; it is that it stays
//! mechanical enough to audit.
//!
//! If you are trying to understand the code path, start with `run`, then follow
//! the `Work` implementation for the call site. The heart of the file is
//! `process_proposed_event_tx`, the one-event pipeline:
//!
//! ```text
//! process_proposed_event_tx
//!   if transient:
//!     project_transient_event_tx
//!   else:
//!     store_durable_event_tx
//!     if newly inserted and ready:
//!       project_ready_event_tx
//!         -> load_event_context_in_tx
//!         -> write_projection_output_in_tx
//!         -> write_applied_event_outputs_in_tx
//! dependency_unblock later consumes recently-valid rows and marks dependents
//! ready without recursively projecting inside the admission transaction.
//! ```
//!
//! Every other helper exists to make one of those verbs precise. A good change
//! should make that call tree shorter, clearer, or more obviously correct. A
//! suspicious change adds a second path that stores, projects, unblocks, or sends
//! around this path.
//!
//! Scheduling: this file exposes bounded worker-compatible `Work` values.
//! CLI and daemon call sites choose the order in which admission, projection,
//! and dependency unblock steps run. Each public work item is bounded by a batch
//! size or by the number of proposed command events.
//!
//! Inputs: command outputs, decoded records, received records, transit input,
//! and selected compatibility drain work supplied by CLI/test call sites.
//! State: durable event rows, ready/blocker indexes, generic labels, and worker
//! queue rows declared in `workers::schema`.
//! Step: admit local canonical records directly, drain queued canonical transit
//! records, project ready durable events, or run bounded compatibility drains
//! according to the supplied work item.
//! Outputs: durable event rows, projector rows/labels, `canonical.in`,
//! `event_modules.ready_events`, `event_modules.recently_valid_events`, and
//! `event_modules.applied_shared_events`.
//! Consume: queue rows are deleted only after the relevant event is accepted,
//! rejected, projected, or dependency unblock is applied.
//! Failure: rejected `canonical_in` rows are consumed; projection failures leave
//! ready events ready for retry; transaction rollback preserves unconsumed queue
//! state.
//! Fairness: explicit workers are batch-limited; compatibility helpers are
//! bounded by command event count or caller-provided batch size.

use crate::core::network_queues::{self, InboundNetworkRow};
use crate::core::store::{Store, TableName, TableRow};
use crate::protocol::event_modules::types::{
    event_id, EventId, EventIndexEntry, EventRecord, EventStatus, ReceiveMetadata,
};

use crate::protocol::event_modules::schema;
use crate::protocol::workers::dependency_unblock;
use crate::protocol::workers::pipeline_helpers::event_lifecycle;
use crate::protocol::workers::schema as worker_schema;

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

/// One exact row deletion requested by a projector.
///
/// This is still row-shaped output, not an imperative storage escape hatch.
/// Projectors choose keys from event bytes and context; the common worker owns
/// applying the delete in the same transaction as row/label writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableDelete {
    pub table: TableName,
    pub key: Vec<u8>,
}

/// Declarative output of a projector.
///
/// A projector may only return rows in protocol-owned state: ordinary table
/// rows, exact row deletes, and generic event labels. It may not emit more
/// events, call a worker, send bytes, or query broad state. If projection
/// appears to need one of those powers, the event module should write a queue
/// row and let its domain worker perform the active step later.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectionOutput {
    pub rows: Vec<TableRow>,
    pub deletes: Vec<TableDelete>,
    pub labels: Vec<schema::EventLabel>,
}

impl ProjectionOutput {
    pub fn rows(rows: Vec<TableRow>) -> Self {
        Self {
            rows,
            deletes: Vec::new(),
            labels: Vec::new(),
        }
    }

    pub fn deletes(deletes: Vec<TableDelete>) -> Self {
        Self {
            rows: Vec::new(),
            deletes,
            labels: Vec::new(),
        }
    }

    pub fn labels(labels: Vec<schema::EventLabel>) -> Self {
        Self {
            rows: Vec::new(),
            deletes: Vec::new(),
            labels,
        }
    }

    pub fn rows_and_labels(rows: Vec<TableRow>, labels: Vec<schema::EventLabel>) -> Self {
        Self {
            rows,
            deletes: Vec::new(),
            labels,
        }
    }

    pub fn deletes_and_labels(deletes: Vec<TableDelete>, labels: Vec<schema::EventLabel>) -> Self {
        Self {
            rows: Vec::new(),
            deletes,
            labels,
        }
    }

    pub fn append(&mut self, mut other: Self) {
        self.rows.append(&mut other.rows);
        self.deletes.append(&mut other.deletes);
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
///
/// `now_unix_minute` is the local logical clock at projection time, expressed
/// as `floor(logical_time_ms / UNIX_MINUTE_MS)`. Projectors use it to make
/// time-sensitive decisions (e.g. message disappearing-expiry) without
/// reaching into storage themselves. `None` means the clock is not pinned —
/// projectors must treat that as "no time-based decision is safe to make."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventContext {
    pub event_id: EventId,
    pub dependencies: Vec<DependencyContext>,
    pub labels: Vec<Vec<u8>>,
    pub receive: Option<ReceiveMetadata>,
    pub now_unix_minute: Option<u64>,
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

/// Decision returned by the registry's receive-side admission gate.
///
/// The gate runs after `record_from_canonical_in` has decoded a receive-side
/// event into an `EventRecord` but before any storage write. It exists to let
/// modules drop events that should not be re-admitted — for example, message
/// events whose ids are already tombstoned, or whose stamped expiry is past.
/// Locally-authored events do not pass through this gate.
///
/// The `WriteRowsAndDrop` variant lets a module record the drop (e.g. by
/// writing a tombstone row) while still skipping the canonical-bytes /
/// admitted-event-index insert. Rows are inserted in the same transaction as
/// the queue consume, so a crash before commit replays the drop on the next
/// tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmitDecision {
    /// Continue the normal admit path: store canonical bytes, project, etc.
    Admit,
    /// Drop the event silently. No storage writes; the canonical_in row is
    /// still consumed so the queue makes progress.
    Drop,
    /// Drop the event, but first insert these rows in the same transaction.
    /// Used to write a `MESSAGE_TOMBSTONES` row when the gate decides an
    /// expired-at-receive message should never have been admitted.
    WriteRowsAndDrop(Vec<TableRow>),
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

    /// Receive-side admission gate.
    ///
    /// Called by the common pipeline for every received record after the
    /// codec has decoded canonical bytes into an `EventRecord` but before
    /// the record has been stored or projected. The gate returns `Admit`
    /// for the normal path; `Drop` to silently discard; or
    /// `WriteRowsAndDrop(rows)` to record the drop with a row write
    /// (e.g. a tombstone) and then discard.
    ///
    /// Locally-authored events do not pass through this gate. Their
    /// canonical-bytes hash already dedupes double-admit attempts; the
    /// gate's job is to defend the receive side from re-admitting events
    /// that local state has already retired.
    ///
    /// The default returns `Admit`.
    fn admit_received_record(
        &self,
        _store: &Store,
        _record: &EventRecord,
    ) -> Result<AdmitDecision, String> {
        Ok(AdmitDecision::Admit)
    }

    /// Project one opaque network row into ordinary worker rows.
    ///
    /// The daemon calls this only through `transit_in`. Protocols that use
    /// encrypted transit envelopes return `canonical.in` rows carrying the
    /// recovered inner bytes and provenance. The common pipeline later admits
    /// those rows with the same dependency, projector, and block/unblock rules
    /// as command-created events.
    fn project_network_in(
        &self,
        _store: &Store,
        _inbound: &InboundNetworkRow,
    ) -> Result<ProjectionOutput, String> {
        Err("event registry does not handle network input".to_string())
    }

    fn record_from_canonical_in(
        &self,
        _store: &Store,
        bytes: Vec<u8>,
        receive: Option<ReceiveMetadata>,
        provenance: Option<worker_schema::TransitProvenance>,
    ) -> Result<ReceivedRecord, String> {
        // The default path is for command-created rows and already-classified
        // local rows. Protocols with envelope boundaries override this method
        // so provenance can decide which receive context, if any, should
        // accompany the canonical bytes into projection.
        if provenance.is_some() {
            return Err("event registry does not handle provenance".to_string());
        }
        let record = self.record_from_bytes(bytes)?;
        Ok(ReceivedRecord { record, receive })
    }

    fn project_record(
        &self,
        store: &Store,
        event: &EventWithContext<'_>,
    ) -> Result<ProjectionOutput, String>;

    /// Run any protocol-specific post-admission drains.
    ///
    /// Called by the common pipeline after any admission path finishes its
    /// own `drain_until_idle`. Protocols may use this hook to fire bounded,
    /// row-triggered worker drains so an in-process CLI admission path
    /// reaches the same end state as a daemon tick before returning to the
    /// caller. The default is a no-op so most protocols pay nothing for the
    /// hook.
    ///
    /// The hook must be bounded and pure operational work: it observes
    /// projector-emitted indicator rows and dispatches to a worker. It must
    /// not invent new semantic events or branch on event type. The pipeline
    /// is intentionally generic: it does not know which workers a protocol
    /// might want to drain here.
    fn post_admission_hook(&self, _store: &Store) -> Result<(), String> {
        Ok(())
    }
}

/// Unit of work accepted by the worker runner.
///
/// Work values are small boundary objects: "admit these records", "drain ready
/// events", or another worker-specific input. They keep callers from reaching into
/// helper functions and make the public entrypoint read like a caller-selected
/// worker step.
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
/// Public commands admit canonical records. Network admission is the boundary
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
    pub network_frames: usize,
    pub event_ids: Vec<EventId>,
    pub inserted_events: usize,
    pub ready_events: usize,
    pub blocked_events: usize,
    pub blocked_edges: usize,
    pub applied_events: usize,
}

/// Summary of inbound transit frame handling.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransitInReport {
    pub network_frames: usize,
    pub canonical_rows: usize,
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

/// Run one common event pipeline action.
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PipelineStepReport {
    pub admitted: AdmitReport,
    pub drained: ApplyReadyReport,
}

pub(crate) fn enqueue_proposed_events(
    store: &Store,
    events: Vec<ProposedEvent>,
) -> Result<usize, String> {
    let rows = events
        .into_iter()
        .map(|event| worker_schema::canonical_in_row(event.record, event.receive))
        .collect();
    store
        .insert_table_rows(rows)
        .map_err(|err| format!("enqueue canonical in: {err}"))
}

pub(crate) fn drain_canonical_in<R>(
    store: &Store,
    registry: &R,
    limit: usize,
) -> Result<AdmitReport, String>
where
    R: EventRegistry,
{
    let input = worker_schema::claim_canonical_in(store, limit)
        .map_err(|err| format!("claim canonical in: {err}"))?;
    let mut total = AdmitReport::default();
    for canonical in input {
        let key = canonical.key;
        let bytes = canonical.canonical_bytes;
        let receive = canonical.receive;
        let provenance = canonical.provenance;
        let result = store.write_transaction(|store| {
            let mut report = AdmitReport::default();
            let received = registry
                .record_from_canonical_in(store, bytes.clone(), receive, provenance)
                .map_err(module_error)?;
            let decision = registry
                .admit_received_record(store, &received.record)
                .map_err(module_error)?;
            match decision {
                AdmitDecision::Admit => {
                    let proposed =
                        ProposedEvent::contextual(received.record, received.receive);
                    process_proposed_event_tx(store, registry, &proposed, &mut report)?;
                }
                AdmitDecision::Drop => {
                    report.event_ids.push(event_id(&received.record.canonical_bytes));
                }
                AdmitDecision::WriteRowsAndDrop(rows) => {
                    report.event_ids.push(event_id(&received.record.canonical_bytes));
                    store.insert_table_rows_in_tx(rows)?;
                }
            }
            store.delete_table_rows_in_tx(worker_schema::CANONICAL_IN, vec![key.clone()])?;
            Ok(report)
        });
        match result {
            Ok(report) => merge_admit_report(&mut total, report),
            Err(err) => {
                store
                    .delete_table_rows(worker_schema::CANONICAL_IN, vec![key])
                    .map_err(|delete_err| {
                        format!(
                            "drain canonical in: {err}; failed to consume rejected event: {delete_err}"
                        )
                    })?;
                return Err(format!("drain canonical in: {err}"));
            }
        }
    }
    if total.inserted_events > 0 || total.applied_events > 0 {
        registry.post_admission_hook(store)?;
    }
    Ok(total)
}

pub(crate) fn drain_transit_in<R>(
    store: &Store,
    registry: &R,
    limit: usize,
) -> Result<TransitInReport, String>
where
    R: EventRegistry,
{
    let input = network_queues::claim_inbound(store, limit)
        .map_err(|err| format!("claim network in: {err}"))?;
    let mut total = TransitInReport::default();
    for inbound in input {
        let result = store.write_transaction(|store| {
            let changes = registry
                .project_network_in(store, &inbound)
                .map_err(module_error)?;
            let canonical_rows = changes
                .rows
                .iter()
                .filter(|row| row.table == worker_schema::CANONICAL_IN)
                .count();
            write_projection_output_in_tx(store, changes)?;
            network_queues::delete_inbound_in_tx(store, std::slice::from_ref(&inbound))?;
            Ok(canonical_rows)
        });
        match result {
            Ok(canonical_rows) => {
                total.network_frames += 1;
                total.canonical_rows += canonical_rows;
            }
            Err(err) => {
                network_queues::delete_inbound(store, std::slice::from_ref(&inbound)).map_err(
                    |delete_err| {
                        format!(
                            "drain transit in: {err}; failed to consume rejected frame: {delete_err}"
                        )
                    },
                )?;
                return Err(format!("drain transit in: {err}"));
            }
        }
    }
    Ok(total)
}

pub(crate) fn drain_ready_events<R>(
    store: &Store,
    registry: &R,
    limit: usize,
) -> Result<ApplyReadyReport, String>
where
    R: EventRegistry,
{
    let report = drain_ready(store, registry, limit)?;
    if report.applied_events > 0 {
        registry.post_admission_hook(store)?;
    }
    Ok(report)
}

pub(crate) fn drain_recently_valid_events(
    store: &Store,
    limit: usize,
) -> Result<ApplyReadyReport, String> {
    store
        .write_transaction(|store| {
            let events = worker_schema::claim_recently_valid_events(store, limit)?;
            let keys = events
                .iter()
                .map(|event| event.key.clone())
                .collect::<Vec<_>>();
            let mut total = ApplyReadyReport::default();
            for event in events {
                total.unblocked_events += unblock_dependents(store, &event.event_id)?;
            }
            store.delete_table_rows_in_tx(worker_schema::RECENTLY_VALID_EVENTS, keys)?;
            Ok(total)
        })
        .map_err(|err| format!("drain recently valid events: {err}"))
}

fn admit_proposed_events<R>(
    store: &Store,
    registry: &R,
    events: Vec<ProposedEvent>,
) -> Result<PipelineStepReport, String>
where
    R: EventRegistry,
{
    let admitted = store
        .write_transaction(|store| {
            let mut report = AdmitReport::default();
            for event in events {
                process_proposed_event_tx(store, registry, &event, &mut report)?;
            }
            Ok(report)
        })
        .map_err(|err| format!("admit proposed events: {err}"))?;
    if admitted.inserted_events > 0 || admitted.applied_events > 0 {
        registry.post_admission_hook(store)?;
    }
    let drained = drain_recently_valid_until_empty(store, DEFAULT_READY_BATCH)?;
    Ok(PipelineStepReport { admitted, drained })
}

fn drain_recently_valid_until_empty(
    store: &Store,
    batch_size: usize,
) -> Result<ApplyReadyReport, String> {
    let mut total = ApplyReadyReport::default();
    let limit = batch_size.max(1);
    while store
        .table_row_count(worker_schema::RECENTLY_VALID_EVENTS)
        .map_err(|err| format!("count recently valid events: {err}"))?
        > 0
    {
        let report = dependency_unblock::run(store, dependency_unblock::Work::Drain { limit })?;
        total.applied_events += report.applied_events;
        total.unblocked_events += report.unblocked_events;
    }
    Ok(total)
}

fn merge_admit_report(total: &mut AdmitReport, next: AdmitReport) {
    total.network_frames += next.network_frames;
    total.event_ids.extend(next.event_ids);
    total.inserted_events += next.inserted_events;
    total.ready_events += next.ready_events;
    total.blocked_events += next.blocked_events;
    total.blocked_edges += next.blocked_edges;
    total.applied_events += next.applied_events;
}

impl<T, R> Work<R> for CommandOutput<T>
where
    R: EventRegistry,
{
    type Output = (T, AdmitReport);

    fn execute(self, store: &Store, registry: &R) -> Result<Self::Output, String> {
        let value = self.value;
        let report = admit_proposed_events(store, registry, self.events)?;
        Ok((value, report.admitted))
    }
}

impl<T, R> Work<R> for AdmitAndDrain<T>
where
    R: EventRegistry,
{
    type Output = AdmitAndDrainReport<T>;

    fn execute(self, store: &Store, registry: &R) -> Result<Self::Output, String> {
        let value = self.output.value;
        let report = admit_proposed_events(store, registry, self.output.events)?;
        let drained = drain_until_idle(store, registry, self.batch_size)?;
        // Re-run the post-admission hook once after the post-drain since a
        // dependent event may have only become Applied as the closure
        // unblocked it. This keeps in-process CLI paths (delete-message,
        // scripted batches, one-shot admission flows) at the same end state
        // as a long-running daemon.
        registry.post_admission_hook(store)?;
        let drained = ApplyReadyReport {
            applied_events: report.drained.applied_events + drained.applied_events,
            unblocked_events: report.drained.unblocked_events + drained.unblocked_events,
        };
        Ok(AdmitAndDrainReport {
            value,
            admitted: report.admitted,
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
        admit_proposed_events(
            store,
            registry,
            self.records.into_iter().map(ProposedEvent::new).collect(),
        )
        .map(|report| report.admitted)
    }
}

impl<R> Work<R> for AdmitReceivedRecords
where
    R: EventRegistry,
{
    type Output = AdmitReport;

    fn execute(self, store: &Store, registry: &R) -> Result<Self::Output, String> {
        admit_proposed_events(
            store,
            registry,
            self.records
                .into_iter()
                .map(|received| ProposedEvent::contextual(received.record, received.receive))
                .collect(),
        )
        .map(|report| report.admitted)
    }
}

impl<R> Work<R> for DrainUntilIdle
where
    R: EventRegistry,
{
    type Output = ApplyReadyReport;

    fn execute(self, store: &Store, registry: &R) -> Result<Self::Output, String> {
        let report = drain_until_idle(store, registry, self.batch_size)?;
        if report.applied_events > 0 {
            registry.post_admission_hook(store)?;
        }
        Ok(report)
    }
}

impl<R> Work<R> for DrainReadyBatch
where
    R: EventRegistry,
{
    type Output = ApplyReadyReport;

    fn execute(self, store: &Store, registry: &R) -> Result<Self::Output, String> {
        let mut report = drain_ready(store, registry, self.batch_size)?;
        let unblock = drain_recently_valid_events(store, self.batch_size)?;
        report.unblocked_events += unblock.unblocked_events;
        if report.applied_events > 0 {
            registry.post_admission_hook(store)?;
        }
        Ok(report)
    }
}

// ---------------------------------------------------------------------------
// Canonical event pipeline
// ---------------------------------------------------------------------------

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
fn process_proposed_event_tx(
    store: &Store,
    modules: &impl EventRegistry,
    event: &ProposedEvent,
    report: &mut AdmitReport,
) -> rusqlite::Result<()> {
    let record = event.record();
    report.event_ids.push(event.event_id());
    if !record.scope.is_durable() {
        project_transient_event_tx(store, modules, record, event.receive())?;
        report.applied_events += 1;
        return Ok(());
    }

    let stored = store_durable_event_tx(store, event, report)?;
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
            project_ready_event_tx(store, modules, &stored.event_id)?
        };
        report.applied_events += apply.applied_events;
    }
    Ok(())
}

fn project_transient_event_tx(
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
fn store_durable_event_tx(
    store: &Store,
    event: &ProposedEvent,
    report: &mut AdmitReport,
) -> rusqlite::Result<StoredDurableEvent> {
    let record = event.record();
    let id = event.event_id();
    let missing = missing_dependencies(store, &record.dependencies)?;
    let status = if missing.is_empty() {
        EventStatus::Ready
    } else {
        EventStatus::Blocked
    };

    let inserted = event_lifecycle::insert_event(store, record, status)?;
    if inserted {
        report.inserted_events += 1;
        if missing.is_empty() {
            report.ready_events += 1;
        } else {
            report.blocked_events += 1;
            report.blocked_edges += write_blockers(store, &id, &missing)?;
            if let Some(receive) = event.receive() {
                store.insert_table_rows_in_tx(vec![worker_schema::event_receive_context_row(
                    id, receive,
                )])?;
            }
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
/// The status change, context load, projector call, row writes, and
/// recently-valid queue write all happen in the caller's transaction. If
/// projection fails, the Applied status rolls back, so failed events cannot
/// become dependency context for later projectors.
fn project_ready_event_tx(
    store: &Store,
    modules: &impl EventRegistry,
    event_id: &EventId,
) -> rusqlite::Result<ApplyReadyReport> {
    let mut report = ApplyReadyReport::default();
    if event_lifecycle::set_event_status(store, event_id, EventStatus::Ready, EventStatus::Applied)?
    {
        // The status change is the claim. Projection runs only for the worker
        // that successfully moved Ready -> Applied, which keeps duplicate drain
        // attempts idempotent when callers retry.
        let bytes =
            schema::event_bytes(store, event_id)?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
        let record = modules.record_from_bytes(bytes).map_err(module_error)?;
        let receive = worker_schema::event_receive_context(store, event_id)?;
        let changes = project_event_with_context_in_tx(store, modules, event_id, &record, receive)?;
        write_projection_output_in_tx(store, changes)?;
        write_applied_event_outputs_in_tx(store, event_id, &record)?;
        if receive.is_some() {
            worker_schema::delete_event_receive_context_in_tx(store, event_id)?;
        }
        report.applied_events = 1;
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
    if event_lifecycle::set_event_status(store, event_id, EventStatus::Ready, EventStatus::Applied)?
    {
        let changes = project_event_with_context_in_tx(store, modules, event_id, record, receive)?;
        write_projection_output_in_tx(store, changes)?;
        write_applied_event_outputs_in_tx(store, event_id, record)?;
        report.applied_events = 1;
    }
    Ok(report)
}

fn write_applied_event_outputs_in_tx(
    store: &Store,
    event_id: &EventId,
    record: &EventRecord,
) -> rusqlite::Result<()> {
    let mut rows = vec![worker_schema::recently_valid_event_row(*event_id)];
    if record.scope.is_shared() {
        rows.push(worker_schema::applied_shared_event_row(EventIndexEntry {
            event_id: *event_id,
            timestamp: record.timestamp,
            workspace_id: record.workspace_id,
        }));
    }
    store.insert_table_rows_in_tx(rows)?;
    Ok(())
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
    let now_unix_minute = crate::core::logical_clock::logical_time(store)
        .map_err(module_error)?
        .map(|ms| ms / crate::protocol::event_modules::content::message::types::UNIX_MINUTE_MS);
    Ok(EventContext {
        event_id: *event_id,
        dependencies,
        labels: schema::event_labels(store, event_id).map_err(module_error)?,
        receive,
        now_unix_minute,
    })
}

fn write_projection_output_in_tx(
    store: &Store,
    changes: ProjectionOutput,
) -> rusqlite::Result<usize> {
    let rows = store.insert_table_rows_in_tx(changes.rows)?;
    let labels = store.insert_table_rows_in_tx(schema::event_label_rows(changes.labels))?;
    let mut deletes = 0;
    for delete in changes.deletes {
        deletes += store.delete_table_rows_in_tx(delete.table, vec![delete.key])?;
    }
    Ok(rows + labels + deletes)
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
                let Some(event_id) = event_lifecycle::next_ready_event(store)? else {
                    break;
                };
                let report = project_ready_event_tx(store, modules, &event_id)?;
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
        let unblock = drain_recently_valid_events(store, batch_size)?;
        total.applied_events += report.applied_events;
        total.unblocked_events += report.unblocked_events + unblock.unblocked_events;
        if report.applied_events == 0 && unblock.unblocked_events == 0 {
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
        if !event_lifecycle::event_is_applied(store, &dependency)? {
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
        inserted += usize::from(event_lifecycle::insert_blocked_event_missing_dep(
            store, dependency, event_id,
        )?);
    }
    Ok(inserted)
}

fn unblock_dependents(store: &Store, applied_event_id: &EventId) -> rusqlite::Result<usize> {
    let dependents = event_lifecycle::blocked_events_by_missing_dep(store, applied_event_id)?;
    event_lifecycle::delete_blocked_events_by_missing_dep(store, applied_event_id)?;

    let mut unblocked = 0;
    for dependent in dependents {
        // Unblocking only changes status. It does not recursively project the
        // newly unblocked canonical inside the same stack frame, which prevents a large
        // dependency cascade from becoming one unbounded transaction.
        if !event_lifecycle::blocked_event_has_missing_deps(store, &dependent)?
            && event_lifecycle::set_event_status(
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

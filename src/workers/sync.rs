//! Sync worker.
//!
//! Sync is an active protocol, not a projector side effect. Projectors write the
//! rows that make sync possible; this worker catches the warm index up, calls
//! sync commands for protocol decisions, writes output queues, and consumes
//! claimed rows. That keeps negentropy out of the kernel while still making
//! every sync message pass through the same event/module discipline as durable
//! content.
//!
//! Inputs:
//! - `event_modules.applied_shared_events` updates the warm negentropy index.
//! - `sync.in` holds projected inbound compare/have/need events by connection.
//! - `Work::Tick` is the daemon input that catches up the index, starts sync,
//!   and drains projected inbound sync work.
//! - `Work::Start` is an explicit local worker input for known connection
//!   routes.
//!
//! State: process-local `SyncIndex` held by the protocol context.
//! Step: drain pending index rows before any response-producing command, then
//! call sync commands and write their queue/event outputs.
//! Outputs: connection-scoped sync events through event admission and durable
//! send ids through `transit.out`.
//! Consume: applied-shared and sync-in rows are deleted after the index update or
//! inbound event handler completes.
//! Failure: response-producing work leaves unconsumed sync-in rows when it fails;
//! index-drain failure leaves applied-shared rows queued.
//! Fairness: `Tick`, `DrainIndex`, and `DrainIn` are limit-bounded where they
//! claim queues; start fans out over the currently known routes.
//!
//! The worker has four input shapes:
//!
//! ```text
//! daemon tick -> catch up index -> start sync -> drain projected sync in
//! applied shared events -> update warm index
//! sync start input -> root compare command per route
//! projected sync in rows -> compare/have/need handler for that connection
//! ```
//!
//! The response paths produce connection-scoped sync events. Those events are
//! transient protocol facts: they can be projected into the transit out,
//! wrapped by transit out, and deduped while queued, but they are not
//! part of the durable content history. Requested durable events are queued by
//! id for transit out; sync does not build data packets. When an
//! inbound sync event arrives on a connection without a stored return route, the
//! response is queued on another routed connection to the same remote endpoint.
//! Daemon ticks start new rounds only when the local endpoint id sorts before
//! the remote endpoint id for that connection. That deterministic leader rule
//! prevents both peers from constantly initiating the same reconciliation; the
//! non-leader still responds to inbound sync work normally.
//!
//! Sync may query sync-owned indexes and propose sync events through commands.
//! It does not perform TCP IO, mutate content projections, or bypass normal
//! event admission.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;

use crate::core::daemon::{StepContext, Worker};
use crate::core::store::Store;
use crate::protocol::event_modules::connection;
use crate::protocol::event_modules::identity::{endpoint, endpoint_shared};
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::sync::commands;
pub use crate::protocol::event_modules::sync::commands::{
    SyncSelection, SyncStartReport, SyncWorkReport,
};
use crate::protocol::event_modules::sync::compare;
use crate::protocol::event_modules::sync::compare::types::{RangeSummary, TimestampRange};
use crate::protocol::event_modules::types::{EventId, EventIndexEntry};
use crate::workers::common::event_pipeline::{CommandOutput, ProposedEvent};
use crate::workers::schema as worker_schema;
use crate::workers::{common::event_pipeline as event_worker, DaemonWorkerContext};

pub const DEFAULT_INBOUND_BATCH: usize = 1024;
const DEFAULT_INDEX_BATCH: usize = 4096;

/// Process-local sync index shared by sync worker turns.
///
/// SQLite remains the source of truth for canonical events. The worker catches
/// this cache up from applied shared events before response work, then sync
/// commands query it through explicit read context.
#[derive(Debug, Default)]
pub struct SyncIndex {
    state: Mutex<IndexState>,
}

impl SyncIndex {
    pub(crate) fn insert_entry(&self, entry: EventIndexEntry) -> Result<bool, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "sync index mutex poisoned".to_string())?;
        if state.indexed.contains(&entry.event_id) {
            return Ok(false);
        }
        state.insert(entry);
        Ok(true)
    }

    fn catch_up(&self, store: &Store) -> Result<(), String> {
        let entries = event_schema::event_index_entries_in_timestamp_range(store, 0, u64::MAX)
            .map_err(|err| format!("load sync index feed: {err}"))?;
        for entry in entries {
            self.insert_entry(entry)?;
        }
        Ok(())
    }

    fn ids_in_range(&self, range: TimestampRange) -> Result<Vec<EventIndexEntry>, String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "sync index mutex poisoned".to_string())?;
        Ok(state.ids_in_range(range))
    }

    fn has_event(&self, event_id: &EventId) -> Result<bool, String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "sync index mutex poisoned".to_string())?;
        Ok(state.entries_by_id.contains_key(event_id))
    }

    fn dependency_closure_entries(
        &self,
        store: &Store,
        roots: &[EventIndexEntry],
    ) -> Result<Vec<EventIndexEntry>, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "sync index mutex poisoned".to_string())?;
        state.dependency_closure_entries(store, roots)
    }
}

/// Work accepted by the sync worker.
///
/// `DrainIndex` processes the shared-event feed. `Start` creates initial
/// compare events for route exchange. `DrainIn` handles work already projected
/// from transient inbound sync events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Work {
    Tick {
        index_limit: usize,
        inbound_limit: usize,
        selection: SyncSelection,
    },
    DrainIndex {
        limit: usize,
    },
    Start {
        selection: SyncSelection,
    },
    /// Start a sync round against exactly one routed peer. Used by the peer
    /// supervisor so a single slow peer cannot starve the rotation: `Start`
    /// fans out across every routed peer in one call, while this variant
    /// drives one peer per call.
    StartForConnection {
        connection_id: connection::types::ConnectionId,
        selection: SyncSelection,
    },
    DrainIn {
        limit: usize,
    },
    DrainConnectionIn {
        connection_id: connection::types::ConnectionId,
        limit: usize,
    },
}

/// Result of a sync worker action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    Ticked(CommandOutput<SyncTickReport>),
    Indexed(SyncIndexReport),
    Started(CommandOutput<SyncStartReport>),
    DrainedIn(SyncWorkReport),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncIndexReport {
    pub indexed_events: usize,
}

/// Summary of one daemon sync tick.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncTickReport {
    pub indexed_events: usize,
    pub started_rounds: usize,
    pub processed_work: usize,
    pub sent_events: usize,
}

/// Run one sync worker action.
///
/// The only public entrypoint mirrors the other workers. Adding a new sync input
/// should add a `Work` variant and keep the command/query/projection boundary
/// visible here.
pub fn run(store: &Store, index: &SyncIndex, work: Work) -> Result<Output, String> {
    match work {
        Work::Tick {
            index_limit,
            inbound_limit,
            selection,
        } => tick(store, index, index_limit, inbound_limit, selection).map(Output::Ticked),
        Work::DrainIndex { limit } => {
            drain_index_queue_once(store, index, limit).map(Output::Indexed)
        }
        Work::Start { selection } => {
            prepare_index_for_response(store, index, DEFAULT_INDEX_BATCH)?;
            start(store, index, selected_range(store, selection)?).map(Output::Started)
        }
        Work::StartForConnection {
            connection_id,
            selection,
        } => {
            prepare_index_for_response(store, index, DEFAULT_INDEX_BATCH)?;
            start_one(
                store,
                index,
                connection_id,
                selected_range(store, selection)?,
            )
            .map(Output::Started)
        }
        Work::DrainIn { limit } => {
            prepare_index_for_response(store, index, DEFAULT_INDEX_BATCH)?;
            drain_in_events(store, index, limit).map(Output::DrainedIn)
        }
        Work::DrainConnectionIn {
            connection_id,
            limit,
        } => {
            prepare_index_for_response(store, index, DEFAULT_INDEX_BATCH)?;
            drain_connection_in_events(store, index, connection_id, limit).map(Output::DrainedIn)
        }
    }
}

pub(crate) fn daemon_worker<C>() -> Worker<C>
where
    C: DaemonWorkerContext,
{
    Worker {
        name: "sync_tick",
        run: daemon_step::<C>,
    }
}

fn daemon_step<C>(ctx: &mut StepContext<'_, C>) -> Result<(), String>
where
    C: DaemonWorkerContext,
{
    let app = &*ctx.app;
    let output = match run(
        app.store(),
        app.sync_index(),
        Work::Tick {
            index_limit: ctx.options.work_limit,
            inbound_limit: DEFAULT_INBOUND_BATCH,
            selection: SyncSelection::All,
        },
    )
    .map_err(|err| format!("tick sync: {err}"))?
    {
        Output::Ticked(output) => output,
        Output::Indexed(_) | Output::Started(_) | Output::DrainedIn(_) => {
            return Err("sync worker returned non-tick output".to_string())
        }
    };
    ctx.report.add("sync_rounds", output.value.started_rounds);
    ctx.report
        .add("sync_indexed_events", output.value.indexed_events);
    ctx.report
        .add("sync_processed_work", output.value.processed_work);
    ctx.report.add("sent_events", output.value.sent_events);
    event_worker::enqueue_proposed_events(app.store(), output.events)?;
    Ok(())
}

fn tick(
    store: &Store,
    index: &SyncIndex,
    index_limit: usize,
    inbound_limit: usize,
    selection: SyncSelection,
) -> Result<CommandOutput<SyncTickReport>, String> {
    let indexed = prepare_index_for_response(store, index, index_limit)?;
    let started = start(store, index, selected_range(store, selection)?)?;
    let inbound = drain_in_events(store, index, inbound_limit)?;

    let mut events = started.events;
    events.extend(inbound.events.into_iter().map(ProposedEvent::new));
    Ok(CommandOutput::with_proposed_events(
        SyncTickReport {
            indexed_events: indexed.indexed_events,
            started_rounds: started.value.sent_events,
            processed_work: inbound.processed_work,
            sent_events: started.value.sent_events + inbound.sent_events,
        },
        events,
    ))
}

fn prepare_index_for_response(
    store: &Store,
    index: &SyncIndex,
    limit: usize,
) -> Result<SyncIndexReport, String> {
    index.catch_up(store)?;
    let limit = limit.max(1);
    let mut aggregate = SyncIndexReport::default();
    loop {
        let report = drain_index_queue_once(store, index, limit)?;
        aggregate.indexed_events += report.indexed_events;
        if report.indexed_events < limit {
            return Ok(aggregate);
        }
    }
}

fn drain_index_queue_once(
    store: &Store,
    index: &SyncIndex,
    limit: usize,
) -> Result<SyncIndexReport, String> {
    let applied = worker_schema::claim_applied_shared_events(store, limit)
        .map_err(|err| format!("claim applied shared events: {err}"))?;
    let keys = applied
        .iter()
        .map(|event| event.key.clone())
        .collect::<Vec<_>>();
    let mut report = SyncIndexReport::default();
    for event in applied {
        if index.insert_entry(event.entry)? {
            report.indexed_events += 1;
        }
    }
    if !keys.is_empty() {
        store
            .delete_table_rows(worker_schema::APPLIED_SHARED_EVENTS, keys)
            .map_err(|err| format!("consume applied shared events: {err}"))?;
    }
    Ok(report)
}

fn selected_range(store: &Store, selection: SyncSelection) -> Result<TimestampRange, String> {
    match selection {
        SyncSelection::All => Ok(TimestampRange::ROOT),
        SyncSelection::Today => {
            let timestamp = event_schema::max_timestamp(store)
                .map_err(|err| format!("load max timestamp for sync today: {err}"))?;
            Ok(TimestampRange::containing_day(timestamp))
        }
    }
}

fn start(
    store: &Store,
    index: &SyncIndex,
    range: TimestampRange,
) -> Result<CommandOutput<SyncStartReport>, String> {
    let connections = connection_ids_with_routes(store)?;
    if connections.is_empty() {
        return Ok(CommandOutput::new(SyncStartReport::default()));
    }
    let mut events = Vec::new();
    let mut sent_events = 0;
    let local = local_endpoint(store)?;
    for connection_id in connections {
        if !local_starts_sync_round(store, local.endpoint, connection_id)? {
            continue;
        }
        let context =
            StoreSyncContext::for_connection(store, index, local.endpoint, connection_id)?;
        if context.workspace_ids.is_empty() {
            continue;
        }
        let output = commands::start_for_connection(&context, connection_id, range)?;
        events.extend(output.events);
        sent_events += output.value.sent_events;
    }
    Ok(CommandOutput::with_proposed_events(
        SyncStartReport { sent_events },
        events,
    ))
}

fn local_starts_sync_round(
    store: &Store,
    local_endpoint: endpoint::types::EndpointId,
    connection_id: connection::types::ConnectionId,
) -> Result<bool, String> {
    let remote = connection::schema::remote_endpoint(store, connection_id)?;
    Ok(local_endpoint < remote)
}

/// Run a sync start command against exactly one routed peer.
///
/// The peer supervisor calls this so a single slow peer can fail one tick
/// without starving the rotation. Unlike `start`, this function does not
/// apply the leader rule: the supervisor is operating outside the leader
/// inhibition because its job is to ensure either side periodically pushes
/// fresh content. The non-leader still suppresses redundant rounds because
/// the inbound compare events are deterministic in projected state, but it
/// no longer waits silently for the leader to start every round.
fn start_one(
    store: &Store,
    index: &SyncIndex,
    connection_id: connection::types::ConnectionId,
    range: TimestampRange,
) -> Result<CommandOutput<SyncStartReport>, String> {
    let local = local_endpoint(store)?;
    if connection::schema::remote_endpoint(store, connection_id).is_err() {
        return Ok(CommandOutput::new(SyncStartReport::default()));
    }
    let context = StoreSyncContext::for_connection(store, index, local.endpoint, connection_id)?;
    if context.workspace_ids.is_empty() {
        return Ok(CommandOutput::new(SyncStartReport::default()));
    }
    let output = commands::start_for_connection(&context, connection_id, range)?;
    Ok(CommandOutput::with_proposed_events(
        SyncStartReport {
            sent_events: output.value.sent_events,
        },
        output.events,
    ))
}

fn drain_in_events(
    store: &Store,
    index: &SyncIndex,
    limit: usize,
) -> Result<SyncWorkReport, String> {
    let limit = limit.max(1);
    let works = worker_schema::claim_sync_in_events(store, limit)
        .map_err(|err| format!("load sync in events: {err}"))?;
    drain_sync_works(store, index, works)
}

fn drain_connection_in_events(
    store: &Store,
    index: &SyncIndex,
    connection_id: connection::types::ConnectionId,
    limit: usize,
) -> Result<SyncWorkReport, String> {
    let limit = limit.max(1);
    let works = worker_schema::claim_sync_in_events_for_connection(store, connection_id, limit)
        .map_err(|err| format!("load sync in events: {err}"))?;
    drain_sync_works(store, index, works)
}

fn drain_sync_works(
    store: &Store,
    index: &SyncIndex,
    works: Vec<worker_schema::SyncInEvent>,
) -> Result<SyncWorkReport, String> {
    if works.is_empty() {
        return Ok(SyncWorkReport::default());
    }
    let mut result = SyncWorkReport::default();
    let mut consumed = Vec::with_capacity(works.len());
    let mut transit_out_rows = Vec::new();
    let local = local_endpoint(store)?;
    for work in works {
        let response_connection_id = response_connection_id(store, work.connection_id)?;
        let context =
            StoreSyncContext::for_connection(store, index, local.endpoint, work.connection_id)?;
        let report = commands::handle_inbound_event(
            &context,
            work.connection_id,
            response_connection_id,
            &work.event_bytes,
        )?;
        result.processed_work += report.processed_work;
        result.sent_events += report.sent_events;
        result.events.extend(report.events);
        for send in report.transit_out {
            transit_out_rows.push(worker_schema::transit_out_row(
                send.connection_id,
                send.event_id,
            ));
            result.transit_out.push(send);
            result.send_event_ids.push(send.event_id);
        }
        consumed.push(work.key());
    }
    if !transit_out_rows.is_empty() {
        store
            .insert_table_rows(transit_out_rows)
            .map_err(|err| format!("queue requested durable events: {err}"))?;
    }
    if !consumed.is_empty() {
        store
            .delete_table_rows(worker_schema::SYNC_IN_EVENTS, consumed)
            .map_err(|err| format!("delete sync in events: {err}"))?;
    }
    Ok(result)
}

struct StoreSyncContext<'a> {
    store: &'a Store,
    index: &'a SyncIndex,
    workspace_ids: Vec<EventId>,
}

impl<'a> StoreSyncContext<'a> {
    fn for_connection(
        store: &'a Store,
        index: &'a SyncIndex,
        local_endpoint: EventId,
        connection_id: connection::types::ConnectionId,
    ) -> Result<Self, String> {
        let remote = connection::schema::remote_endpoint(store, connection_id)?;
        let workspace_ids =
            endpoint_shared::schema::mutual_workspace_ids(store, local_endpoint, remote)?;
        Ok(Self {
            store,
            index,
            workspace_ids,
        })
    }

    fn entry_is_allowed(&self, entry: &EventIndexEntry) -> bool {
        entry.workspace_id.is_some_and(|workspace_id| {
            self.workspace_ids
                .iter()
                .any(|allowed| allowed == &workspace_id)
        })
    }

    fn entries_in_range(&self, range: TimestampRange) -> Result<Vec<EventIndexEntry>, String> {
        self.index.ids_in_range(range).map(|entries| {
            entries
                .into_iter()
                .filter(|entry| self.entry_is_allowed(entry))
                .collect()
        })
    }
}

impl compare::commands::ReadContext for StoreSyncContext<'_> {
    fn summary(&self, range: TimestampRange) -> Result<RangeSummary, String> {
        Ok(summarize_entries(&self.entries_in_range(range)?))
    }

    fn ids_in_range(&self, range: TimestampRange) -> Result<Vec<EventIndexEntry>, String> {
        self.entries_in_range(range)
    }

    fn timestamp_bounds(&self, range: TimestampRange) -> Result<Option<(u64, u64)>, String> {
        let entries = self.entries_in_range(range)?;
        let Some(first) = entries.first() else {
            return Ok(None);
        };
        let last = entries.last().unwrap_or(first);
        Ok(Some((first.timestamp, last.timestamp)))
    }

    fn has_event(&self, event_id: &EventId) -> Result<bool, String> {
        self.index.has_event(event_id)
    }

    fn dependency_closure_entries(
        &self,
        roots: &[EventIndexEntry],
    ) -> Result<Vec<EventIndexEntry>, String> {
        self.index
            .dependency_closure_entries(self.store, roots)
            .map(|entries| {
                entries
                    .into_iter()
                    .filter(|entry| self.entry_is_allowed(entry))
                    .collect()
            })
    }

    fn fresh_have_entries(
        &self,
        connection_id: EventId,
        entries: Vec<EventIndexEntry>,
    ) -> Result<Vec<EventIndexEntry>, String> {
        let _ = connection_id;
        Ok(entries
            .into_iter()
            .filter(|entry| self.entry_is_allowed(entry))
            .collect())
    }

    fn can_send_event(&self, event_id: &EventId) -> Result<bool, String> {
        event_schema::has_shared_event_in_workspaces(self.store, event_id, &self.workspace_ids)
            .map_err(|err| format!("check scoped event presence: {err}"))
    }
}

fn local_endpoint(store: &Store) -> Result<endpoint::types::EndpointKeypair, String> {
    endpoint::commands::local_keypair(store)?.ok_or_else(|| "local endpoint is missing".to_string())
}

fn connection_ids_with_routes(
    store: &Store,
) -> Result<Vec<connection::types::ConnectionId>, String> {
    store
        .table_rows(connection::schema::TRANSPORT_TARGETS)
        .map_err(|err| format!("load transport targets: {err}"))?
        .into_iter()
        .map(|(key, _)| connection::types::connection_id_from_bytes(&key))
        .collect()
}

fn response_connection_id(
    store: &Store,
    inbound_connection_id: connection::types::ConnectionId,
) -> Result<connection::types::ConnectionId, String> {
    let remote = connection::schema::remote_endpoint(store, inbound_connection_id)?;
    let mut fallback = None;
    for connection_id in connection_ids_with_routes(store)? {
        if connection::schema::remote_endpoint(store, connection_id)? != remote {
            continue;
        }
        if fallback.is_none() {
            fallback = Some(connection_id);
        }
        // Workspace invite bootstrap routes are often short-lived listener
        // source addresses. Once both endpoints have steady-state membership,
        // sync replies should prefer an unscoped daemon route to the same
        // endpoint so old invite routes cannot black-hole responses.
        if connection::schema::bootstrap_workspace_id(store, connection_id)?.is_none() {
            return Ok(connection_id);
        }
    }
    Ok(fallback.unwrap_or(inbound_connection_id))
}

fn summarize_entries(entries: &[EventIndexEntry]) -> RangeSummary {
    let mut summary = RangeSummary::default();
    for entry in entries {
        summary.count += 1;
        xor_into(&mut summary.fingerprint, &fingerprint_id(&entry.event_id));
    }
    summary
}

#[derive(Debug, Default)]
struct IndexState {
    indexed: HashSet<EventId>,
    ids_by_time: BTreeMap<(u64, EventId), EventIndexEntry>,
    entries_by_id: HashMap<EventId, EventIndexEntry>,
    deps_by_event: HashMap<EventId, Vec<EventId>>,
}

impl IndexState {
    fn insert(&mut self, entry: EventIndexEntry) {
        self.indexed.insert(entry.event_id);
        self.ids_by_time
            .insert((entry.timestamp, entry.event_id), entry.clone());
        self.entries_by_id.insert(entry.event_id, entry);
    }

    fn ids_in_range(&self, range: TimestampRange) -> Vec<EventIndexEntry> {
        let lower = (range.start, [0; 32]);
        let upper = (range.end, [0xff; 32]);
        self.ids_by_time
            .range(lower..=upper)
            .map(|(_, entry)| entry.clone())
            .collect()
    }

    fn dependency_closure_entries(
        &mut self,
        store: &Store,
        roots: &[EventIndexEntry],
    ) -> Result<Vec<EventIndexEntry>, String> {
        let root_ids = roots
            .iter()
            .map(|entry| entry.event_id)
            .collect::<HashSet<_>>();
        let mut seen = root_ids.clone();
        let mut stack = Vec::new();
        for entry in roots {
            stack.extend(self.dependencies_for(store, &entry.event_id)?);
        }
        let mut out = BTreeMap::<(u64, EventId), EventIndexEntry>::new();

        while let Some(dep) = stack.pop() {
            if !seen.insert(dep) {
                continue;
            }
            let Some(entry) = self.entries_by_id.get(&dep) else {
                continue;
            };
            if !root_ids.contains(&dep) {
                out.insert((entry.timestamp, entry.event_id), entry.clone());
            }
            stack.extend(self.dependencies_for(store, &dep)?);
        }

        Ok(out.into_values().collect())
    }

    fn dependencies_for(
        &mut self,
        store: &Store,
        event_id: &EventId,
    ) -> Result<Vec<EventId>, String> {
        if let Some(dependencies) = self.deps_by_event.get(event_id) {
            return Ok(dependencies.clone());
        }
        if !self.entries_by_id.contains_key(event_id) {
            return Ok(Vec::new());
        }
        let bytes = event_schema::event_bytes(store, event_id)
            .map_err(|err| format!("load sync dependency event bytes: {err}"))?
            .ok_or_else(|| "sync index referenced missing dependency event".to_string())?;
        let record = crate::protocol::event_modules::record_from_bytes(bytes)?;
        let dependencies = record.dependencies;
        self.deps_by_event.insert(*event_id, dependencies.clone());
        Ok(dependencies)
    }
}

fn fingerprint_id(id: &EventId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"sync-event-id:");
    hasher.update(id);
    *hasher.finalize().as_bytes()
}

fn xor_into(target: &mut [u8; 32], value: &[u8; 32]) {
    for (left, right) in target.iter_mut().zip(value.iter()) {
        *left ^= *right;
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::identity::{endpoint, endpoint_shared, workspace};
    use crate::protocol::event_modules::sync::compare;
    use crate::protocol::event_modules::types::{event_id, ConnectionScope, EventId, EventScope};
    use crate::protocol::event_modules::worker as event_worker;
    use crate::protocol::Protocol;

    use super::*;

    #[test]
    fn start_rounds_only_from_lower_endpoint_peer() {
        let first = endpoint::commands::create_local_keypair().value;
        let second = endpoint::commands::create_local_keypair().value;
        let (lower, higher) = if first.endpoint < second.endpoint {
            (first, second)
        } else {
            (second, first)
        };

        let lower_store = routed_sync_store(lower, higher);
        let higher_store = routed_sync_store(higher, lower);
        let index = SyncIndex::default();

        let lower_output = run(
            &lower_store,
            &index,
            Work::Start {
                selection: SyncSelection::All,
            },
        )
        .expect("lower endpoint starts sync");
        let Output::Started(lower_output) = lower_output else {
            panic!("expected start output");
        };
        assert_eq!(lower_output.value.sent_events, 1);
        assert_eq!(lower_output.events.len(), 1);

        let higher_output = run(
            &higher_store,
            &index,
            Work::Start {
                selection: SyncSelection::All,
            },
        )
        .expect("higher endpoint does not start sync");
        let Output::Started(higher_output) = higher_output else {
            panic!("expected start output");
        };
        assert_eq!(higher_output.value.sent_events, 0);
        assert!(higher_output.events.is_empty());
    }

    #[test]
    fn tick_responds_on_routed_connection_to_same_remote_endpoint() {
        let store = Protocol::open_memory_store().expect("open store");
        let protocol = Protocol::new();
        let local = endpoint::commands::create_local_keypair().value;
        let remote = endpoint::commands::create_local_keypair().value;
        let inbound_connection_id = [1; 32];
        let response_connection_id = [2; 32];

        let workspace = workspace::commands::create(workspace::commands::CreateWorkspace {
            created_at_ms: 1,
            public_key: [9; 32],
            name: "sync-in-route".to_string(),
        })
        .expect("create workspace");
        let workspace_id = workspace.value.workspace_id;
        event_worker::run(&store, &protocol, workspace).expect("admit workspace");

        let mut rows = endpoint::projector::local_endpoint(local);
        rows.extend([
            connection::schema::connection_row(inbound_connection_id, remote.endpoint),
            connection::schema::connection_row(response_connection_id, remote.endpoint),
            connection::schema::transport_target_row(
                response_connection_id,
                "127.0.0.1:41000".parse().expect("route addr"),
            ),
            endpoint_membership_row(workspace_id, local.endpoint, local.signing_public_key, 10),
            endpoint_membership_row(workspace_id, remote.endpoint, remote.signing_public_key, 11),
        ]);
        store.insert_table_rows(rows).expect("insert sync context");

        let compare = compare::types::CompareEvent {
            connection_id: inbound_connection_id,
            range: compare::types::TimestampRange::ROOT,
            summary: compare::types::RangeSummary::default(),
            response_requested: true,
        };
        let bytes = compare::codec::encode(&compare);
        let record = compare::codec::inbound_record_from_wire(bytes).expect("inbound compare");
        store
            .insert_table_rows(vec![worker_schema::sync_in_event_row(
                inbound_connection_id,
                event_id(&record.canonical_bytes),
                record.canonical_bytes,
            )])
            .expect("insert sync in");

        let index = SyncIndex::default();
        let output = run(
            &store,
            &index,
            Work::Tick {
                index_limit: DEFAULT_INDEX_BATCH,
                inbound_limit: DEFAULT_INBOUND_BATCH,
                selection: SyncSelection::All,
            },
        )
        .expect("tick sync");
        let Output::Ticked(output) = output else {
            panic!("expected sync tick output");
        };
        let report = output.value;

        assert_eq!(report.processed_work, 1);
        assert!(
            !output.events.is_empty(),
            "local summary should produce response events"
        );
        for event in output.events {
            let event = event.into_record();
            assert_eq!(
                event.scope,
                EventScope::Connection(ConnectionScope::Outgoing {
                    connection_id: response_connection_id,
                })
            );
        }
        assert_eq!(
            store
                .table_row_count(worker_schema::SYNC_IN_EVENTS)
                .expect("count sync in"),
            0
        );
    }

    #[test]
    fn tick_prefers_steady_state_route_over_bootstrap_invite_route_for_responses() {
        let store = Protocol::open_memory_store().expect("open store");
        let protocol = Protocol::new();
        let local = endpoint::commands::create_local_keypair().value;
        let remote = endpoint::commands::create_local_keypair().value;
        let inbound_connection_id = [1; 32];
        let bootstrap_route_id = [2; 32];
        let steady_route_id = [3; 32];

        let workspace = workspace::commands::create(workspace::commands::CreateWorkspace {
            created_at_ms: 1,
            public_key: [9; 32],
            name: "sync-route-choice".to_string(),
        })
        .expect("create workspace");
        let workspace_id = workspace.value.workspace_id;
        event_worker::run(&store, &protocol, workspace).expect("admit workspace");

        let mut rows = endpoint::projector::local_endpoint(local);
        rows.extend([
            connection::schema::connection_row(inbound_connection_id, remote.endpoint),
            connection::schema::connection_row(bootstrap_route_id, remote.endpoint),
            connection::schema::connection_row(steady_route_id, remote.endpoint),
            connection::schema::transport_target_row(
                bootstrap_route_id,
                "127.0.0.1:41000".parse().expect("bootstrap route addr"),
            ),
            connection::schema::transport_target_row(
                steady_route_id,
                "127.0.0.1:42000".parse().expect("steady route addr"),
            ),
            connection::schema::bootstrap_workspace_row(bootstrap_route_id, workspace_id),
            endpoint_membership_row(workspace_id, local.endpoint, local.signing_public_key, 10),
            endpoint_membership_row(workspace_id, remote.endpoint, remote.signing_public_key, 11),
        ]);
        store.insert_table_rows(rows).expect("insert sync context");

        let compare = compare::types::CompareEvent {
            connection_id: inbound_connection_id,
            range: compare::types::TimestampRange::ROOT,
            summary: compare::types::RangeSummary::default(),
            response_requested: true,
        };
        let bytes = compare::codec::encode(&compare);
        let record = compare::codec::inbound_record_from_wire(bytes).expect("inbound compare");
        store
            .insert_table_rows(vec![worker_schema::sync_in_event_row(
                inbound_connection_id,
                event_id(&record.canonical_bytes),
                record.canonical_bytes,
            )])
            .expect("insert sync in");

        let index = SyncIndex::default();
        let output = run(
            &store,
            &index,
            Work::DrainIn {
                limit: DEFAULT_INBOUND_BATCH,
            },
        )
        .expect("drain sync in");
        let Output::DrainedIn(output) = output else {
            panic!("expected sync drain output");
        };

        assert!(
            !output.events.is_empty(),
            "local summary should produce response events"
        );
        for event in output.events {
            assert_eq!(
                event.scope,
                EventScope::Connection(ConnectionScope::Outgoing {
                    connection_id: steady_route_id,
                })
            );
        }
    }

    fn routed_sync_store(
        local: endpoint::types::EndpointKeypair,
        remote: endpoint::types::EndpointKeypair,
    ) -> Store {
        let store = Protocol::open_memory_store().expect("open store");
        let connection_id = [3; 32];
        let workspace_id = [5; 32];
        let mut rows = endpoint::projector::local_endpoint(local);
        rows.extend([
            connection::schema::connection_row(connection_id, remote.endpoint),
            connection::schema::transport_target_row(
                connection_id,
                "127.0.0.1:41000".parse().expect("route addr"),
            ),
            endpoint_membership_row(workspace_id, local.endpoint, local.signing_public_key, 20),
            endpoint_membership_row(workspace_id, remote.endpoint, remote.signing_public_key, 21),
        ]);
        store
            .insert_table_rows(rows)
            .expect("insert routed sync context");
        store
    }

    fn endpoint_membership_row(
        workspace_id: EventId,
        endpoint_id: endpoint::types::EndpointId,
        signing_public_key: [u8; 32],
        seed: u8,
    ) -> crate::core::store::TableRow {
        endpoint_shared::schema::endpoint_membership_row(
            [seed; 32],
            [seed.saturating_add(1); 32],
            &endpoint_shared::types::EndpointSharedEvent {
                created_at_ms: seed as u64,
                workspace_id,
                user_authority_event_id: [seed.saturating_add(2); 32],
                endpoint_id,
                signing_public_key,
                endpoint_role: endpoint::types::EndpointRole::Device,
                device_name: format!("endpoint-{seed}"),
            },
        )
    }
}

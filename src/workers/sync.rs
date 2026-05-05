//! Sync worker.
//!
//! Sync is an active protocol, not a projector side effect. Projectors write the
//! rows that make sync possible; this worker performs the stateful comparison
//! work and turns its answers back into normal event records. That keeps
//! negentropy out of the kernel while still making every sync message pass
//! through the same event/module discipline as durable content.
//!
//! The current POC has two wake shapes:
//!
//! ```text
//! manual sync start -> root compare command for each known connection route
//! projected inbound sync event rows -> compare/have/need handler for that connection
//! ```
//!
//! Both paths produce connection-scoped sync events. Those events are
//! transient protocol facts: they can be projected into the connection outbox,
//! wrapped by the connection worker, and deduped while queued, but they are not
//! part of the durable content history. Requested durable events are queued by
//! id for the connection worker; sync does not build data packets.
//!
//! A future dep-aware worker will probably have more queues and cursors, but it
//! should preserve this boundary: sync may query sync-owned indexes and propose
//! sync events; it should not perform TCP IO, mutate content projections, or
//! bypass normal event admission.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;

use crate::core::store::Store;
use crate::protocol::event_modules::connection;
use crate::protocol::event_modules::identity::{endpoint, endpoint_shared};
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::types::{EventId, EventIndexEntry, EventRecord};
use crate::workers::events::CommandOutput;
use crate::workers::sync_index;

use crate::protocol::event_modules::sync::{
    compare,
    compare::types::{RangeSummary, TimestampRange},
    schema,
};

pub const DEFAULT_INBOUND_BATCH: usize = 1024;
const DEFAULT_INDEX_BATCH: usize = 4096;

/// Work accepted by the sync worker.
///
/// `Start` is intentionally explicit because the current control loop is still
/// CLI-driven. `DrainInboundSync` handles work that has already been projected
/// from transient inbound sync events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Work {
    Start {
        selection: SyncSelection,
    },
    DrainInboundSync {
        connection_id: connection::types::ConnectionId,
        limit: usize,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SyncSelection {
    #[default]
    All,
    Today,
}

/// Result of a sync worker action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    Started(CommandOutput<SyncStartReport>),
    DrainedInboundSync(SyncWorkReport),
}

/// Summary of a manual sync start.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncStartReport {
    pub sent_events: usize,
}

/// Records and durable send ids produced by handling inbound sync work.
///
/// `events` are connection-scoped sync records that should be admitted so their
/// projector can queue them for connection transit. `send_event_ids` are
/// durable shared event ids requested by the peer and queued directly to the
/// connection outbox.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncWorkReport {
    pub events: Vec<EventRecord>,
    pub processed_work: usize,
    pub sent_events: usize,
    pub send_event_ids: Vec<crate::protocol::event_modules::types::EventId>,
}

/// Run one sync worker action.
///
/// The only public entrypoint mirrors the other workers. Adding a new sync wake
/// should add a `Work` variant and keep the command/query/projection boundary
/// visible here.
pub fn run(store: &Store, index: &SyncIndex, work: Work) -> Result<Output, String> {
    drain_index_queue(store, index)?;
    index.catch_up(store)?;
    match work {
        Work::Start { selection } => {
            start(store, index, selected_range(store, selection)?).map(Output::Started)
        }
        Work::DrainInboundSync {
            connection_id,
            limit,
        } => {
            drain_inbound_events(store, index, connection_id, limit).map(Output::DrainedInboundSync)
        }
    }
}

fn drain_index_queue(store: &Store, index: &SyncIndex) -> Result<(), String> {
    loop {
        let report = sync_index::run(
            store,
            index,
            sync_index::Work::Drain {
                limit: DEFAULT_INDEX_BATCH,
            },
        )?;
        if report.indexed_events < DEFAULT_INDEX_BATCH {
            return Ok(());
        }
    }
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
    // Manual sync fans out over known routes. The route table is owned by the
    // connection domain; sync only borrows the connection id needed to make a
    // connection-scoped compare event.
    let connections = connection_ids_with_routes(store)?;
    if connections.is_empty() {
        return Ok(CommandOutput::new(SyncStartReport::default()));
    }
    let mut events = Vec::new();
    let mut sent_events = 0;
    let local = local_endpoint(store)?;
    for connection_id in connections {
        let context =
            StoreSyncContext::for_connection(store, index, local.endpoint, connection_id)?;
        if context.workspace_ids.is_empty() {
            continue;
        }
        let report = compare::commands::start(&context, connection_id, range)?;
        events.extend(report.events);
        sent_events += report.sent_events;
    }
    Ok(CommandOutput::with_events(
        SyncStartReport { sent_events },
        events,
    ))
}

fn drain_inbound_events(
    store: &Store,
    index: &SyncIndex,
    connection_id: connection::types::ConnectionId,
    limit: usize,
) -> Result<SyncWorkReport, String> {
    let mut result = SyncWorkReport::default();
    let limit = limit.max(1);
    let works = inbound_events_for_connection(store, connection_id, limit)?;
    result.processed_work = works.len();
    let mut consumed = Vec::with_capacity(works.len());
    let mut outbox_rows = Vec::new();
    for work in works {
        let local = local_endpoint(store)?;
        let context =
            StoreSyncContext::for_connection(store, index, local.endpoint, work.connection_id)?;
        let report = compare::commands::handle_inbound_event(
            &context,
            work.connection_id,
            &work.event_bytes,
        )?;
        result.sent_events += report.sent_events;
        result.events.extend(report.events);
        for event_id in report.send_event_ids {
            outbox_rows.push(connection::schema::outbox_row(work.connection_id, event_id));
            result.send_event_ids.push(event_id);
        }
        consumed.push(work.key());
    }
    if !outbox_rows.is_empty() {
        store
            .insert_table_rows(outbox_rows)
            .map_err(|err| format!("queue requested durable events: {err}"))?;
    }
    if !consumed.is_empty() {
        store
            .delete_table_rows(schema::INBOUND_EVENTS, consumed)
            .map_err(|err| format!("delete inbound sync events: {err}"))?;
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
    fn summary(
        &self,
        range: compare::types::TimestampRange,
    ) -> Result<compare::types::RangeSummary, String> {
        let mut summary = RangeSummary::default();
        for entry in self.entries_in_range(range)? {
            summary.count += 1;
            xor_into(&mut summary.fingerprint, &fingerprint_id(&entry.event_id));
        }
        Ok(summary)
    }

    fn ids_in_range(
        &self,
        range: compare::types::TimestampRange,
    ) -> Result<Vec<crate::protocol::event_modules::types::EventIndexEntry>, String> {
        self.entries_in_range(range)
    }

    fn timestamp_bounds(
        &self,
        range: compare::types::TimestampRange,
    ) -> Result<Option<(u64, u64)>, String> {
        let entries = self.entries_in_range(range)?;
        let Some(first) = entries.first() else {
            return Ok(None);
        };
        let last = entries.last().unwrap_or(first);
        Ok(Some((first.timestamp, last.timestamp)))
    }

    fn has_event(
        &self,
        event_id: &crate::protocol::event_modules::types::EventId,
    ) -> Result<bool, String> {
        self.index.has_event(event_id)
    }

    fn dependency_closure_entries(
        &self,
        roots: &[crate::protocol::event_modules::types::EventIndexEntry],
    ) -> Result<Vec<crate::protocol::event_modules::types::EventIndexEntry>, String> {
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
        connection_id: crate::protocol::event_modules::types::EventId,
        entries: Vec<crate::protocol::event_modules::types::EventIndexEntry>,
    ) -> Result<Vec<crate::protocol::event_modules::types::EventIndexEntry>, String> {
        self.index.fresh_have_entries(
            connection_id,
            entries
                .into_iter()
                .filter(|entry| self.entry_is_allowed(entry))
                .collect(),
        )
    }

    fn can_send_event(
        &self,
        event_id: &crate::protocol::event_modules::types::EventId,
    ) -> Result<bool, String> {
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

fn inbound_events_for_connection(
    store: &Store,
    connection_id: connection::types::ConnectionId,
    limit: usize,
) -> Result<Vec<schema::InboundSyncEvent>, String> {
    let prefix = schema::inbound_event_prefix(connection_id);
    store
        .table_rows_with_key_prefix(schema::INBOUND_EVENTS, &prefix, limit)
        .map_err(|err| format!("load inbound sync events: {err}"))?
        .into_iter()
        .map(|(key, value)| schema::decode_inbound_event(key, value))
        .collect()
}

// ---------------------------------------------------------------------------
// In-memory negentropy index
// ---------------------------------------------------------------------------

/// Process-local negentropy state owned by the sync worker.
///
/// SQLite remains the source of truth for canonical events. This index catches
/// up from the shared-event feed, updates a timestamp tree along each inserted
/// event's path, and serves range summaries without rebuilding hashes for every
/// compare. In the current CLI each command gets a fresh process and may rebuild
/// once at startup; in the intended long-lived control loop the same structure
/// stays warm and receives only path updates for new shared events.
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

    fn fresh_have_entries(
        &self,
        connection_id: EventId,
        entries: Vec<EventIndexEntry>,
    ) -> Result<Vec<EventIndexEntry>, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "sync index mutex poisoned".to_string())?;
        Ok(state.fresh_have_entries(connection_id, entries))
    }
}

#[derive(Debug, Default)]
struct IndexState {
    indexed: HashSet<EventId>,
    nodes: HashMap<NodeKey, RangeSummary>,
    ids_by_time: BTreeMap<(u64, EventId), EventIndexEntry>,
    entries_by_id: HashMap<EventId, EventIndexEntry>,
    deps_by_event: HashMap<EventId, Vec<EventId>>,
    advertised_haves_by_connection: HashMap<EventId, HashSet<EventId>>,
}

impl IndexState {
    fn insert(&mut self, entry: EventIndexEntry) {
        let fingerprint = fingerprint_id(&entry.event_id);
        for depth in 0..=64 {
            let key = NodeKey::for_timestamp(entry.timestamp, depth);
            let summary = self.nodes.entry(key).or_default();
            summary.count += 1;
            xor_into(&mut summary.fingerprint, &fingerprint);
        }
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

    fn fresh_have_entries(
        &mut self,
        connection_id: EventId,
        entries: Vec<EventIndexEntry>,
    ) -> Vec<EventIndexEntry> {
        let advertised = self
            .advertised_haves_by_connection
            .entry(connection_id)
            .or_default();
        entries
            .into_iter()
            .filter(|entry| advertised.insert(entry.event_id))
            .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct NodeKey {
    depth: u8,
    prefix: u64,
}

impl NodeKey {
    fn for_timestamp(timestamp: u64, depth: u8) -> Self {
        debug_assert!(depth <= 64);
        let prefix = if depth == 0 {
            0
        } else {
            timestamp >> (64 - depth)
        };
        Self { depth, prefix }
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

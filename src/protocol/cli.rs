//! Topo CLI command registry.
//!
//! This file is intentionally a shell. Command names, argv parsing, help text,
//! worker calls, follow-up queries, and output formatting belong in the closest
//! scoped `cli.rs` under `event_modules/`. The protocol shell only assembles
//! those command specs, adds whole-protocol status aliases, and provides the
//! small context object those specs share.
//!
//! The runner lives in core and knows nothing about Topo. This registry is the
//! place where the current protocol says, "these are my commands." If command
//! behavior starts appearing here, move it back to the owning module.

use std::path::Path;

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::core::logical_clock;
use crate::core::network_queues::InboundNetworkRow;
use crate::core::store::Store;
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::types::{EventRecord, ReceiveMetadata};
use crate::protocol::event_modules::worker::{
    AdmitDecision, EventRegistry, EventWithContext, ProjectionOutput, ReceivedRecord,
};
use crate::protocol::{event_modules, Protocol};
use crate::protocol::workers::DaemonWorkerContext;

const CLOCK_USAGE: &str = "clock [set TIMESTAMP|advance DELTA|clear]";
const COUNT_USAGE: &str = "count";
const STATUS_USAGE: &str = "status";
const SYNC_STATUS_USAGE: &str = "sync-status";
const NEGENTROPY_DRAIN_USAGE: &str = "negentropy-drain [LIMIT]";

pub struct Context {
    pub db_path: std::path::PathBuf,
    pub store: Store,
    pub protocol: Protocol,
}

impl Context {
    pub fn open(db_path: impl AsRef<Path>) -> Result<Self, String> {
        let db_path = db_path.as_ref().to_path_buf();
        Ok(Self {
            store: Protocol::open_store(&db_path).map_err(|err| format!("open store: {err}"))?,
            protocol: Protocol::new(),
            db_path,
        })
    }
}

// The shared CLI/daemon context delegates protocol behavior to `Protocol` while
// exposing the store and persistent worker state required by the generic runner.
impl EventRegistry for Context {
    fn record_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        self.protocol.record_from_bytes(bytes)
    }

    fn project_network_in(
        &self,
        store: &Store,
        inbound: &InboundNetworkRow,
    ) -> Result<ProjectionOutput, String> {
        self.protocol.project_network_in(store, inbound)
    }

    fn record_from_canonical_in(
        &self,
        store: &Store,
        bytes: Vec<u8>,
        receive: Option<ReceiveMetadata>,
        provenance: Option<crate::protocol::workers::schema::TransitProvenance>,
    ) -> Result<ReceivedRecord, String> {
        self.protocol
            .record_from_canonical_in(store, bytes, receive, provenance)
    }

    fn project_record(
        &self,
        store: &Store,
        event: &EventWithContext<'_>,
    ) -> Result<ProjectionOutput, String> {
        self.protocol.project_record(store, event)
    }

    fn admit_received_record(
        &self,
        store: &Store,
        record: &EventRecord,
    ) -> Result<AdmitDecision, String> {
        self.protocol.admit_received_record(store, record)
    }
}

impl DaemonWorkerContext for Context {
    fn store(&self) -> &Store {
        &self.store
    }

    fn sync_index(&self) -> &event_modules::sync::SyncIndex {
        self.protocol.sync_index()
    }
}

pub fn commands() -> Vec<CliCommand<Context>> {
    let mut out = Vec::new();
    out.extend(event_modules::identity::admin::cli::commands());
    out.extend(event_modules::identity::user::cli::commands());
    out.extend(event_modules::identity::endpoint_shared::cli::commands());
    out.extend(event_modules::identity::cli::commands());
    out.extend(event_modules::connection::cli::commands());
    out.extend(event_modules::content::content_event::cli::commands());
    out.extend(event_modules::content::message::cli::commands());
    out.extend(event_modules::content::reaction::cli::commands());
    out.extend(event_modules::content::message_deletion::cli::commands());
    out.extend(event_modules::content::file::cli::commands());
    out.extend(event_modules::content::file_deletion::cli::commands());
    out.extend(event_modules::content::cli::commands());
    out.extend(event_modules::encryption::cli::commands());
    out.extend(event_modules::sync::cli::commands());
    out.extend(event_modules::test_events::event_with_deps::cli::commands());
    out.extend([
        clock_command(),
        count_command("count", COUNT_USAGE),
        count_command("status", STATUS_USAGE),
        sync_status_command(),
        negentropy_drain_command(),
    ]);
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountSummary {
    pub events: usize,
    pub payload_bytes: usize,
    pub connections: usize,
    pub connection_events: usize,
    pub invite_accepted: usize,
    pub ready_events: usize,
    pub blocked_events: usize,
    pub applied_events: usize,
    pub rejected_events: usize,
    pub blocked_edges: usize,
}

impl CountSummary {
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("events: {}", self.events),
            format!("payload_bytes: {}", self.payload_bytes),
            format!("connections: {}", self.connections),
            format!("connection_events: {}", self.connection_events),
            format!("invite_accepted: {}", self.invite_accepted),
            format!("ready_events: {}", self.ready_events),
            format!("blocked_events: {}", self.blocked_events),
            format!("applied_events: {}", self.applied_events),
            format!("rejected_events: {}", self.rejected_events),
            format!("blocked_edges: {}", self.blocked_edges),
        ]
    }
}

fn count_command(name: &'static str, usage: &'static str) -> CliCommand<Context> {
    CliCommand {
        name,
        usage,
        help: "Print protocol-wide event counts.",
        run: run_count_command,
    }
}

fn run_count_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(0, COUNT_USAGE)?;
    let events =
        event_schema::event_count(&context.store).map_err(|err| format!("count events: {err}"))?;
    let payload_bytes =
        event_schema::body_bytes(&context.store).map_err(|err| format!("count bytes: {err}"))?;
    let connections = event_modules::connection::queries::connection_count(&context.store)?;
    let connection_events =
        event_modules::connection::queries::connection_event_count(&context.store)?;
    let invite_accepted =
        event_modules::identity::invite_accepted::schema::invite_accepted_count(&context.store)?;
    let statuses = event_schema::status_counts(&context.store)
        .map_err(|err| format!("count event statuses: {err}"))?;
    Ok(CliOutput::lines(
        CountSummary {
            events,
            payload_bytes,
            connections,
            connection_events,
            invite_accepted,
            ready_events: statuses.ready,
            blocked_events: statuses.blocked,
            applied_events: statuses.applied,
            rejected_events: statuses.rejected,
            blocked_edges: statuses.blocked_edges,
        }
        .lines(),
    ))
}

fn clock_command() -> CliCommand<Context> {
    CliCommand {
        name: "clock",
        usage: CLOCK_USAGE,
        help: "Show or adjust this store's logical timestamp lower bound.",
        run: run_clock_command,
    }
}

fn run_clock_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    match args.values() {
        [] => {}
        [op, timestamp] if op == "set" => {
            logical_clock::set_logical_time(&context.store, parse_u64(timestamp)?)?;
        }
        [op, delta] if op == "advance" => {
            logical_clock::advance_logical_time(&context.store, parse_u64(delta)?)?;
        }
        [op] if op == "clear" => {
            logical_clock::clear_logical_time(&context.store)?;
        }
        _ => return Err(CLOCK_USAGE.to_string()),
    }
    clock_output(&context.store)
}

fn clock_output(store: &Store) -> Result<CliOutput, String> {
    let logical_time = logical_clock::logical_time(store)?;
    let max_event_timestamp =
        event_schema::max_timestamp(store).map_err(|err| format!("load max timestamp: {err}"))?;
    let next_timestamp = logical_clock::next_timestamp(store, max_event_timestamp)?;
    Ok(CliOutput::lines(vec![
        format!(
            "logical_time: {}",
            logical_time
                .map(|timestamp| timestamp.to_string())
                .unwrap_or_else(|| "unset".to_string())
        ),
        format!("max_event_timestamp: {max_event_timestamp}"),
        format!("next_timestamp: {next_timestamp}"),
    ]))
}

fn parse_u64(value: &str) -> Result<u64, String> {
    value.parse::<u64>().map_err(|_| CLOCK_USAGE.to_string())
}

/// Inspect the in-memory negentropy `SyncIndex` and the durable
/// pending-purge queue.
///
/// Returned lines:
///   * `indexed_events: <usize>` — number of admitted ids in the index
///   * `root_count: <u64>` — total ids contributing to the root summary
///   * `root_fingerprint: <hex>` — XOR-fold of per-id fingerprints
///   * `pending_purges: <usize>` — queued rows the drainer has not run on
///
/// Tests for the negentropy purge drainer assert root_fingerprint
/// equality across two peers and zero pending_purges after a daemon
/// tick. The catch-up call mirrors `prepare_index_for_response` so a
/// CLI invocation outside the daemon sees the same index state the
/// daemon would.
fn sync_status_command() -> CliCommand<Context> {
    CliCommand {
        name: "sync-status",
        usage: SYNC_STATUS_USAGE,
        help: "Print the in-memory negentropy index size, root summary, and pending-purge queue size.",
        run: run_sync_status_command,
    }
}

fn run_sync_status_command(
    context: &mut Context,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    args.require_len(0, SYNC_STATUS_USAGE)?;
    let index = context.protocol.sync_index();
    // Catch the in-memory index up from durable rows so a fresh CLI
    // invocation (no running daemon) sees the same state the daemon
    // would after one `sync_tick` step. Then run the negentropy purge
    // drainer so pending purge rows are applied to the index — that
    // way `root_fingerprint` reflects the post-purge state on a
    // CLI-only inspection, not just the post-purge state on a
    // running daemon.
    index
        .catch_up(&context.store)
        .map_err(|err| format!("catch up sync index: {err}"))?;
    let _ = crate::protocol::workers::negentropy_purge_drainer::run(
        &context.store,
        index,
        crate::protocol::workers::negentropy_purge_drainer::Work::Drain {
            limit: usize::MAX,
        },
    )
    .map_err(|err| format!("drain negentropy purges: {err}"))?;
    let summary = index.root_summary()?;
    let count = index.indexed_event_count()?;
    let pending = event_modules::sync::schema::pending_purge_count(&context.store)
        .map_err(|err| format!("count pending purges: {err}"))?;
    Ok(CliOutput::lines(vec![
        format!("indexed_events: {count}"),
        format!("root_count: {}", summary.count),
        format!("root_fingerprint: {}", hex_bytes(&summary.fingerprint)),
        format!("pending_purges: {pending}"),
    ]))
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Manually invoke one tick of the `negentropy_purge_drainer` worker.
///
/// Useful for tests and operators who want to force a drain without
/// waiting for the daemon's sync_tick. Output mirrors `sync-status`'s
/// post-drain shape so test callers can assert on the same fields:
///
///   * `drained: <count>` — rows pulled from `negentropy_pending_purges`
///   * `remaining_pending: <count>` — queue rows still waiting after this tick
///   * `new_root_count: <count>` — admitted ids contributing to the index
///   * `new_root_fingerprint: <hex>` — XOR-fold of per-id fingerprints
fn negentropy_drain_command() -> CliCommand<Context> {
    CliCommand {
        name: "negentropy-drain",
        usage: NEGENTROPY_DRAIN_USAGE,
        help: "Manually run one tick of the negentropy purge drainer; \
               useful for forcing a drain in tests or after operator \
               intervention without waiting for the daemon.",
        run: run_negentropy_drain_command,
    }
}

fn run_negentropy_drain_command(
    context: &mut Context,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    if args.values().len() > 1 {
        return Err(NEGENTROPY_DRAIN_USAGE.to_string());
    }
    let limit = match args.get(0) {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| NEGENTROPY_DRAIN_USAGE.to_string())?,
        None => crate::protocol::workers::negentropy_purge_drainer::DEFAULT_DRAIN_LIMIT,
    };
    let index = context.protocol.sync_index();
    // Same sequencing as `sync-status`: catch the in-memory index up
    // from durable rows so a CLI invocation outside the daemon sees
    // the same starting state the daemon would.
    index
        .catch_up(&context.store)
        .map_err(|err| format!("catch up sync index: {err}"))?;
    let report = crate::protocol::workers::negentropy_purge_drainer::run(
        &context.store,
        index,
        crate::protocol::workers::negentropy_purge_drainer::Work::Drain { limit },
    )
    .map_err(|err| format!("drain negentropy purges: {err}"))?;
    let summary = index.root_summary()?;
    let remaining = event_modules::sync::schema::pending_purge_count(&context.store)
        .map_err(|err| format!("count pending purges: {err}"))?;
    Ok(CliOutput::lines(vec![
        format!("drained: {}", report.drained_rows),
        format!("removed_from_index: {}", report.removed_from_index),
        format!("remaining_pending: {remaining}"),
        format!("new_root_count: {}", summary.count),
        format!(
            "new_root_fingerprint: {}",
            hex_bytes(&summary.fingerprint)
        ),
    ]))
}

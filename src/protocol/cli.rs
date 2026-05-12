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
    EventRegistry, EventWithContext, ProjectionOutput, ReceivedRecord,
};
use crate::protocol::{event_modules, Protocol};
use crate::workers::DaemonWorkerContext;

const CLOCK_USAGE: &str = "clock [set TIMESTAMP|advance DELTA|clear]";
const COUNT_USAGE: &str = "count";
const STATUS_USAGE: &str = "status";

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
        provenance: Option<crate::workers::schema::TransitProvenance>,
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

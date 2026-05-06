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
use crate::core::store::Store;
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::{clock, event_modules, Protocol};

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

pub fn commands() -> Vec<CliCommand<Context>> {
    let mut out = Vec::new();
    out.extend(event_modules::identity::cli::commands());
    out.extend(event_modules::connection::cli::commands());
    out.extend(event_modules::content::content_event::cli::commands());
    out.extend(event_modules::content::message::cli::commands());
    out.extend(event_modules::content::reaction::cli::commands());
    out.extend(event_modules::content::message_deletion::cli::commands());
    out.extend(event_modules::content::file::cli::commands());
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
    let statuses = event_schema::status_counts(&context.store)
        .map_err(|err| format!("count event statuses: {err}"))?;
    Ok(CliOutput::lines(
        CountSummary {
            events,
            payload_bytes,
            connections,
            connection_events,
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
            clock::set_logical_time(&context.store, parse_u64(timestamp)?)?;
        }
        [op, delta] if op == "advance" => {
            clock::advance_logical_time(&context.store, parse_u64(delta)?)?;
        }
        [op] if op == "clear" => {
            clock::clear_logical_time(&context.store)?;
        }
        _ => return Err(CLOCK_USAGE.to_string()),
    }
    clock_output(&context.store)
}

fn clock_output(store: &Store) -> Result<CliOutput, String> {
    let logical_time = clock::logical_time(store)?;
    let max_event_timestamp =
        event_schema::max_timestamp(store).map_err(|err| format!("load max timestamp: {err}"))?;
    let next_timestamp = clock::next_timestamp(store, max_event_timestamp)?;
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

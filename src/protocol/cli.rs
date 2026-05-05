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
use crate::protocol::{event_modules, Protocol};

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
    out.extend(event_modules::sync::cli::commands());
    out.extend(event_modules::test_events::event_with_deps::cli::commands());
    out.extend([
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

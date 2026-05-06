//! CLI summaries for dependency-cascade tests.
//!
//! The output names the observable admission behavior: how many events were
//! staged, how many were blocked by reverse replay, and whether the final drain
//! applied everything. These summaries are intentionally close to the event
//! module so black-box tests can stay small.

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::protocol::cli::Context;
use crate::protocol::clock;
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::types::EventIndexEntry;
use crate::protocol::event_modules::worker::{self, CommandOutput};

const GENERATE_DEPS_USAGE: &str = "generate-deps NUM_EVENTS DEPS_PER_EVENT";
const GENERATE_DEPS_RECENT_ROOT_USAGE: &str = "generate-deps-recent-root OLD_EVENTS DEPS_PER_EVENT";
const GENERATE_DEPS_RECENT_SHARED_CLOSURE_USAGE: &str =
    "generate-deps-recent-shared-closure OLD_EVENTS RECENT_EVENTS";
const REPLAY_DEPS_REVERSE_USAGE: &str = "replay-deps-reverse";

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![
        CliCommand {
            name: "generate-deps",
            usage: GENERATE_DEPS_USAGE,
            help: "Stage dependency-bearing test events.",
            run: run_generate_command,
        },
        CliCommand {
            name: "generate-deps-recent-root",
            usage: GENERATE_DEPS_RECENT_ROOT_USAGE,
            help: "Generate one newest dependency-bearing event rooted in old events.",
            run: run_generate_recent_root_command,
        },
        CliCommand {
            name: "generate-deps-recent-shared-closure",
            usage: GENERATE_DEPS_RECENT_SHARED_CLOSURE_USAGE,
            help: "Generate many newest roots that share the same old dependency closure.",
            run: run_generate_recent_shared_closure_command,
        },
        CliCommand {
            name: "replay-deps-reverse",
            usage: REPLAY_DEPS_REVERSE_USAGE,
            help: "Replay staged dependency-bearing events in reverse order.",
            run: run_replay_reverse_command,
        },
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventWithDepsStageSummary {
    pub staged_events: usize,
    pub deps_per_event: usize,
    pub dep_edges: usize,
    pub first_timestamp: u64,
    pub last_timestamp: u64,
}

impl EventWithDepsStageSummary {
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("staged_events: {}", self.staged_events),
            format!("deps_per_event: {}", self.deps_per_event),
            format!("dep_edges: {}", self.dep_edges),
            format!("first_timestamp: {}", self.first_timestamp),
            format!("last_timestamp: {}", self.last_timestamp),
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventWithDepsRecentRootSummary {
    pub generated_events: usize,
    pub dep_edges: usize,
    pub timestamp: u64,
}

impl EventWithDepsRecentRootSummary {
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("generated_events: {}", self.generated_events),
            format!("dep_edges: {}", self.dep_edges),
            format!("timestamp: {}", self.timestamp),
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventWithDepsRecentSharedClosureSummary {
    pub generated_events: usize,
    pub dep_edges: usize,
    pub first_timestamp: u64,
    pub last_timestamp: u64,
}

impl EventWithDepsRecentSharedClosureSummary {
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("generated_events: {}", self.generated_events),
            format!("dep_edges: {}", self.dep_edges),
            format!("first_timestamp: {}", self.first_timestamp),
            format!("last_timestamp: {}", self.last_timestamp),
        ]
    }
}

fn run_generate_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(2, GENERATE_DEPS_USAGE)?;
    let num_events = args.parse_positive_usize(0, GENERATE_DEPS_USAGE)?;
    let deps_per_event = args.parse_positive_usize(1, GENERATE_DEPS_USAGE)?;
    let read = EventWithDepsContext::new(&context.store)?;
    let output = super::commands::stage_next(&read, num_events, deps_per_event)
        .map_err(|err| format!("stage event_with_deps: {err}"))?;
    let (report, _) = worker::run(&context.store, &context.protocol, output)
        .map_err(|err| format!("admit staged event_with_deps: {err}"))?;
    Ok(CliOutput::lines(
        EventWithDepsStageSummary {
            staged_events: report.staged_events,
            deps_per_event: report.deps_per_event,
            dep_edges: report.dep_edges,
            first_timestamp: report.first_timestamp,
            last_timestamp: report.last_timestamp,
        }
        .lines(),
    ))
}

fn run_generate_recent_root_command(
    context: &mut Context,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    args.require_len(2, GENERATE_DEPS_RECENT_ROOT_USAGE)?;
    let old_events = args.parse_positive_usize(0, GENERATE_DEPS_RECENT_ROOT_USAGE)?;
    let deps_per_event = args.parse_positive_usize(1, GENERATE_DEPS_RECENT_ROOT_USAGE)?;
    let read = EventWithDepsContext::new(&context.store)?;
    let output = super::commands::recent_root_from_old_events(&read, old_events, deps_per_event)
        .map_err(|err| format!("generate recent event_with_deps root: {err}"))?;
    let report = worker::run(
        &context.store,
        &context.protocol,
        worker::AdmitAndDrain {
            output,
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("admit and drain recent event_with_deps root: {err}"))?;
    if report.admitted.blocked_events > 0 {
        return Err(format!(
            "recent event_with_deps root blocked on {} dependencies",
            report.admitted.blocked_edges
        ));
    }
    Ok(CliOutput::lines(
        EventWithDepsRecentRootSummary {
            generated_events: report.value.generated_events,
            dep_edges: report.value.dep_edges,
            timestamp: report.value.timestamp,
        }
        .lines(),
    ))
}

fn run_generate_recent_shared_closure_command(
    context: &mut Context,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    args.require_len(2, GENERATE_DEPS_RECENT_SHARED_CLOSURE_USAGE)?;
    let old_events = args.parse_positive_usize(0, GENERATE_DEPS_RECENT_SHARED_CLOSURE_USAGE)?;
    let recent_events = args.parse_positive_usize(1, GENERATE_DEPS_RECENT_SHARED_CLOSURE_USAGE)?;
    let read = EventWithDepsContext::new(&context.store)?;
    let output = super::commands::recent_roots_with_shared_dep_closure_from_old_events(
        &read,
        old_events,
        recent_events,
    )
    .map_err(|err| format!("generate recent event_with_deps shared closure: {err}"))?;
    let report = worker::run(
        &context.store,
        &context.protocol,
        worker::AdmitAndDrain {
            output,
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("admit and drain recent event_with_deps shared closure: {err}"))?;
    if report.admitted.blocked_events > 0 {
        return Err(format!(
            "recent event_with_deps shared closure roots blocked on {} dependencies",
            report.admitted.blocked_edges
        ));
    }
    Ok(CliOutput::lines(
        EventWithDepsRecentSharedClosureSummary {
            generated_events: report.value.generated_events,
            dep_edges: report.value.dep_edges,
            first_timestamp: report.value.first_timestamp,
            last_timestamp: report.value.last_timestamp,
        }
        .lines(),
    ))
}

fn run_replay_reverse_command(
    context: &mut Context,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    args.require_len(0, REPLAY_DEPS_REVERSE_USAGE)?;
    let records = super::queries::staged_records(&context.store)
        .map_err(|err| format!("load staged event_with_deps: {err}"))?;
    if records.is_empty() {
        return Err("no staged event_with_deps to replay".to_string());
    }

    let max_deps = records
        .iter()
        .map(|record| record.dependencies.len())
        .max()
        .unwrap_or(0);
    let root_count = records.len().min(max_deps.max(1));
    let reverse_non_roots = records[root_count..].iter().rev().cloned().collect();
    let (_, reverse_report) = worker::run(
        &context.store,
        context.protocol.modules(),
        CommandOutput::with_events((), reverse_non_roots),
    )
    .map_err(|err| format!("admit reverse event_with_deps: {err}"))?;

    let blocked_after_reverse = event_schema::status_counts(&context.store)
        .map_err(|err| format!("count blocked reverse events: {err}"))?
        .blocked;

    let roots = records[..root_count].to_vec();
    let root_report = worker::run(
        &context.store,
        context.protocol.modules(),
        worker::AdmitAndDrain {
            output: CommandOutput::with_events((), roots),
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("admit and drain event_with_deps roots: {err}"))?;
    let final_counts = event_schema::status_counts(&context.store)
        .map_err(|err| format!("count event_with_deps replay statuses: {err}"))?;

    Ok(CliOutput::lines(
        EventWithDepsReplaySummary {
            replayed_events: records.len(),
            blocked_after_reverse,
            applied_events: reverse_report.applied_events
                + root_report.admitted.applied_events
                + root_report.drained.applied_events,
            ready_events: final_counts.ready,
            blocked_events: final_counts.blocked,
            blocked_edges: final_counts.blocked_edges,
        }
        .lines(),
    ))
}

struct EventWithDepsContext {
    max_timestamp: u64,
    event_index_entries: Vec<EventIndexEntry>,
}

impl EventWithDepsContext {
    fn new(store: &crate::core::store::Store) -> Result<Self, String> {
        let max_timestamp = event_schema::max_timestamp(store)
            .map_err(|err| format!("load max timestamp: {err}"))?;
        Ok(Self {
            max_timestamp: clock::max_timestamp_for_next(store, max_timestamp)?,
            event_index_entries: event_schema::event_index_entries_in_timestamp_range(
                store,
                0,
                u64::MAX,
            )
            .map_err(|err| format!("load dependency event ids: {err}"))?,
        })
    }
}

impl super::commands::EventWithDepsRead for EventWithDepsContext {
    fn max_timestamp(&self) -> Result<u64, String> {
        Ok(self.max_timestamp)
    }

    fn event_index_entries(&self) -> Result<Vec<EventIndexEntry>, String> {
        Ok(self.event_index_entries.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventWithDepsReplaySummary {
    pub replayed_events: usize,
    pub blocked_after_reverse: usize,
    pub applied_events: usize,
    pub ready_events: usize,
    pub blocked_events: usize,
    pub blocked_edges: usize,
}

impl EventWithDepsReplaySummary {
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("replayed_events: {}", self.replayed_events),
            format!("blocked_after_reverse: {}", self.blocked_after_reverse),
            format!("applied_events: {}", self.applied_events),
            format!("ready_events: {}", self.ready_events),
            format!("blocked_events: {}", self.blocked_events),
            format!("blocked_edges: {}", self.blocked_edges),
        ]
    }
}

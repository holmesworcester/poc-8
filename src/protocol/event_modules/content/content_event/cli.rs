//! Content-event CLI command and summary.
//!
//! `generate` creates this one event type, so its argv shape and output live at
//! the leaf module rather than the content domain root. Authorization material is
//! read from the local endpoint and endpoint-membership projections, then passed
//! into the content command explicitly.

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::core::logical_clock;
use crate::protocol::cli::Context;
use crate::protocol::event_modules::identity::{endpoint, endpoint_shared};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker;

use super::queries;

const GENERATE_USAGE: &str = "generate WORKSPACE_ID_HEX NUM_EVENTS EVENT_SIZE_BYTES";
const CONTENT_COUNT_USAGE: &str = "content-count WORKSPACE_ID_HEX";

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![
        CliCommand {
            name: "generate",
            usage: GENERATE_USAGE,
            help: "Generate content events.",
            run: run_generate_command,
        },
        CliCommand {
            name: "content-count",
            usage: CONTENT_COUNT_USAGE,
            help: "Print content counts for one workspace.",
            run: run_content_count_command,
        },
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateSummary {
    pub generated_events: usize,
    pub applied_events: usize,
    pub event_size: usize,
    pub first_timestamp: u64,
    pub last_timestamp: u64,
}

impl GenerateSummary {
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("generated_events: {}", self.generated_events),
            format!("applied_events: {}", self.applied_events),
            format!("event_size_bytes: {}", self.event_size),
            format!("first_timestamp: {}", self.first_timestamp),
            format!("last_timestamp: {}", self.last_timestamp),
        ]
    }
}

fn run_generate_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(3, GENERATE_USAGE)?;
    let workspace_id = parse_hex_id(args.get(0).expect("length checked"), GENERATE_USAGE)?;
    let num_events = args.parse_positive_usize(1, GENERATE_USAGE)?;
    let event_size = args.parse_positive_usize(2, GENERATE_USAGE)?;
    let local = endpoint::commands::local_keypair(&context.store)?
        .ok_or_else(|| "local endpoint is missing".to_string())?;
    let membership_key =
        endpoint_shared::schema::endpoint_membership_key(local.endpoint, workspace_id);
    let membership_bytes = context
        .store
        .table_row(
            endpoint_shared::schema::ENDPOINT_MEMBERSHIPS,
            &membership_key,
        )
        .map_err(|err| format!("load local endpoint membership: {err}"))?
        .ok_or_else(|| "local endpoint is not joined to workspace".to_string())?;
    let membership = endpoint_shared::schema::decode_endpoint_membership_row(
        &membership_key,
        &membership_bytes,
    )?;
    if membership.signing_public_key != local.signing_public_key {
        return Err("local endpoint signing key does not match workspace membership".to_string());
    }

    let start = logical_clock::next_timestamp(
        &context.store,
        queries::max_timestamp_for_workspace(&context.store, workspace_id)?,
    )?;
    let output = super::commands::generate(
        workspace_id,
        membership.endpoint_shared_id,
        local.signing_secret,
        start,
        num_events,
        event_size,
    )
    .map_err(|err| format!("generate: {err}"))?;
    let report = worker::run(
        &context.store,
        &context.protocol,
        worker::AdmitAndDrain {
            output,
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("admit and drain generated events: {err}"))?;
    Ok(CliOutput::lines(
        GenerateSummary {
            generated_events: report.admitted.inserted_events,
            applied_events: report.admitted.applied_events + report.drained.applied_events,
            event_size,
            first_timestamp: report.value.first_timestamp,
            last_timestamp: report.value.last_timestamp,
        }
        .lines(),
    ))
}

fn run_content_count_command(
    context: &mut Context,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    args.require_len(1, CONTENT_COUNT_USAGE)?;
    let workspace_id = parse_hex_id(args.get(0).expect("length checked"), CONTENT_COUNT_USAGE)?;
    let events = queries::count_for_workspace(&context.store, workspace_id)?;
    let payload_bytes = queries::payload_bytes_for_workspace(&context.store, workspace_id)?;
    Ok(CliOutput::lines(vec![
        format!("workspace_id: {}", args.get(0).expect("length checked")),
        format!("content_events: {events}"),
        format!("content_payload_bytes: {payload_bytes}"),
    ]))
}

fn parse_hex_id(value: &str, usage: &str) -> Result<EventId, String> {
    if value.len() != 64 {
        return Err(usage.to_string());
    }
    let mut out = [0; 32];
    let bytes = value.as_bytes();
    for idx in 0..32 {
        out[idx] = (hex_value(bytes[idx * 2], usage)? << 4) | hex_value(bytes[idx * 2 + 1], usage)?;
    }
    Ok(out)
}

fn hex_value(byte: u8, usage: &str) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(usage.to_string()),
    }
}

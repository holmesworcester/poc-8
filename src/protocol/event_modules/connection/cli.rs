//! Connection CLI commands and summaries.
//!
//! This file is the user-facing adapter for connection commands. It parses argv,
//! sends a connection request, and formats the report. Ongoing daemon
//! scheduling uses the core daemon runner and the `src/workers` catalog.

use super::connection_request;
use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::protocol::cli::Context;
use crate::protocol::event_modules::worker;
use crate::workers::transit_out;

const CONNECT_USAGE: &str = "connect INVITE_LINK";

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![CliCommand {
        name: "connect",
        usage: CONNECT_USAGE,
        help: "Connect to an invite over real TCP.",
        run: run_connect_command,
    }]
}

fn run_connect_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(1, CONNECT_USAGE)?;
    let output = connection_request::commands::create_with_local(
        &context.store,
        args.get(0).expect("length checked"),
    )?;
    let (request, _) = worker::run(&context.store, &context.protocol, output)
        .map_err(|err| format!("record connection request: {err}"))?;
    let report = transit_out::run(
        &context.store,
        transit_out::Work::SendConnectionRequest {
            connection_id: request.connection_id,
            addr: request.addr,
            bytes: request.bytes,
        },
    )?;
    Ok(CliOutput::lines(vec![
        format!("connected: {}", request.addr),
        format!("routes_synced: {}", report.routes_synced),
        format!("sent_events: {}", report.sent_events),
    ]))
}

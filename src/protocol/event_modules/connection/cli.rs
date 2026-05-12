//! Connection CLI commands and summaries.
//!
//! This file is the user-facing adapter for connection commands. It parses argv,
//! sends a connection request, and formats the report. Ongoing daemon
//! scheduling uses the core daemon runner and the `src/protocol/workers` catalog.

use std::time::Duration;

use super::connection_request;
use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::protocol::cli::Context;
use crate::protocol::event_modules::worker;
use crate::protocol::workers::connection as connection_worker;

const CONNECT_USAGE: &str = "connect INVITE_LINK";
const CONNECT_WAIT: Duration = Duration::from_secs(2);

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
    // Read the running daemon's bound listener (if any) from the core-owned
    // lock file. None when no daemon is running for this DB.
    let from_listen_addr = crate::core::daemon::current_listen_addr(&context.db_path)?;
    let output = connection_request::commands::create_with_local(
        &context.store,
        args.get(0).expect("length checked"),
        from_listen_addr,
    )?;
    let (request, _) = worker::run(&context.store, &context.protocol, output)
        .map_err(|err| format!("record connection request: {err}"))?;
    let report = connection_worker::run(
        &context.store,
        &context.protocol,
        connection_worker::Work::DrainUntilConnected {
            request_id: request.request_id,
            timeout: CONNECT_WAIT,
            fail_on_route_error: true,
        },
    )?;
    Ok(CliOutput::lines(vec![
        format!("connected: {}", request.addr),
        format!("routes_synced: {}", report.attempts_completed),
        format!("sent_events: {}", report.sent_events),
    ]))
}

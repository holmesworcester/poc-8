//! Connection CLI commands and summaries.
//!
//! This file is the user-facing adapter for connection commands. It parses argv,
//! runs the invite bootstrap exchange, and formats the report. Ongoing daemon
//! scheduling uses the core daemon runner and the `src/workers` catalog.

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::protocol::cli::Context;
use crate::protocol::event_modules::connection::worker as connection_worker;

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
    // Read the running daemon's bound listener (if any) from the core-owned
    // lock file. None when no daemon is running for this DB.
    let from_listen_addr = crate::core::daemon::current_listen_addr(&context.db_path)?;
    let output = connection_worker::run(
        &context.store,
        &context.protocol,
        connection_worker::Work::ConnectInvite {
            invite: args.get(0).expect("length checked").to_string(),
            from_listen_addr,
        },
    )?;
    let connection_worker::Output::Connected(report) = output;
    Ok(CliOutput::lines(vec![
        format!("connected: {}", report.addr),
        format!("sent_events: {}", report.sent_events),
        format!("received_events: {}", report.received_events),
    ]))
}

//! Connection CLI commands and summaries.
//!
//! This file is the user-facing adapter for connection commands. It parses argv,
//! sends a connection request, and formats the report. Ongoing daemon
//! scheduling uses the core daemon runner and the `src/workers` catalog.

use super::connection_request;
use super::queries;
use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::protocol::cli::Context;
use crate::protocol::event_modules::worker;
use crate::workers::transit_out;

const CONNECT_USAGE: &str = "connect INVITE_LINK";
const CONNECTIONS_USAGE: &str = "connections";

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![
        CliCommand {
            name: "connect",
            usage: CONNECT_USAGE,
            help: "Connect to an invite over real TCP.",
            run: run_connect_command,
        },
        CliCommand {
            name: "connections",
            usage: CONNECTIONS_USAGE,
            help: "List established peer connections and last-known addresses.",
            run: run_connections_command,
        },
    ]
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

fn run_connections_command(
    context: &mut Context,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    args.require_len(0, CONNECTIONS_USAGE)?;
    let listings = queries::list_connections(&context.store)?;
    let mut lines = vec![format!("CONNECTIONS ({}):", listings.len())];
    if listings.is_empty() {
        lines.push("  (none)".to_string());
    } else {
        for (index, listing) in listings.iter().enumerate() {
            let peer_short = short_hex(&listing.remote_endpoint);
            let addr_part = listing
                .addr
                .as_deref()
                .map(|addr| format!(" addr={addr}"))
                .unwrap_or_default();
            lines.push(format!(
                "  {}. {}{}",
                index + 1,
                peer_short,
                addr_part
            ));
        }
    }
    Ok(CliOutput::lines(lines))
}

fn short_hex(bytes: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(8);
    for byte in bytes.iter().take(4) {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

//! Connection CLI commands and summaries.
//!
//! This file is the user-facing adapter for connection commands. It parses argv,
//! calls the connection worker, and formats worker reports. TCP exchange,
//! transit bookkeeping, route draining, and daemon scheduling stay in
//! `worker.rs`.

use std::net::SocketAddr;
use std::time::Duration;

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::protocol::cli::Context;

use super::{types, worker as connection_worker};

const CONNECT_USAGE: &str = "connect INVITE_LINK";
const DAEMON_USAGE: &str =
    "daemon --listen IP PORT [--duration-ms N] [--idle-ms N] [--ready-batch N]";

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![
        CliCommand {
            name: "connect",
            usage: CONNECT_USAGE,
            help: "Connect to an invite over real TCP.",
            run: run_connect_command,
        },
        CliCommand {
            name: "daemon",
            usage: DAEMON_USAGE,
            help: "Run a bounded or long-lived TCP sync daemon.",
            run: run_daemon_command,
        },
    ]
}

fn run_connect_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(1, CONNECT_USAGE)?;
    let output = connection_worker::run(
        &context.store,
        &context.protocol,
        connection_worker::Work::ConnectInvite {
            invite: args.get(0).expect("length checked").to_string(),
        },
    )?;
    let connection_worker::Output::Connected(report) = output else {
        return Err("connection worker returned non-connect output".to_string());
    };
    Ok(CliOutput::line(format!("connected: {}", report.addr)))
}

fn run_daemon_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let output = connection_worker::run(
        &context.store,
        &context.protocol,
        connection_worker::Work::RunDaemon {
            options: parse_daemon_options(args)?,
        },
    )?;
    let connection_worker::Output::DaemonRan(report) = output else {
        return Err("connection worker returned non-daemon output".to_string());
    };
    Ok(CliOutput::lines(daemon_lines(&report)))
}

fn parse_daemon_options(args: CliArgs<'_>) -> Result<types::DaemonOptions, String> {
    let mut listen = None;
    let mut duration = None;
    let mut idle = Duration::from_millis(250);
    let mut ready_batch = connection_worker::DEFAULT_DAEMON_READY_BATCH;
    let mut idx = 0;
    while idx < args.values().len() {
        match args.get(idx).expect("index in bounds") {
            "--listen" => {
                let ip = args.get(idx + 1).ok_or_else(|| DAEMON_USAGE.to_string())?;
                let port = args.get(idx + 2).ok_or_else(|| DAEMON_USAGE.to_string())?;
                listen = Some(
                    format!("{ip}:{port}")
                        .parse::<SocketAddr>()
                        .map_err(|_| DAEMON_USAGE.to_string())?,
                );
                idx += 3;
            }
            "--duration-ms" => {
                duration = Some(Duration::from_millis(parse_positive_u64(
                    args.get(idx + 1),
                )?));
                idx += 2;
            }
            "--idle-ms" => {
                idle = Duration::from_millis(parse_positive_u64(args.get(idx + 1))?);
                idx += 2;
            }
            "--ready-batch" => {
                ready_batch = args.parse_positive_usize(idx + 1, DAEMON_USAGE)?;
                idx += 2;
            }
            other => return Err(format!("unknown daemon option `{other}`\n{DAEMON_USAGE}")),
        }
    }
    Ok(types::DaemonOptions {
        listen: listen.ok_or_else(|| DAEMON_USAGE.to_string())?,
        duration,
        idle,
        ready_batch,
    })
}

fn parse_positive_u64(value: Option<&str>) -> Result<u64, String> {
    let value = value.ok_or_else(|| DAEMON_USAGE.to_string())?;
    let parsed = value.parse::<u64>().map_err(|_| DAEMON_USAGE.to_string())?;
    if parsed == 0 {
        return Err(DAEMON_USAGE.to_string());
    }
    Ok(parsed)
}

fn daemon_lines(report: &types::DaemonReport) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(local_addr) = report.local_addr {
        lines.push(format!("listening: {local_addr}"));
    }
    lines.extend([
        format!("accepted_connections: {}", report.accepted_connections),
        format!("sync_rounds: {}", report.sync_rounds),
        format!("routes_synced: {}", report.routes_synced),
        format!("failed_routes: {}", report.failed_routes),
        format!("sent_events: {}", report.sent_events),
        format!("received_events: {}", report.received_events),
        format!("ready_events: {}", report.ready_events),
        format!("unblocked_events: {}", report.unblocked_events),
    ]);
    lines
}

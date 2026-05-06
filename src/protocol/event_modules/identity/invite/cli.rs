//! Invite CLI command.
//!
//! Invite creation is local identity behavior: it may create the local endpoint
//! first, then records an invite secret and prints the link. Listening is owned
//! by the long-running daemon `start` command.

use std::net::SocketAddr;

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::protocol::cli::Context;
use crate::protocol::event_modules::worker;

const INVITE_USAGE: &str = "invite --public-addr ADDR";

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![CliCommand {
        name: "invite",
        usage: INVITE_USAGE,
        help: "Create an invite link for this endpoint.",
        run: run_invite_command,
    }]
}

fn run_invite_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let options = InviteOptions::parse(args)?;
    let output = super::commands::create_with_local(&context.store, options.public_addr)
        .map_err(|err| format!("create invite: {err}"))?;
    let (link, _) = worker::run(&context.store, &context.protocol, output)
        .map_err(|err| format!("apply invite: {err}"))?;
    Ok(CliOutput::line(link))
}

struct InviteOptions {
    public_addr: SocketAddr,
}

impl InviteOptions {
    fn parse(args: CliArgs<'_>) -> Result<Self, String> {
        let mut public_addr = None;
        let mut idx = 0;
        while idx < args.values().len() {
            match args.get(idx).expect("index in bounds") {
                "--public-addr" => {
                    let addr = args
                        .get(idx + 1)
                        .ok_or_else(|| INVITE_USAGE.to_string())?
                        .parse::<SocketAddr>()
                        .map_err(|_| INVITE_USAGE.to_string())?;
                    public_addr = Some(addr);
                    idx += 2;
                }
                other => return Err(format!("unknown invite option `{other}`\n{INVITE_USAGE}")),
            }
        }
        Ok(Self {
            public_addr: public_addr.ok_or_else(|| INVITE_USAGE.to_string())?,
        })
    }
}

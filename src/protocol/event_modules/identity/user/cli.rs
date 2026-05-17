//! CLI for workspace user rows.
//!
//! `users` is a read-only view of the user leaf table for one workspace. It
//! does not create users or coordinate invite acceptance; those workflows remain
//! in commands or the identity root CLI where their cross-leaf dependencies are
//! visible.

use crate::core::cli::{
    decode_hex_32 as core_decode_hex_32, encode_hex_32, CliArgs, CliCommand, CliOutput,
};
use crate::protocol::cli::Context;
use crate::protocol::event_modules::types::EventId;

const USERS_USAGE: &str = "users WORKSPACE_ID_HEX";

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![CliCommand {
        name: "users",
        usage: USERS_USAGE,
        help: "List users in a workspace.",
        run: run_users_command,
    }]
}

fn run_users_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(1, USERS_USAGE)?;
    let workspace_id = decode_hex_32(args.get(0).expect("length checked"))?;
    let mut lines = Vec::new();
    for (key, value) in context
        .store
        .table_rows_with_key_prefix(super::schema::USERS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load users: {err}"))?
    {
        let row = super::schema::decode_user_row(&key, &value)?;
        lines.push(format!("{} {}", encode_hex(&row.user_id), row.username));
    }
    Ok(CliOutput::lines(lines))
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    encode_hex_32(bytes)
}

fn decode_hex_32(value: &str) -> Result<EventId, String> {
    core_decode_hex_32(value).map_err(|_| USERS_USAGE.to_string())
}

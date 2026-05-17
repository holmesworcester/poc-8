//! CLI for workspace endpoint membership rows.
//!
//! `peers` is a read-only endpoint_shared listing for one workspace. It does
//! not create endpoint shares, accept links, or open transport; those operations
//! are cross-leaf workflows and stay outside this leaf CLI.

use crate::core::cli::{
    decode_hex_32 as core_decode_hex_32, encode_hex_32, CliArgs, CliCommand, CliOutput,
};
use crate::protocol::cli::Context;
use crate::protocol::event_modules::types::EventId;

const PEERS_USAGE: &str = "peers WORKSPACE_ID_HEX";

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![CliCommand {
        name: "peers",
        usage: PEERS_USAGE,
        help: "List endpoints in a workspace.",
        run: run_peers_command,
    }]
}

fn run_peers_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(1, PEERS_USAGE)?;
    let workspace_id = decode_hex_32(args.get(0).expect("length checked"))?;
    let mut lines = Vec::new();
    for (key, value) in context
        .store
        .table_rows_with_key_prefix(super::schema::ENDPOINT_SHARED, &workspace_id, usize::MAX)
        .map_err(|err| format!("load peers: {err}"))?
    {
        let row = super::schema::decode_endpoint_shared_row(&key, &value)?;
        lines.push(format!(
            "{} user_id={} endpoint_role={} device_name={}",
            encode_hex(&row.endpoint_id),
            encode_hex(&row.user_authority_event_id),
            row.endpoint_role.as_str(),
            row.device_name
        ));
    }
    Ok(CliOutput::lines(lines))
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    encode_hex_32(bytes)
}

fn decode_hex_32(value: &str) -> Result<EventId, String> {
    core_decode_hex_32(value).map_err(|_| PEERS_USAGE.to_string())
}

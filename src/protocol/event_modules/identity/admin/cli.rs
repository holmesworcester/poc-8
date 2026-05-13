//! CLI for workspace admin grants.
//!
//! This file is local to the admin leaf because `grant-admin` emits exactly an
//! admin grant after loading the local endpoint membership, the caller's admin
//! row, and the target user row. It does not create invites, endpoints,
//! workspaces, or transport state; those cross-leaf workflows stay in the
//! identity root CLI.

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::core::logical_clock;
use crate::core::store::Store;
use crate::protocol::cli::Context;
use crate::protocol::event_modules::identity::{endpoint, endpoint_shared, invite, user};
use crate::protocol::event_modules::queries as event_queries;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker;

use super::commands;

const GRANT_ADMIN_USAGE: &str = "grant-admin WORKSPACE_ID_HEX USER_ID_HEX";

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![CliCommand {
        name: "grant-admin",
        usage: GRANT_ADMIN_USAGE,
        help: "Grant admin authority to a workspace user.",
        run: run_grant_admin_command,
    }]
}

fn run_grant_admin_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(2, GRANT_ADMIN_USAGE)?;
    let workspace_id = decode_hex_32(args.get(0).expect("length checked"))?;
    let target_user_id = decode_hex_32(args.get(1).expect("length checked"))?;
    let local = ensure_local_endpoint(context)?;
    let membership = local_membership(&context.store, local.endpoint, workspace_id)?;
    let authority_admin_id = admin_for_user(
        &context.store,
        workspace_id,
        membership.user_authority_event_id,
    )?
    .ok_or_else(|| "local user is not an admin in this workspace".to_string())?;
    let target = user_row(&context.store, workspace_id, target_user_id)?;
    let grant = commands::sign_grant(commands::SignGrantAdmin {
        grant: commands::GrantAdmin {
            created_at_ms: next_timestamp(&context.store)?,
            workspace_id,
            authority_admin_id,
            target_user_event_id: target.user_id,
            target_user_public_key: target.public_key,
        },
        signer_event_id: authority_admin_id,
        signer_private_key: local.signing_secret,
    })?;
    let admin_id = grant.value.signed_event_id;
    worker::run(&context.store, &context.protocol, grant)
        .map_err(|err| format!("apply admin grant: {err}"))?;
    Ok(CliOutput::line(format!(
        "admin_id: {}",
        encode_hex(&admin_id)
    )))
}

fn ensure_local_endpoint(
    context: &mut Context,
) -> Result<endpoint::types::EndpointKeypair, String> {
    let output = endpoint::commands::local_or_create(&context.store)?;
    let local = output.value;
    if !output.events.is_empty() {
        worker::run(&context.store, &context.protocol, output)
            .map_err(|err| format!("apply local endpoint: {err}"))?;
    }
    Ok(local)
}

fn local_membership(
    store: &Store,
    endpoint_id: endpoint::types::EndpointId,
    workspace_id: EventId,
) -> Result<endpoint_shared::types::EndpointMembershipRow, String> {
    let key = endpoint_shared::schema::endpoint_membership_key(endpoint_id, workspace_id);
    let value = store
        .table_row(endpoint_shared::schema::ENDPOINT_MEMBERSHIPS, &key)
        .map_err(|err| format!("load endpoint membership: {err}"))?
        .ok_or_else(|| "local endpoint has not joined this workspace".to_string())?;
    endpoint_shared::schema::decode_endpoint_membership_row(&key, &value)
}

fn user_row(
    store: &Store,
    workspace_id: EventId,
    user_id: EventId,
) -> Result<user::types::UserRow, String> {
    let key = user::schema::user_key(&workspace_id, &user_id);
    let value = store
        .table_row(user::schema::USERS, &key)
        .map_err(|err| format!("load user: {err}"))?
        .ok_or_else(|| "user row is missing".to_string())?;
    user::schema::decode_user_row(&key, &value)
}

fn admin_for_user(
    store: &Store,
    workspace_id: EventId,
    user_id: EventId,
) -> Result<Option<EventId>, String> {
    for (key, value) in store
        .table_rows_with_key_prefix(super::schema::ADMINS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load admins: {err}"))?
    {
        let row = super::schema::decode_admin_row(&key, &value)?;
        if row.user_event_id == user_id {
            return Ok(Some(row.admin_id));
        }
    }
    Ok(None)
}

fn next_timestamp(store: &Store) -> Result<u64, String> {
    let max_timestamp =
        event_queries::max_timestamp(store).map_err(|err| format!("load max timestamp: {err}"))?;
    logical_clock::next_timestamp(store, max_timestamp)
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    invite::commands::encode_hex(bytes)
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err(GRANT_ADMIN_USAGE.to_string());
    }
    let mut out = [0; 32];
    let bytes = value.as_bytes();
    for idx in 0..32 {
        out[idx] = (hex_value(bytes[idx * 2])? << 4) | hex_value(bytes[idx * 2 + 1])?;
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(GRANT_ADMIN_USAGE.to_string()),
    }
}

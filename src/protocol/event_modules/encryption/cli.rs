//! Encryption CLI workflows.
//!
//! These commands span several encryption leaves: recipient-key publication,
//! admin-authorized frontier creation, wrap creation, derivation, and key
//! status reporting.

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::core::store::Store;
use crate::protocol::cli::Context;
use crate::protocol::clock;
use crate::protocol::event_modules::identity::{admin, endpoint, endpoint_shared};
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker as common_worker;

use super::{
    key_wrap, local_history_node_secret, local_key_secret, local_recipient_key, recipient_key,
    recipient_key_tombstone, removal_frontier, worker,
};

const KEY_RECIPIENT_USAGE: &str = "key-recipient WORKSPACE_ID_HEX";
const KEY_ROTATE_RECIPIENT_USAGE: &str = "key-rotate-recipient WORKSPACE_ID_HEX";
const KEY_FRONTIER_USAGE: &str = "key-frontier WORKSPACE_ID_HEX";
const KEY_WRAP_USAGE: &str =
    "key-wrap WORKSPACE_ID_HEX REMOVAL_FRONTIER_ID_HEX RECIPIENT_KEY_ID_HEX";
const KEY_DERIVE_USAGE: &str = "key-derive [LIMIT]";
const KEY_NODE_USAGE: &str = "key-node WORKSPACE_ID_HEX REMOVAL_FRONTIER_ID_HEX SOURCE_SECRET_ID_HEX RANGE_START RANGE_WIDTH [TOMBSTONE_NODE_ID_HEX]";
const KEY_ACCESS_USAGE: &str = "key-access WORKSPACE_ID_HEX REMOVAL_FRONTIER_ID_HEX";
const KEYS_USAGE: &str = "keys WORKSPACE_ID_HEX";

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![
        CliCommand {
            name: "key-recipient",
            usage: KEY_RECIPIENT_USAGE,
            help: "Create and publish a recipient key for this endpoint membership.",
            run: run_key_recipient_command,
        },
        CliCommand {
            name: "key-rotate-recipient",
            usage: KEY_ROTATE_RECIPIENT_USAGE,
            help: "Create a replacement recipient key and tombstone this endpoint's old keys.",
            run: run_key_rotate_recipient_command,
        },
        CliCommand {
            name: "key-frontier",
            usage: KEY_FRONTIER_USAGE,
            help: "Create an empty removal frontier and local key secret.",
            run: run_key_frontier_command,
        },
        CliCommand {
            name: "key-wrap",
            usage: KEY_WRAP_USAGE,
            help: "Create a key wrap for a recipient key.",
            run: run_key_wrap_command,
        },
        CliCommand {
            name: "key-derive",
            usage: KEY_DERIVE_USAGE,
            help: "Derive local key secrets from received key wraps.",
            run: run_key_derive_command,
        },
        CliCommand {
            name: "key-node",
            usage: KEY_NODE_USAGE,
            help: "Derive a local history range-node key from an applied key event.",
            run: run_key_node_command,
        },
        CliCommand {
            name: "key-access",
            usage: KEY_ACCESS_USAGE,
            help: "Report whether this store has local key material for a frontier.",
            run: run_key_access_command,
        },
        CliCommand {
            name: "keys",
            usage: KEYS_USAGE,
            help: "List key rows and local access for a workspace.",
            run: run_keys_command,
        },
    ]
}

fn run_key_recipient_command(
    context: &mut Context,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    args.require_len(1, KEY_RECIPIENT_USAGE)?;
    let workspace_id = parse_hex_id(args.get(0).expect("length checked"), KEY_RECIPIENT_USAGE)?;
    let membership = require_membership(&context.store, workspace_id)?;
    let local = endpoint::commands::local_keypair(&context.store)?
        .ok_or_else(|| "local endpoint is missing".to_string())?;
    if membership.signing_public_key != local.signing_public_key {
        return Err("local endpoint signing key does not match workspace membership".to_string());
    }
    if !membership.endpoint_role.can_receive_key_wraps() {
        return Err("local endpoint role cannot receive key wraps".to_string());
    }

    let local_key = local_recipient_key::commands::create(workspace_id)?;
    let local_report = common_worker::run(
        &context.store,
        &context.protocol,
        common_worker::AdmitAndDrain {
            output: local_key,
            batch_size: common_worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("apply local recipient key: {err}"))?;

    let recipient =
        recipient_key::commands::publish(recipient_key::commands::PublishRecipientKey {
            workspace_id,
            created_at_ms: next_timestamp(&context.store)?,
            endpoint_shared_id: membership.endpoint_shared_id,
            signer_private_key: local.signing_secret,
            recipient_key: local_report.value.recipient_key,
        })?;
    let recipient_report = common_worker::run(
        &context.store,
        &context.protocol,
        common_worker::AdmitAndDrain {
            output: recipient,
            batch_size: common_worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("apply recipient key: {err}"))?;

    Ok(CliOutput::lines(vec![
        format!(
            "local_recipient_key_id: {}",
            hex_id(local_report.admitted.event_ids[0])
        ),
        format!(
            "recipient_key_id: {}",
            hex_id(recipient_report.value.recipient_key_id)
        ),
        format!(
            "recipient_key: {}",
            hex_id(recipient_report.value.recipient_key)
        ),
    ]))
}

fn run_key_rotate_recipient_command(
    context: &mut Context,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    args.require_len(1, KEY_ROTATE_RECIPIENT_USAGE)?;
    let workspace_id = parse_hex_id(
        args.get(0).expect("length checked"),
        KEY_ROTATE_RECIPIENT_USAGE,
    )?;
    let output = worker::run(
        &context.store,
        &context.protocol,
        worker::Work::RotateRecipientKey { workspace_id },
    )?;
    let worker::Output::RotatedRecipientKey(report) = output else {
        return Err("unexpected key rotation worker output".to_string());
    };

    Ok(CliOutput::lines(vec![
        format!(
            "old_active_recipient_keys: {}",
            report.old_active_recipient_keys
        ),
        format!(
            "tombstoned_recipient_keys: {}",
            report.tombstoned_recipient_keys
        ),
        format!(
            "local_recipient_key_id: {}",
            optional_hex_id(report.local_recipient_key_id)
        ),
        format!(
            "recipient_key_id: {}",
            optional_hex_id(report.recipient_key_id)
        ),
        format!("admitted_events: {}", report.admitted_events),
    ]))
}

fn run_key_frontier_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(1, KEY_FRONTIER_USAGE)?;
    let workspace_id = parse_hex_id(args.get(0).expect("length checked"), KEY_FRONTIER_USAGE)?;
    let membership = require_membership(&context.store, workspace_id)?;
    let local = endpoint::commands::local_keypair(&context.store)?
        .ok_or_else(|| "local endpoint is missing".to_string())?;
    let authority_admin_id = admin_for_user(
        &context.store,
        workspace_id,
        membership.user_authority_event_id,
    )?
    .ok_or_else(|| "local user is not an admin in this workspace".to_string())?;

    let frontier =
        removal_frontier::commands::create(removal_frontier::commands::CreateRemovalFrontier {
            workspace_id,
            created_at_ms: next_timestamp(&context.store)?,
            authority_admin_id,
            signer_endpoint_shared_id: membership.endpoint_shared_id,
            signer_private_key: local.signing_secret,
            removal_event_ids: Vec::new(),
        })?;
    let frontier_report = common_worker::run(
        &context.store,
        &context.protocol,
        common_worker::AdmitAndDrain {
            output: frontier,
            batch_size: common_worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("apply removal frontier: {err}"))?;

    let local_secret = local_key_secret::commands::create(
        workspace_id,
        frontier_report.value.removal_frontier_id,
    )?;
    let secret_report = common_worker::run(
        &context.store,
        &context.protocol,
        common_worker::AdmitAndDrain {
            output: local_secret,
            batch_size: common_worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("apply local key secret: {err}"))?;

    Ok(CliOutput::lines(vec![
        format!(
            "removal_frontier_id: {}",
            hex_id(frontier_report.value.removal_frontier_id)
        ),
        format!(
            "local_key_secret_id: {}",
            hex_id(secret_report.value.local_key_secret_id)
        ),
    ]))
}

fn run_key_wrap_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(3, KEY_WRAP_USAGE)?;
    let workspace_id = parse_hex_id(args.get(0).expect("length checked"), KEY_WRAP_USAGE)?;
    let removal_frontier_id = parse_hex_id(args.get(1).expect("length checked"), KEY_WRAP_USAGE)?;
    let recipient_key_id = parse_hex_id(args.get(2).expect("length checked"), KEY_WRAP_USAGE)?;
    let membership = require_membership(&context.store, workspace_id)?;
    let local = endpoint::commands::local_keypair(&context.store)?
        .ok_or_else(|| "local endpoint is missing".to_string())?;
    let key_secret =
        local_key_secret::schema::get(&context.store, workspace_id, removal_frontier_id)?
            .ok_or_else(|| "local key secret is missing for removal frontier".to_string())?;
    let recipient_key = load_recipient_key(&context.store, workspace_id, recipient_key_id)?
        .ok_or_else(|| "recipient key is missing".to_string())?;

    let key_wrap = key_wrap::commands::create(key_wrap::commands::CreateKeyWrap {
        workspace_id,
        created_at_ms: next_timestamp(&context.store)?,
        signer_endpoint_shared_id: membership.endpoint_shared_id,
        signer_private_key: local.signing_secret,
        removal_frontier_id,
        local_key_secret_id: key_secret.local_key_secret_id,
        key_secret: key_secret.key_secret,
        recipient_key_id,
        recipient_key: recipient_key.recipient_key,
    })?;
    let report = common_worker::run(
        &context.store,
        &context.protocol,
        common_worker::AdmitAndDrain {
            output: key_wrap,
            batch_size: common_worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("apply key wrap: {err}"))?;

    Ok(CliOutput::lines(vec![
        format!("key_wrap_id: {}", hex_id(report.value.key_wrap_id)),
        format!(
            "removal_frontier_id: {}",
            hex_id(report.value.removal_frontier_id)
        ),
        format!(
            "recipient_key_id: {}",
            hex_id(report.value.recipient_key_id)
        ),
        format!(
            "local_key_secret_id: {}",
            hex_id(report.value.local_key_secret_id)
        ),
    ]))
}

fn run_key_derive_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    if args.values().len() > 1 {
        return Err(KEY_DERIVE_USAGE.to_string());
    }
    let batch_size = match args.get(0) {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| KEY_DERIVE_USAGE.to_string())?,
        None => common_worker::DEFAULT_READY_BATCH,
    };
    let output = worker::run(
        &context.store,
        &context.protocol,
        worker::Work::DeriveKeySecrets { batch_size },
    )?;
    let worker::Output::DerivedKeySecrets(report) = output else {
        return Err("unexpected key derive worker output".to_string());
    };

    Ok(CliOutput::lines(vec![
        format!("scanned_key_wraps: {}", report.scanned_key_wraps),
        format!("derived_key_secrets: {}", report.derived_key_secrets),
        format!("failed_key_wraps: {}", report.failed_key_wraps),
        format!("admitted_events: {}", report.admitted_events),
    ]))
}

fn run_key_node_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    if args.values().len() != 5 && args.values().len() != 6 {
        return Err(KEY_NODE_USAGE.to_string());
    }
    let workspace_id = parse_hex_id(args.get(0).expect("length checked"), KEY_NODE_USAGE)?;
    let removal_frontier_id = parse_hex_id(args.get(1).expect("length checked"), KEY_NODE_USAGE)?;
    let source_secret_id = parse_hex_id(args.get(2).expect("length checked"), KEY_NODE_USAGE)?;
    let range_start = parse_u64(args.get(3).expect("length checked"), KEY_NODE_USAGE)?;
    let range_width = parse_u64(args.get(4).expect("length checked"), KEY_NODE_USAGE)?;
    let tombstone_node_id = args
        .get(5)
        .map(|value| parse_hex_id(value, KEY_NODE_USAGE))
        .transpose()?;
    let output = worker::run(
        &context.store,
        &context.protocol,
        worker::Work::DeriveHistoryNode {
            workspace_id,
            removal_frontier_id,
            source_secret_id,
            range_start,
            range_width,
            tombstone_node_id,
        },
    )?;
    let worker::Output::DerivedHistoryNode(report) = output else {
        return Err("unexpected key node worker output".to_string());
    };

    Ok(CliOutput::lines(vec![
        format!(
            "local_history_node_secret_id: {}",
            optional_hex_id(report.local_history_node_secret_id)
        ),
        format!(
            "tombstoned_node_id: {}",
            optional_hex_id(report.tombstoned_node_id)
        ),
        format!("admitted_events: {}", report.admitted_events),
    ]))
}

fn run_key_access_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(2, KEY_ACCESS_USAGE)?;
    let workspace_id = parse_hex_id(args.get(0).expect("length checked"), KEY_ACCESS_USAGE)?;
    let removal_frontier_id = parse_hex_id(args.get(1).expect("length checked"), KEY_ACCESS_USAGE)?;
    let access = local_key_secret::schema::get(&context.store, workspace_id, removal_frontier_id)?;
    let mut lines = Vec::new();
    lines.push(format!(
        "access: {}",
        if access.is_some() { "yes" } else { "no" }
    ));
    lines.push(format!(
        "local_key_secret_id: {}",
        access
            .map(|row| hex_id(row.local_key_secret_id))
            .unwrap_or_else(|| "none".to_string())
    ));
    Ok(CliOutput::lines(lines))
}

fn run_keys_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(1, KEYS_USAGE)?;
    let workspace_id = parse_hex_id(args.get(0).expect("length checked"), KEYS_USAGE)?;
    let frontiers = removal_frontier::schema::list_for_workspace(&context.store, workspace_id)?;
    let local_secrets = local_key_secret::schema::list_for_workspace(&context.store, workspace_id)?;
    let recipient_keys = recipient_key::schema::list_for_workspace(&context.store, workspace_id)?;
    let recipient_key_tombstones =
        recipient_key_tombstone::schema::list_for_workspace(&context.store, workspace_id)?;
    let local_recipient_keys =
        local_recipient_key::schema::list_for_workspace(&context.store, workspace_id)?;
    let key_wraps = key_wrap::schema::list_for_workspace(&context.store, workspace_id)?;
    let history_nodes =
        local_history_node_secret::schema::list_for_workspace(&context.store, workspace_id)?;
    let history_tombstones = local_history_node_secret::schema::list_tombstones_for_workspace(
        &context.store,
        workspace_id,
    )?;

    let mut lines = vec![
        format!("recipient_keys: {}", recipient_keys.len()),
        format!(
            "recipient_key_tombstones: {}",
            recipient_key_tombstones.len()
        ),
        format!("local_recipient_keys: {}", local_recipient_keys.len()),
        format!("removal_frontiers: {}", frontiers.len()),
        format!("key_wraps: {}", key_wraps.len()),
        format!("local_key_secrets: {}", local_secrets.len()),
        format!("local_history_node_secrets: {}", history_nodes.len()),
        format!(
            "local_history_node_tombstones: {}",
            history_tombstones.len()
        ),
    ];
    for frontier in frontiers {
        let access = local_key_secret::schema::get(
            &context.store,
            workspace_id,
            frontier.removal_frontier_id,
        )?
        .is_some();
        lines.push(format!(
            "frontier: {} access={}",
            hex_id(frontier.removal_frontier_id),
            if access { "yes" } else { "no" }
        ));
    }
    for node in history_nodes {
        lines.push(format!(
            "history_node: {} frontier={} start={} width={} tombstones={}",
            hex_id(node.local_history_node_secret_id),
            hex_id(node.removal_frontier_id),
            node.range_start,
            node.range_width,
            optional_hex_id(node.tombstone_node_id)
        ));
    }
    Ok(CliOutput::lines(lines))
}

fn require_membership(
    store: &Store,
    workspace_id: EventId,
) -> Result<endpoint_shared::types::EndpointMembershipRow, String> {
    let local = endpoint::commands::local_keypair(store)?
        .ok_or_else(|| "local endpoint is missing".to_string())?;
    let key = endpoint_shared::schema::endpoint_membership_key(local.endpoint, workspace_id);
    let value = store
        .table_row(endpoint_shared::schema::ENDPOINT_MEMBERSHIPS, &key)
        .map_err(|err| format!("load endpoint membership: {err}"))?
        .ok_or_else(|| "local endpoint is not joined to workspace".to_string())?;
    let row = endpoint_shared::schema::decode_endpoint_membership_row(&key, &value)?;
    if row.signing_public_key != local.signing_public_key {
        return Err("local endpoint signing key does not match workspace membership".to_string());
    }
    Ok(row)
}

fn load_recipient_key(
    store: &Store,
    workspace_id: EventId,
    recipient_key_id: EventId,
) -> Result<Option<recipient_key::types::RecipientKeyRow>, String> {
    let key = recipient_key::schema::recipient_key_key(workspace_id, recipient_key_id);
    store
        .table_row(recipient_key::schema::RECIPIENT_KEYS, &key)
        .map_err(|err| format!("load recipient key: {err}"))?
        .map(|value| recipient_key::schema::decode_recipient_key_row(&key, &value))
        .transpose()
}

fn admin_for_user(
    store: &Store,
    workspace_id: EventId,
    user_id: EventId,
) -> Result<Option<EventId>, String> {
    for (key, value) in store
        .table_rows_with_key_prefix(admin::schema::ADMINS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load admins: {err}"))?
    {
        let row = admin::schema::decode_admin_row(&key, &value)?;
        if row.user_event_id == user_id {
            return Ok(Some(row.admin_id));
        }
    }
    Ok(None)
}

fn next_timestamp(store: &Store) -> Result<u64, String> {
    let max_timestamp =
        event_schema::max_timestamp(store).map_err(|err| format!("load max timestamp: {err}"))?;
    clock::next_timestamp(store, max_timestamp)
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

fn parse_u64(value: &str, usage: &str) -> Result<u64, String> {
    value.parse::<u64>().map_err(|_| usage.to_string())
}

fn hex_id(id: EventId) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in id {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn optional_hex_id(id: Option<EventId>) -> String {
    id.map(hex_id).unwrap_or_else(|| "none".to_string())
}

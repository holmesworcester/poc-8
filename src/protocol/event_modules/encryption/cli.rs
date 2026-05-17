//! Encryption CLI workflows.
//!
//! These commands span several encryption leaves: recipient-key publication,
//! admin-authorized frontier creation, wrap creation, derivation, and key
//! status reporting. They load local authority/key rows and call leaf commands
//! or workers, but they do not define event syntax, projection rules, or store
//! schemas.

use std::io::{self, BufRead};

use crate::core::cli::{decode_hex_32, encode_hex, encode_hex_32, CliArgs, CliCommand, CliOutput};
use crate::core::logical_clock;
use crate::core::store::Store;
use crate::protocol::cli::Context;
use crate::protocol::event_modules::content::message::queries as message_queries;
use crate::protocol::event_modules::content::message::types::UNIX_MINUTE_MS;
use crate::protocol::event_modules::identity::{admin, endpoint};
use crate::protocol::event_modules::queries as event_queries;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker as common_worker;

use super::disappearing_messages_setting::types::COVER_HORIZON_MINUTES;
use super::{
    disappearing_messages_setting, key_wrap, local_history_node_secret, local_key_secret,
    local_recipient_key, recipient_key, removal_frontier, worker,
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
const DISAPPEARING_SET_USAGE: &str =
    "disappearing-set WORKSPACE_ID_HEX TTL_MINUTES [--floor MINUTE]";
const DISAPPEARING_STATUS_USAGE: &str = "disappearing-status WORKSPACE_ID_HEX";
const DISAPPEARING_TIGHTEN_USAGE: &str =
    "disappearing-tighten WORKSPACE_ID_HEX TTL_MINUTES [--yes|-y]";
const DISAPPEARING_COMPACT_USAGE: &str = "disappearing-compact WORKSPACE_ID_HEX";
const CHOP_NOW_USAGE: &str = "chop-now WORKSPACE_ID_HEX FLOOR_MINUTE";

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
        CliCommand {
            name: "disappearing-set",
            usage: DISAPPEARING_SET_USAGE,
            help: "Author an admin-signed disappearing-messages TTL setting. \
                   By default the monotonic deletion floor is auto-advanced \
                   to max(previous_floor, current_minute - new_ttl_minutes); \
                   pass --floor MINUTE to override (rejected if below the \
                   previous floor).",
            run: run_disappearing_set_command,
        },
        CliCommand {
            name: "disappearing-status",
            usage: DISAPPEARING_STATUS_USAGE,
            help: "Print the active disappearing-messages setting, dispatcher \
                   chop progress, message + tombstone counts, and the pending \
                   negentropy purge queue size for one workspace.",
            run: run_disappearing_status_command,
        },
        CliCommand {
            name: "disappearing-tighten",
            usage: DISAPPEARING_TIGHTEN_USAGE,
            help: "Tighten the workspace TTL and immediately advance the \
                   monotonic deletion floor to current_minute - new_ttl_minutes. \
                   Prompts before deleting live messages unless --yes is passed.",
            run: run_disappearing_tighten_command,
        },
        CliCommand {
            name: "disappearing-compact",
            usage: DISAPPEARING_COMPACT_USAGE,
            help: "Re-author the active setting with the same TTL but advance \
                   the floor to current_minute - current_ttl_minutes. A \
                   no-confirmation operator GC: only debris below the floor \
                   is collected; no live messages are deleted.",
            run: run_disappearing_compact_command,
        },
        CliCommand {
            name: "chop-now",
            usage: CHOP_NOW_USAGE,
            help: "Diagnostic: directly invoke ChopTimeTreePrefix on the \
                   workspace's most recent removal_frontier with the given \
                   floor. Bypasses the dispatcher's last_chopped_floor \
                   bookkeeping; intended for tests/operators forcing a chop.",
            run: run_chop_now_command,
        },
    ]
}

fn run_key_recipient_command(
    context: &mut Context,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    args.require_len(1, KEY_RECIPIENT_USAGE)?;
    let workspace_id = parse_hex_id(args.get(0).expect("length checked"), KEY_RECIPIENT_USAGE)?;
    let membership =
        crate::protocol::event_modules::content::message::commands::require_local_membership(
            &context.store,
            workspace_id,
        )?;
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
            // Fresh first-time publication, not a rotation. The
            // forward-secrecy rotation path in the encryption worker
            // sets this to the wiped pubkey when re-publishing under
            // an F-wipe.
            previous_recipient_key_id: super::recipient_key::types::NO_PREVIOUS_RECIPIENT_KEY,
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
    let membership =
        crate::protocol::event_modules::content::message::commands::require_local_membership(
            &context.store,
            workspace_id,
        )?;
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
    let membership =
        crate::protocol::event_modules::content::message::commands::require_local_membership(
            &context.store,
            workspace_id,
        )?;
    let local = endpoint::commands::local_keypair(&context.store)?
        .ok_or_else(|| "local endpoint is missing".to_string())?;
    let key_secret =
        local_key_secret::queries::get(&context.store, workspace_id, removal_frontier_id)?
            .ok_or_else(|| "local key secret is missing for removal frontier".to_string())?;
    let recipient_key = load_recipient_key(&context.store, workspace_id, recipient_key_id)?
        .ok_or_else(|| "recipient key is missing".to_string())?;

    let key_wrap = key_wrap::commands::create(key_wrap::commands::CreateKeyWrap {
        workspace_id,
        created_at_ms: next_timestamp(&context.store)?,
        signer_endpoint_shared_id: membership.endpoint_shared_id,
        signer_private_key: local.signing_secret,
        removal_frontier_id,
        wrapped_secret_kind: key_wrap::types::WrappedSecretKind::FrontierRoot,
        wrapped_secret_id: key_secret.local_key_secret_id,
        wrapped_source_secret_id: [0; 32],
        wrapped_tombstone_node_id: [0; 32],
        range_start: 0,
        range_width: 0,
        bit_depth: 0,
        event_id_prefix: [0; 32],
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
            "wrapped_secret_id: {}",
            hex_id(report.value.wrapped_secret_id)
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
    // Dev/test utility for materializing a time-tree split off a known parent
    // secret. The parent must be either the workspace `local_key_secret`
    // (frontier root) or a previously-materialized time-tree node. The CLI
    // figures out the correct `parent_range_start`/`parent_range_width` by
    // looking up `source_secret_id`.
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

    let parent = local_history_node_secret::commands::load_time_tree_parent(
        &context.store,
        workspace_id,
        removal_frontier_id,
        source_secret_id,
    )?;
    let child_side = if range_start < parent.parent_range_start + parent.parent_range_width / 2 {
        0u8
    } else {
        1u8
    };
    let output = local_history_node_secret::commands::derive_time_split(
        local_history_node_secret::commands::DeriveTimeSplit {
            workspace_id,
            removal_frontier_id,
            parent_secret_id: source_secret_id,
            parent_secret: parent.parent_secret,
            parent_range_start: parent.parent_range_start,
            parent_range_width: parent.parent_range_width,
            child_side,
            child_range_start: range_start,
            child_range_width: range_width,
            tombstone_node_id,
        },
    )?;
    let local_history_node_secret_id = output.value.local_history_node_secret_id;
    let admitted = common_worker::run(
        &context.store,
        &context.protocol,
        common_worker::AdmitAndDrain {
            output,
            batch_size: common_worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("admit local history node secret: {err}"))?;
    let mut purged_event_bytes = 0usize;
    if let Some(retired_node_id) = tombstone_node_id {
        // `key-node` is a dev utility that bypasses the worker's full
        // retire pipeline; the worker would normally purge the retired
        // event's canonical bytes itself. Driving the same primitive
        // through `Work::PurgeRetiredHistoryNodeBytes` keeps the storage
        // mutation in the encryption worker where it belongs.
        let output = worker::run(
            &context.store,
            &context.protocol,
            worker::Work::PurgeRetiredHistoryNodeBytes { retired_node_id },
        )?;
        let worker::Output::PurgedRetiredHistoryNodeBytes(report) = output else {
            return Err("unexpected purge retired history node bytes output".to_string());
        };
        if report.purged {
            purged_event_bytes += 1;
        }
    }

    Ok(CliOutput::lines(vec![
        format!(
            "local_history_node_secret_id: {}",
            hex_id(local_history_node_secret_id)
        ),
        format!("tombstoned_node_id: {}", optional_hex_id(tombstone_node_id)),
        format!("admitted_events: {}", admitted.admitted.inserted_events),
        format!("purged_event_bytes: {}", purged_event_bytes),
    ]))
}

fn run_key_access_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(2, KEY_ACCESS_USAGE)?;
    let workspace_id = parse_hex_id(args.get(0).expect("length checked"), KEY_ACCESS_USAGE)?;
    let removal_frontier_id = parse_hex_id(args.get(1).expect("length checked"), KEY_ACCESS_USAGE)?;
    let access = local_key_secret::queries::get(&context.store, workspace_id, removal_frontier_id)?;
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
    let frontiers = removal_frontier::queries::list_for_workspace(&context.store, workspace_id)?;
    let local_secrets =
        local_key_secret::queries::list_for_workspace(&context.store, workspace_id)?;
    let recipient_keys = recipient_key::queries::list_for_workspace(&context.store, workspace_id)?;
    let local_recipient_keys =
        local_recipient_key::queries::list_for_workspace(&context.store, workspace_id)?;
    let key_wraps = key_wrap::queries::list_for_workspace(&context.store, workspace_id)?;
    let history_nodes =
        local_history_node_secret::queries::list_for_workspace(&context.store, workspace_id)?;
    let history_tombstones = local_history_node_secret::queries::list_tombstones_for_workspace(
        &context.store,
        workspace_id,
    )?;
    let message_tombstones =
        crate::protocol::event_modules::content::message::queries::list_message_tombstones_for_workspace(
            &context.store,
            workspace_id,
        )?;
    let cover_summary =
        local_history_node_secret::queries::cover_summary(&context.store, workspace_id)?;
    use local_history_node_secret::types::{
        is_leaf_row, is_minute_node_row, TIME_TREE_BIT_DEPTH, TRIE_LEAF_BIT_DEPTH,
    };
    let leaf_count = history_nodes
        .iter()
        .filter(|node| is_leaf_row(node))
        .count();
    let minute_node_count = history_nodes
        .iter()
        .filter(|node| is_minute_node_row(node))
        .count();
    let trie_internal_count = history_nodes
        .iter()
        .filter(|node| node.bit_depth > TIME_TREE_BIT_DEPTH && node.bit_depth < TRIE_LEAF_BIT_DEPTH)
        .count();
    let time_internal_count = history_nodes
        .iter()
        .filter(|node| node.bit_depth == TIME_TREE_BIT_DEPTH && node.range_width > 1)
        .count();

    let mut lines = vec![
        format!("recipient_keys: {}", recipient_keys.len()),
        format!("local_recipient_keys: {}", local_recipient_keys.len()),
        format!("removal_frontiers: {}", frontiers.len()),
        format!("key_wraps: {}", key_wraps.len()),
        format!("local_key_secrets: {}", local_secrets.len()),
        format!("local_history_node_secrets: {}", history_nodes.len()),
        format!("local_history_minute_nodes: {minute_node_count}"),
        format!("local_history_leaves: {leaf_count}"),
        format!("local_history_trie_internals: {trie_internal_count}"),
        format!("local_history_time_internals: {time_internal_count}"),
        format!(
            "local_history_node_tombstones: {}",
            history_tombstones.len()
        ),
        format!("message_tombstones: {}", message_tombstones.len()),
        format!("cover_summary: {}", hex_bytes(&cover_summary)),
    ];
    for frontier in frontiers {
        let access = local_key_secret::queries::get(
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
        // Render `event_id_in_minute` as the leaf's full coord (when this row
        // is a trie leaf) or `none` for time-tree nodes / minute_nodes /
        // trie internals. Trie internals also surface their `bit_depth` and
        // `prefix` so the test/debug output unambiguously names every row.
        let event_id_in_minute_field = if is_leaf_row(&node) {
            hex_id(node.event_id_prefix)
        } else {
            "none".to_string()
        };
        lines.push(format!(
            "history_node: {} frontier={} start={} width={} bit_depth={} prefix={} event_id_in_minute={} tombstones={}",
            hex_id(node.local_history_node_secret_id),
            hex_id(node.removal_frontier_id),
            node.range_start,
            node.range_width,
            node.bit_depth,
            hex_id(node.event_id_prefix),
            event_id_in_minute_field,
            optional_hex_id(node.tombstone_node_id)
        ));
    }
    Ok(CliOutput::lines(lines))
}

fn run_disappearing_set_command(
    context: &mut Context,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let parsed = parse_disappearing_set_args(args)?;
    let now_ms = next_timestamp(&context.store)?;
    let output = disappearing_messages_setting::commands::author_set_with_auto_floor(
        &context.store,
        disappearing_messages_setting::commands::AuthorSetting {
            workspace_id: parsed.workspace_id,
            now_ms,
            ttl_minutes: parsed.ttl_minutes,
            explicit_floor: parsed.explicit_floor,
        },
    )?;
    let report = common_worker::run(
        &context.store,
        &context.protocol,
        common_worker::AdmitAndDrain {
            output,
            batch_size: common_worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("apply disappearing_messages_setting: {err}"))?;
    let delta = report
        .value
        .new_floor_minute
        .saturating_sub(report.value.previous_floor_minute);
    Ok(CliOutput::lines(vec![
        format!(
            "setting_event_id: {}",
            hex_id(report.value.setting_event_id)
        ),
        format!("ttl_minutes: {}", parsed.ttl_minutes),
        format!(
            "previous_floor_minute: {}",
            report.value.previous_floor_minute
        ),
        format!("new_floor_minute: {}", report.value.new_floor_minute),
        format!("floor_delta_minutes: {delta}"),
    ]))
}

struct DisappearingSetArgs {
    workspace_id: EventId,
    ttl_minutes: u32,
    explicit_floor: Option<u64>,
}

/// Parse `disappearing-set` argv. The accepted shapes are:
///   * `WORKSPACE_ID_HEX TTL_MINUTES`
///   * `WORKSPACE_ID_HEX TTL_MINUTES --floor MINUTE`
///   * `WORKSPACE_ID_HEX TTL_MINUTES --floor=MINUTE`
fn parse_disappearing_set_args(args: CliArgs<'_>) -> Result<DisappearingSetArgs, String> {
    let values = args.values();
    if values.len() < 2 {
        return Err(DISAPPEARING_SET_USAGE.to_string());
    }
    let workspace_id = parse_hex_id(&values[0], DISAPPEARING_SET_USAGE)?;
    let ttl_minutes = values[1]
        .parse::<u32>()
        .map_err(|_| DISAPPEARING_SET_USAGE.to_string())?;
    let mut explicit_floor: Option<u64> = None;
    let mut idx = 2;
    while idx < values.len() {
        let arg = values[idx].as_str();
        if let Some(value) = arg.strip_prefix("--floor=") {
            explicit_floor = Some(parse_u64(value, DISAPPEARING_SET_USAGE)?);
            idx += 1;
        } else if arg == "--floor" {
            let value = values
                .get(idx + 1)
                .ok_or_else(|| DISAPPEARING_SET_USAGE.to_string())?;
            explicit_floor = Some(parse_u64(value, DISAPPEARING_SET_USAGE)?);
            idx += 2;
        } else {
            return Err(DISAPPEARING_SET_USAGE.to_string());
        }
    }
    Ok(DisappearingSetArgs {
        workspace_id,
        ttl_minutes,
        explicit_floor,
    })
}

fn run_disappearing_status_command(
    context: &mut Context,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    args.require_len(1, DISAPPEARING_STATUS_USAGE)?;
    let workspace_id = parse_hex_id(
        args.get(0).expect("length checked"),
        DISAPPEARING_STATUS_USAGE,
    )?;

    let active =
        disappearing_messages_setting::queries::active_for_workspace(&context.store, workspace_id)?;
    let ttl_minutes = active
        .as_ref()
        .map(|row| row.ttl_minutes.to_string())
        .unwrap_or_else(|| "unset".to_string());
    let setting_floor = active
        .as_ref()
        .map(|row| row.expires_at_or_before_minute)
        .unwrap_or(0);
    let setting_event_id = active
        .as_ref()
        .map(|row| hex_id(row.setting_event_id))
        .unwrap_or_else(|| "none".to_string());

    let now_ms_opt = logical_clock::logical_time(&context.store)?;
    let now_minute_str = match now_ms_opt {
        Some(ms) => (ms / UNIX_MINUTE_MS).to_string(),
        None => "unset".to_string(),
    };
    let horizon_floor = now_ms_opt
        .map(|ms| (ms / UNIX_MINUTE_MS).saturating_sub(COVER_HORIZON_MINUTES))
        .unwrap_or(0);
    let effective_floor = std::cmp::max(setting_floor, horizon_floor);

    let frontiers = removal_frontier::queries::list_for_workspace(&context.store, workspace_id)?;
    // Report the highest `last_chopped_floor` across this workspace's
    // frontiers. One frontier is the norm; on a rotated workspace the
    // highest value is the meaningful signal because the dispatcher
    // progresses each frontier independently and tightenings target
    // whichever frontier is active for new authoring.
    let mut last_chopped_floor: u64 = 0;
    let mut last_chopped_present = false;
    for frontier in &frontiers {
        if let Some(value) = disappearing_messages_setting::queries::get_last_chopped_floor(
            &context.store,
            workspace_id,
            frontier.removal_frontier_id,
        )? {
            last_chopped_present = true;
            if value > last_chopped_floor {
                last_chopped_floor = value;
            }
        }
    }
    let last_chopped_str = if last_chopped_present {
        last_chopped_floor.to_string()
    } else {
        "none".to_string()
    };

    // Live messages = opened (`MESSAGES`) + still-sealed
    // (`SEALED_MESSAGES`). The CLI `messages` listing folds these two
    // together, so this matches what an operator sees.
    let live_messages = message_queries::count_for_workspace(&context.store, workspace_id)?
        + message_queries::count_sealed_for_workspace(&context.store, workspace_id)?;
    let message_tombstones =
        message_queries::list_message_tombstones_for_workspace(&context.store, workspace_id)?.len();
    let leaf_tombstones = local_history_node_secret::queries::list_tombstones_for_workspace(
        &context.store,
        workspace_id,
    )?
    .len();
    let pending_purges =
        crate::protocol::event_modules::sync::queries::pending_purge_count(&context.store)
            .map_err(|err| format!("count pending purges: {err}"))?;

    Ok(CliOutput::lines(vec![
        format!("workspace: {}", hex_id(workspace_id)),
        format!("setting_event_id: {setting_event_id}"),
        format!("current_ttl_minutes: {ttl_minutes}"),
        format!("current_floor_minute: {setting_floor}"),
        format!("last_chopped_floor: {last_chopped_str}"),
        format!("now_minute: {now_minute_str}"),
        format!("horizon_floor: {horizon_floor}"),
        format!("effective_floor: {effective_floor}"),
        format!("live_messages: {live_messages}"),
        format!("message_tombstones: {message_tombstones}"),
        format!("leaf_tombstones: {leaf_tombstones}"),
        format!("pending_purges: {pending_purges}"),
    ]))
}

fn run_disappearing_tighten_command(
    context: &mut Context,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    let parsed = parse_disappearing_tighten_args(args)?;
    let now_ms = next_timestamp(&context.store)?;
    let input = disappearing_messages_setting::commands::AuthorTighten {
        workspace_id: parsed.workspace_id,
        now_ms,
        ttl_minutes: parsed.ttl_minutes,
    };

    // Plan first so the operator confirmation prompt knows how many live
    // messages will fall below the target floor.
    let plan = disappearing_messages_setting::commands::plan_tighten(&context.store, input)?;
    if !parsed.yes {
        eprintln!(
            "WARNING: this will delete {} messages older than {} minutes (new floor = {}).",
            plan.messages_below_floor, parsed.ttl_minutes, plan.target_floor_minute
        );
        eprint!("Continue? [y/N] ");
        let mut response = String::new();
        io::stdin()
            .lock()
            .read_line(&mut response)
            .map_err(|err| format!("read confirmation: {err}"))?;
        let trimmed = response.trim();
        if !(trimmed == "y" || trimmed == "Y" || trimmed == "yes" || trimmed == "Yes") {
            return Err("aborted".to_string());
        }
    }

    let output = disappearing_messages_setting::commands::author_tighten(&context.store, input)?;
    let report = common_worker::run(
        &context.store,
        &context.protocol,
        common_worker::AdmitAndDrain {
            output,
            batch_size: common_worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("apply disappearing_messages_setting: {err}"))?;

    Ok(CliOutput::lines(vec![
        format!(
            "setting_event_id: {}",
            hex_id(report.value.setting_event_id)
        ),
        format!("ttl_minutes: {}", parsed.ttl_minutes),
        format!(
            "previous_floor_minute: {}",
            report.value.previous_floor_minute
        ),
        format!("new_floor_minute: {}", report.value.target_floor_minute),
        format!("messages_below_floor: {}", plan.messages_below_floor),
    ]))
}

struct DisappearingTightenArgs {
    workspace_id: EventId,
    ttl_minutes: u32,
    yes: bool,
}

fn parse_disappearing_tighten_args(args: CliArgs<'_>) -> Result<DisappearingTightenArgs, String> {
    let values = args.values();
    if values.len() < 2 {
        return Err(DISAPPEARING_TIGHTEN_USAGE.to_string());
    }
    let workspace_id = parse_hex_id(&values[0], DISAPPEARING_TIGHTEN_USAGE)?;
    let ttl_minutes = values[1]
        .parse::<u32>()
        .map_err(|_| DISAPPEARING_TIGHTEN_USAGE.to_string())?;
    let mut yes = false;
    for arg in &values[2..] {
        match arg.as_str() {
            "--yes" | "-y" => yes = true,
            _ => return Err(DISAPPEARING_TIGHTEN_USAGE.to_string()),
        }
    }
    Ok(DisappearingTightenArgs {
        workspace_id,
        ttl_minutes,
        yes,
    })
}

fn run_disappearing_compact_command(
    context: &mut Context,
    args: CliArgs<'_>,
) -> Result<CliOutput, String> {
    args.require_len(1, DISAPPEARING_COMPACT_USAGE)?;
    let workspace_id = parse_hex_id(
        args.get(0).expect("length checked"),
        DISAPPEARING_COMPACT_USAGE,
    )?;
    let now_ms = next_timestamp(&context.store)?;
    let output = disappearing_messages_setting::commands::author_compact(
        &context.store,
        disappearing_messages_setting::commands::AuthorCompact {
            workspace_id,
            now_ms,
        },
    )?;
    let report = common_worker::run(
        &context.store,
        &context.protocol,
        common_worker::AdmitAndDrain {
            output,
            batch_size: common_worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("apply disappearing_messages_setting: {err}"))?;
    let delta = report
        .value
        .new_floor_minute
        .saturating_sub(report.value.previous_floor_minute);
    Ok(CliOutput::lines(vec![
        format!(
            "setting_event_id: {}",
            hex_id(report.value.setting_event_id)
        ),
        format!("ttl_minutes: {}", report.value.ttl_minutes),
        format!(
            "previous_floor_minute: {}",
            report.value.previous_floor_minute
        ),
        format!("new_floor_minute: {}", report.value.new_floor_minute),
        format!("floor_delta_minutes: {delta}"),
    ]))
}

fn run_chop_now_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(2, CHOP_NOW_USAGE)?;
    let workspace_id = parse_hex_id(args.get(0).expect("length checked"), CHOP_NOW_USAGE)?;
    let floor_minute = parse_u64(args.get(1).expect("length checked"), CHOP_NOW_USAGE)?;

    let removal_frontier_id =
        removal_frontier::commands::latest_frontier_id(&context.store, workspace_id)?;
    let output = worker::run(
        &context.store,
        &context.protocol,
        worker::Work::ChopTimeTreePrefix {
            workspace_id,
            removal_frontier_id,
            floor_minute,
        },
    )?;
    let worker::Output::ChoppedTimeTreePrefix(report) = output else {
        return Err("unexpected encryption worker output for chop".to_string());
    };

    Ok(CliOutput::lines(vec![
        format!("removal_frontier_id: {}", hex_id(removal_frontier_id)),
        format!("floor_minute: {floor_minute}"),
        format!(
            "subtree_tombstones_written: {}",
            report.subtree_tombstones_written
        ),
        format!(
            "boundary_descend_tombstones_written: {}",
            report.boundary_descend_tombstones_written
        ),
        format!(
            "right_side_siblings_materialized: {}",
            report.right_side_siblings_materialized
        ),
        format!("purged_event_bytes: {}", report.purged_event_bytes),
        format!(
            "subsumed_message_tombstones_gcd: {}",
            report.subsumed_message_tombstones_gcd
        ),
        format!(
            "subsumed_leaf_tombstones_gcd: {}",
            report.subsumed_leaf_tombstones_gcd
        ),
    ]))
}

fn hex_bytes(bytes: &[u8]) -> String {
    encode_hex(bytes)
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
        event_queries::max_timestamp(store).map_err(|err| format!("load max timestamp: {err}"))?;
    logical_clock::next_timestamp(store, max_timestamp)
}

fn parse_hex_id(value: &str, usage: &str) -> Result<EventId, String> {
    decode_hex_32(value).map_err(|_| usage.to_string())
}

fn parse_u64(value: &str, usage: &str) -> Result<u64, String> {
    value.parse::<u64>().map_err(|_| usage.to_string())
}

fn hex_id(id: EventId) -> String {
    encode_hex_32(&id)
}

fn optional_hex_id(id: Option<EventId>) -> String {
    id.map(hex_id).unwrap_or_else(|| "none".to_string())
}

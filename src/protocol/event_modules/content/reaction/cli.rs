//! Reaction CLI: `react`.
//!
//! This adapter resolves a message selector, loads local membership and content
//! key material, then admits one signed reaction event. It does not own reaction
//! projection, display grouping, or message deletion cleanup; those stay in the
//! reaction projector/schema and content purge worker.

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::protocol::cli::Context;
use crate::protocol::event_modules::content::message;
use crate::protocol::event_modules::identity::endpoint;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker;

use super::commands;

const REACT_USAGE: &str = "react WORKSPACE_ID_HEX MESSAGE_SELECTOR EMOJI";

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![CliCommand {
        name: "react",
        usage: REACT_USAGE,
        help: "React to a message in a workspace.",
        run: run_react_command,
    }]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactSummary {
    pub event_id: EventId,
    pub target_message_id: EventId,
    pub emoji: String,
}

impl ReactSummary {
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("event_id: {}", message::cli::hex_id(self.event_id)),
            format!("target: {}", message::cli::hex_id(self.target_message_id)),
            format!("emoji: {}", self.emoji),
        ]
    }
}

fn run_react_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(3, REACT_USAGE)?;
    let workspace_id =
        message::cli::parse_hex_id(args.get(0).expect("length checked"), REACT_USAGE)?;
    let target = message::cli::resolve_selector(
        &context.store,
        workspace_id,
        args.get(1).expect("length checked"),
    )?;
    let emoji = args.get(2).expect("length checked").to_string();

    let membership = message::cli::require_membership(&context.store, workspace_id)?;
    let local = endpoint::commands::local_keypair(&context.store)?
        .ok_or_else(|| "local endpoint is missing".to_string())?;

    let timestamp = message::cli::next_timestamp(&context.store, workspace_id)?;
    let removal_frontier_id =
        message::cli::require_active_frontier_id(&context.store, workspace_id)?;
    let leaf = message::cli::derive_message_leaf(
        &context.store,
        &context.protocol,
        workspace_id,
        removal_frontier_id,
        timestamp,
    )?;
    let post = commands::post(commands::PostReaction {
        workspace_id,
        created_at_ms: timestamp,
        target_message_id: target,
        author_user_id: membership.user_authority_event_id,
        signer_endpoint_shared_id: membership.endpoint_shared_id,
        signer_private_key: local.signing_secret,
        removal_frontier_id,
        local_history_node_secret_id: leaf.local_history_node_secret_id,
        leaf_node_secret: leaf.leaf_node_secret,
        emoji,
    })?;
    let report = worker::run(
        &context.store,
        &context.protocol,
        worker::AdmitAndDrain {
            output: post,
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("admit reaction: {err}"))?;
    if report.admitted.inserted_events == 0 {
        return Err("reaction was not admitted".to_string());
    }
    Ok(CliOutput::lines(
        ReactSummary {
            event_id: report.value.reaction_id,
            target_message_id: report.value.target_message_id,
            emoji: report.value.emoji,
        }
        .lines(),
    ))
}

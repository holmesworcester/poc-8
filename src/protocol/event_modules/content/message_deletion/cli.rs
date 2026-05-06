//! Message deletion CLI: `delete-message`.
//!
//! This adapter resolves a user-facing message selector, signs the deletion
//! fact with the local workspace endpoint, admits it, then runs one bounded
//! purge pass so local display state catches up. It does not define deletion
//! semantics: the protocol fact lives in `commands`/`projector`, and byte
//! retention belongs to the worker.

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::protocol::cli::Context;
use crate::protocol::event_modules::content::message;
use crate::protocol::event_modules::identity::endpoint;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker;
use crate::workers::content_purge;

use super::commands;

const DELETE_USAGE: &str = "delete-message WORKSPACE_ID_HEX MESSAGE_SELECTOR";

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![CliCommand {
        name: "delete-message",
        usage: DELETE_USAGE,
        help: "Delete one of your messages in a workspace.",
        run: run_delete_command,
    }]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteSummary {
    pub event_id: EventId,
    pub target_message_id: EventId,
}

impl DeleteSummary {
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("event_id: {}", message::cli::hex_id(self.event_id)),
            format!("target: {}", message::cli::hex_id(self.target_message_id)),
        ]
    }
}

fn run_delete_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(2, DELETE_USAGE)?;
    let workspace_id =
        message::cli::parse_hex_id(args.get(0).expect("length checked"), DELETE_USAGE)?;
    let target = message::cli::resolve_selector(
        &context.store,
        workspace_id,
        args.get(1).expect("length checked"),
    )?;

    let membership = message::cli::require_membership(&context.store, workspace_id)?;
    let local = endpoint::commands::local_keypair(&context.store)?
        .ok_or_else(|| "local endpoint is missing".to_string())?;

    let timestamp = message::cli::next_timestamp(&context.store, workspace_id)?;
    let delete = commands::delete(commands::DeleteMessage {
        workspace_id,
        created_at_ms: timestamp,
        target_message_id: target,
        author_user_id: membership.user_authority_event_id,
        signer_endpoint_shared_id: membership.endpoint_shared_id,
        signer_private_key: local.signing_secret,
    })?;
    let report = worker::run(
        &context.store,
        &context.protocol,
        worker::AdmitAndDrain {
            output: delete,
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("admit deletion: {err}"))?;
    if report.admitted.inserted_events == 0 {
        return Err("deletion was not admitted".to_string());
    }
    content_purge::run(
        &context.store,
        content_purge::Work::Drain {
            limit: worker::DEFAULT_READY_BATCH,
        },
    )?;
    Ok(CliOutput::lines(
        DeleteSummary {
            event_id: report.value.deletion_id,
            target_message_id: report.value.target_message_id,
        }
        .lines(),
    ))
}

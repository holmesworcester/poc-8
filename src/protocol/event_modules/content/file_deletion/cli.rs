//! File deletion CLI: `delete-file`.
//!
//! This adapter resolves a file selector, signs the deletion fact with the
//! local workspace endpoint, admits it, then runs one bounded purge pass so
//! local display state catches up. It does not define deletion semantics:
//! the protocol fact lives in `commands`/`projector`, and byte retention
//! belongs to the worker.

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::protocol::cli::Context;
use crate::protocol::event_modules::content::message;
use crate::protocol::event_modules::identity::endpoint;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker;
use crate::workers::content_purge;

use super::commands;

const DELETE_USAGE: &str = "delete-file WORKSPACE_ID_HEX FILE_SELECTOR";

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![CliCommand {
        name: "delete-file",
        usage: DELETE_USAGE,
        help: "Delete one of your files in a workspace.",
        run: run_delete_command,
    }]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteSummary {
    pub event_id: EventId,
    pub target_file_event_id: EventId,
}

impl DeleteSummary {
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("event_id: {}", message::cli::hex_id(self.event_id)),
            format!(
                "target: {}",
                message::cli::hex_id(self.target_file_event_id)
            ),
        ]
    }
}

fn run_delete_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(2, DELETE_USAGE)?;
    let workspace_id =
        message::cli::parse_hex_id(args.get(0).expect("length checked"), DELETE_USAGE)?;
    let target = resolve_file_selector(
        &context.store,
        workspace_id,
        args.get(1).expect("length checked"),
    )?;

    let membership = message::cli::require_membership(&context.store, workspace_id)?;
    let local = endpoint::commands::local_keypair(&context.store)?
        .ok_or_else(|| "local endpoint is missing".to_string())?;

    let timestamp = message::cli::next_timestamp(&context.store, workspace_id)?;
    let delete = commands::delete(commands::DeleteFile {
        workspace_id,
        created_at_ms: timestamp,
        target_file_event_id: target,
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
    .map_err(|err| format!("admit file deletion: {err}"))?;
    if report.admitted.inserted_events == 0 {
        return Err("file deletion was not admitted".to_string());
    }
    content_purge::run(
        &context.store,
        &context.protocol,
        content_purge::Work::Drain {
            limit: worker::DEFAULT_READY_BATCH,
        },
    )?;
    Ok(CliOutput::lines(
        DeleteSummary {
            event_id: report.value.deletion_id,
            target_file_event_id: report.value.target_file_event_id,
        }
        .lines(),
    ))
}

/// Accept either a hex file_event_id or a `#N` selector against the
/// workspace's visible file rows. Mirrors the message-deletion CLI's
/// selector ergonomics so `topo delete-file WS #1` works in scripts.
fn resolve_file_selector(
    store: &crate::core::store::Store,
    workspace_id: EventId,
    selector: &str,
) -> Result<EventId, String> {
    if let Some(rest) = selector.strip_prefix('#') {
        let number: usize = rest
            .parse()
            .map_err(|_| format!("invalid file selector: {selector}"))?;
        if number == 0 {
            return Err(format!("invalid file selector: {selector}"));
        }
        let rows =
            crate::protocol::event_modules::content::file::cli::visible_file_rows(store, workspace_id)?;
        let row = rows
            .get(number - 1)
            .ok_or_else(|| format!("file #{number} does not exist"))?;
        Ok(row.file_event_id)
    } else {
        message::cli::parse_hex_id(selector, "FILE_SELECTOR")
    }
}

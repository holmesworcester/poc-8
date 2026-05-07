//! Reaction CLI: `react`.
//!
//! This adapter resolves a message selector, loads local membership and content
//! key material, then admits one signed reaction event. It does not own reaction
//! projection, display grouping, or message deletion cleanup; those stay in the
//! reaction projector/schema and content purge worker.

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::core::crypto;
use crate::core::store::Store;
use crate::protocol::cli::Context;
use crate::protocol::event_modules::content::message;
use crate::protocol::event_modules::encryption::local_key_secret;
use crate::protocol::event_modules::identity::endpoint;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker;

use super::types::{ReactionEvent, ReactionRow};
use super::{codec, commands, schema};

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
    let content_key = message::cli::require_content_key(&context.store, workspace_id)?;
    let post = commands::post(commands::PostReaction {
        workspace_id,
        created_at_ms: timestamp,
        target_message_id: target,
        author_user_id: membership.user_authority_event_id,
        signer_endpoint_shared_id: membership.endpoint_shared_id,
        signer_private_key: local.signing_secret,
        removal_frontier_id: content_key.removal_frontier_id,
        local_key_secret_id: content_key.local_key_secret_id,
        key_secret: content_key.key_secret,
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

/// Read-time decryption of sealed reactions for a workspace.
///
/// Mirrors the message CLI's read-time decrypt path so debuggability tools can
/// show emojis without forcing projector files to call cryptographic helpers.
pub fn decrypted_for_workspace(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<ReactionRow>, String> {
    let mut rows = schema::list_for_workspace(store, workspace_id)?;
    let known: std::collections::BTreeSet<EventId> =
        rows.iter().map(|row| row.reaction_id).collect();
    for sealed in sealed_for_workspace(store, workspace_id)? {
        if known.contains(&sealed.reaction_id) {
            continue;
        }
        if let Some(row) = open_sealed(store, sealed)? {
            rows.push(row);
        }
    }
    rows.sort_by(|a, b| {
        a.created_at_ms
            .cmp(&b.created_at_ms)
            .then_with(|| a.reaction_id.cmp(&b.reaction_id))
    });
    Ok(rows)
}

fn sealed_for_workspace(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<schema::SealedReactionRow>, String> {
    store
        .table_rows_with_key_prefix(schema::SEALED_REACTIONS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load sealed reactions: {err}"))?
        .into_iter()
        .map(|(key, value)| schema::decode_sealed_reaction_row(&key, &value))
        .collect()
}

fn open_sealed(
    store: &Store,
    row: schema::SealedReactionRow,
) -> Result<Option<ReactionRow>, String> {
    let Some(secret) =
        local_key_secret::schema::get(store, row.workspace_id, row.removal_frontier_id)?
    else {
        return Ok(None);
    };
    if secret.local_key_secret_id != row.local_key_secret_id {
        return Err("sealed reaction local_key_secret_id does not match local key".to_string());
    }
    let event = ReactionEvent {
        workspace_id: row.workspace_id,
        created_at_ms: row.created_at_ms,
        target_message_id: row.target_message_id,
        author_user_id: row.author_user_id,
        removal_frontier_id: row.removal_frontier_id,
        local_key_secret_id: row.local_key_secret_id,
        nonce: row.nonce,
        ciphertext: row.ciphertext,
    };
    let plaintext = crypto::xchacha20poly1305_decrypt(
        &secret.key_secret,
        &codec::associated_data(&event, row.signer_endpoint_shared_id),
        &event.nonce,
        &event.ciphertext,
    )
    .map_err(|err| format!("decrypt sealed reaction: {err}"))?;
    let emoji = codec::decode_emoji_slot(&plaintext)?;
    Ok(Some(ReactionRow {
        workspace_id: row.workspace_id,
        reaction_id: row.reaction_id,
        target_message_id: row.target_message_id,
        author_user_id: row.author_user_id,
        signer_endpoint_shared_id: row.signer_endpoint_shared_id,
        created_at_ms: row.created_at_ms,
        emoji,
    }))
}

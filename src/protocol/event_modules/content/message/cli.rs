//! Message CLI: `send` and `messages`.
//!
//! `send` looks up the local endpoint's workspace membership, builds a signed
//! message, and admits it. `messages` is a read-only listing that joins users
//! and content/reaction/file projections so display matches the poc-7 contract
//! without scoped CLI helpers reaching across modules' write paths.

use std::collections::BTreeMap;

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::core::crypto;
use crate::core::logical_clock;
use crate::core::store::Store;
use crate::protocol::cli::Context;
use crate::protocol::event_modules::content::message_deletion::types::deletion_label_author;
use crate::protocol::event_modules::content::reaction;
use crate::protocol::event_modules::encryption::{
    local_history_node_secret, local_key_secret, removal_frontier,
};
use crate::protocol::event_modules::identity::{endpoint, endpoint_shared, user};
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker;
use crate::workers::encryption as encryption_worker;

use super::types::message_event_id_in_minute;

use super::{commands, schema};

const SEND_USAGE: &str = "send WORKSPACE_ID_HEX TEXT";
const MESSAGES_USAGE: &str = "messages WORKSPACE_ID_HEX [LIMIT]";

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![
        CliCommand {
            name: "send",
            usage: SEND_USAGE,
            help: "Send a message to a workspace.",
            run: run_send_command,
        },
        CliCommand {
            name: "messages",
            usage: MESSAGES_USAGE,
            help: "List messages for a workspace.",
            run: run_messages_command,
        },
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendSummary {
    pub event_id: EventId,
    pub text: String,
}

impl SendSummary {
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("event_id: {}", hex_id(self.event_id)),
            format!("text: {}", self.text),
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageDisplay {
    pub index: usize,
    pub message_id: EventId,
    pub author_user_id: EventId,
    pub author_username: String,
    pub created_at_ms: u64,
    pub text: String,
    pub reactions: Vec<String>,
    pub files: Vec<String>,
}

impl MessageDisplay {
    pub fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        lines.push(format!(
            "{}. [{}] {}: {}",
            self.index, self.created_at_ms, self.author_username, self.text
        ));
        if !self.reactions.is_empty() {
            lines.push(format!("   reactions: {}", self.reactions.join(" ")));
        }
        for file in &self.files {
            lines.push(format!("   file: {}", file));
        }
        lines.push(format!("   id: {}", hex_id(self.message_id)));
        lines
    }
}

fn run_send_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(2, SEND_USAGE)?;
    let workspace_id = parse_hex_id(args.get(0).expect("length checked"), SEND_USAGE)?;
    let text = args.get(1).expect("length checked").to_string();

    let membership = require_membership(&context.store, workspace_id)?;
    let local = endpoint::commands::local_keypair(&context.store)?
        .ok_or_else(|| "local endpoint is missing".to_string())?;
    if membership.signing_public_key != local.signing_public_key {
        return Err("local endpoint signing key does not match workspace membership".to_string());
    }

    let timestamp = next_timestamp(&context.store, workspace_id)?;
    let removal_frontier_id = require_active_frontier_id(&context.store, workspace_id)?;
    let event_id_in_minute = message_event_id_in_minute(
        &workspace_id,
        &membership.user_authority_event_id,
        &removal_frontier_id,
        timestamp,
    );
    let leaf = derive_message_leaf(
        &context.store,
        &context.protocol,
        workspace_id,
        removal_frontier_id,
        timestamp,
        event_id_in_minute,
    )?;
    let send = commands::send(commands::SendMessage {
        workspace_id,
        created_at_ms: timestamp,
        author_user_id: membership.user_authority_event_id,
        signer_endpoint_shared_id: membership.endpoint_shared_id,
        signer_private_key: local.signing_secret,
        removal_frontier_id,
        local_history_node_secret_id: leaf.local_history_node_secret_id,
        leaf_node_secret: leaf.leaf_node_secret,
        text,
    })?;
    let report = worker::run(
        &context.store,
        &context.protocol,
        worker::AdmitAndDrain {
            output: send,
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("admit message: {err}"))?;
    if report.admitted.inserted_events == 0 {
        return Err("message was not admitted".to_string());
    }
    Ok(CliOutput::lines(
        SendSummary {
            event_id: report.value.message_id,
            text: report.value.text,
        }
        .lines(),
    ))
}

fn run_messages_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    if args.values().is_empty() || args.values().len() > 2 {
        return Err(MESSAGES_USAGE.to_string());
    }
    let workspace_id = parse_hex_id(args.get(0).expect("length checked"), MESSAGES_USAGE)?;
    let limit = match args.get(1) {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| MESSAGES_USAGE.to_string())?,
        None => 0,
    };

    let messages = list_for_display(&context.store, workspace_id, limit)?;
    let mut lines = vec![format!("messages: {}", messages.len())];
    for message in &messages {
        lines.extend(message.lines());
    }
    Ok(CliOutput::lines(lines))
}

pub fn list_for_display(
    store: &Store,
    workspace_id: EventId,
    limit: usize,
) -> Result<Vec<MessageDisplay>, String> {
    let mut messages = visible_message_rows(store, workspace_id)?;
    let total = messages.len();
    let take = if limit == 0 || limit >= total {
        total
    } else {
        limit
    };
    let start = total - take;
    messages.drain(..start);
    let reactions = reactions_grouped_by_message_for_display(store, workspace_id)?;
    let files = files_grouped_by_message_for_display(store, workspace_id)?;
    let mut display = Vec::with_capacity(messages.len());
    for (idx, row) in messages.into_iter().enumerate() {
        let author_username = user_name(store, workspace_id, row.author_user_id)?;
        let reactions_for = reactions.get(&row.message_id).cloned().unwrap_or_default();
        let files_for = files
            .get(&row.message_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|file| file.summary())
            .collect::<Vec<_>>();
        display.push(MessageDisplay {
            index: start + idx + 1,
            message_id: row.message_id,
            author_user_id: row.author_user_id,
            author_username,
            created_at_ms: row.created_at_ms,
            text: row.text,
            reactions: reactions_for,
            files: files_for,
        });
    }
    Ok(display)
}

/// True iff the target message id has a deletion label authored by `author_user_id`.
///
/// Projectors now purge message rows for both message-before-tombstone and
/// tombstone-before-message orders. The read-side check remains as a defensive
/// compatibility filter for rows written by older code or interrupted test
/// fixtures; it should not be the primary deletion mechanism.
pub(crate) fn is_deleted_by_author(
    store: &Store,
    message_id: &EventId,
    author_user_id: &EventId,
) -> Result<bool, String> {
    let labels = event_schema::event_labels(store, message_id)
        .map_err(|err| format!("load deletion labels: {err}"))?;
    Ok(labels.iter().any(|label| {
        deletion_label_author(label)
            .map(|author| author == *author_user_id)
            .unwrap_or(false)
    }))
}

fn visible_message_rows(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<super::types::MessageRow>, String> {
    let mut by_id = BTreeMap::new();
    for row in schema::list_for_workspace(store, workspace_id)? {
        by_id.insert(row.message_id, row);
    }
    for sealed in sealed_message_rows_for_workspace(store, workspace_id)? {
        if let Some(row) = open_sealed_message_row(store, sealed)? {
            by_id.entry(row.message_id).or_insert(row);
        }
    }
    let mut rows = by_id.into_values().collect::<Vec<_>>();
    rows.sort_by(|a, b| {
        a.created_at_ms
            .cmp(&b.created_at_ms)
            .then_with(|| a.message_id.cmp(&b.message_id))
    });
    rows.into_iter()
        .filter_map(
            |row| match is_deleted_by_author(store, &row.message_id, &row.author_user_id) {
                Ok(false) => Some(Ok(row)),
                Ok(true) => None,
                Err(err) => Some(Err(err)),
            },
        )
        .collect()
}

fn sealed_message_rows_for_workspace(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<schema::SealedMessageRow>, String> {
    store
        .table_rows_with_key_prefix(schema::SEALED_MESSAGES, &workspace_id, usize::MAX)
        .map_err(|err| format!("load sealed messages: {err}"))?
        .into_iter()
        .map(|(key, value)| schema::decode_sealed_message_row(&key, &value))
        .collect()
}

fn open_sealed_message_row(
    store: &Store,
    row: schema::SealedMessageRow,
) -> Result<Option<super::types::MessageRow>, String> {
    let unix_minute = super::types::unix_minute_for(row.created_at_ms);
    let event_id_in_minute = message_event_id_in_minute(
        &row.workspace_id,
        &row.author_user_id,
        &row.removal_frontier_id,
        row.created_at_ms,
    );
    let Some(leaf) = local_history_node_secret::schema::get_leaf(
        store,
        row.workspace_id,
        row.removal_frontier_id,
        unix_minute,
        event_id_in_minute,
    )?
    else {
        return Ok(None);
    };
    if leaf.local_history_node_secret_id != row.local_history_node_secret_id {
        return Err(
            "sealed message local_history_node_secret_id does not match local leaf".to_string(),
        );
    }
    let event = super::types::MessageEvent {
        workspace_id: row.workspace_id,
        created_at_ms: row.created_at_ms,
        author_user_id: row.author_user_id,
        removal_frontier_id: row.removal_frontier_id,
        local_history_node_secret_id: row.local_history_node_secret_id,
        nonce: row.nonce,
        ciphertext: row.ciphertext,
    };
    let plaintext = crypto::xchacha20poly1305_decrypt(
        &leaf.node_secret,
        &super::codec::associated_data(&event, row.signer_endpoint_shared_id),
        &event.nonce,
        &event.ciphertext,
    )
    .map_err(|err| format!("decrypt sealed message: {err}"))?;
    let text = super::codec::decode_text_slot(&plaintext)?;
    Ok(Some(super::types::MessageRow {
        workspace_id: row.workspace_id,
        message_id: row.message_id,
        created_at_ms: row.created_at_ms,
        author_user_id: row.author_user_id,
        signer_endpoint_shared_id: row.signer_endpoint_shared_id,
        text,
    }))
}

fn files_grouped_by_message_for_display(
    store: &Store,
    workspace_id: EventId,
) -> Result<BTreeMap<EventId, Vec<super::super::file::types::FileRow>>, String> {
    let rows = super::super::file::cli::visible_file_rows(store, workspace_id)?;
    let mut grouped: BTreeMap<EventId, Vec<super::super::file::types::FileRow>> = BTreeMap::new();
    for row in rows {
        grouped.entry(row.message_id).or_default().push(row);
    }
    Ok(grouped)
}

fn reactions_grouped_by_message_for_display(
    store: &Store,
    workspace_id: EventId,
) -> Result<BTreeMap<EventId, Vec<String>>, String> {
    let rows = visible_reaction_rows(store, workspace_id)?;
    let mut grouped: BTreeMap<EventId, Vec<(EventId, String)>> = BTreeMap::new();
    for row in rows {
        let entry = grouped.entry(row.target_message_id).or_default();
        let key_pair = (row.author_user_id, row.emoji.clone());
        if !entry.iter().any(|existing| existing == &key_pair) {
            entry.push(key_pair);
        }
    }
    Ok(grouped
        .into_iter()
        .map(|(target, pairs)| (target, pairs.into_iter().map(|(_, emoji)| emoji).collect()))
        .collect())
}

/// All reactions visible to the local store for one workspace, including
/// sealed rows that the local key secret can open. Sorted chronologically by
/// `(created_at_ms, reaction_id)` so callers can group/dedupe deterministically.
pub fn visible_reaction_rows(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<reaction::types::ReactionRow>, String> {
    let mut by_id = BTreeMap::new();
    for row in reaction::schema::list_for_workspace(store, workspace_id)? {
        by_id.insert(row.reaction_id, row);
    }
    for sealed in sealed_reaction_rows_for_workspace(store, workspace_id)? {
        if let Some(row) = open_sealed_reaction_row(store, sealed)? {
            by_id.entry(row.reaction_id).or_insert(row);
        }
    }

    let mut rows = by_id.into_values().collect::<Vec<_>>();
    rows.sort_by(|a, b| {
        a.created_at_ms
            .cmp(&b.created_at_ms)
            .then_with(|| a.reaction_id.cmp(&b.reaction_id))
    });
    Ok(rows)
}

fn sealed_reaction_rows_for_workspace(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<reaction::schema::SealedReactionRow>, String> {
    store
        .table_rows_with_key_prefix(
            reaction::schema::SEALED_REACTIONS,
            &workspace_id,
            usize::MAX,
        )
        .map_err(|err| format!("load sealed reactions: {err}"))?
        .into_iter()
        .map(|(key, value)| reaction::schema::decode_sealed_reaction_row(&key, &value))
        .collect()
}

fn open_sealed_reaction_row(
    store: &Store,
    row: reaction::schema::SealedReactionRow,
) -> Result<Option<reaction::types::ReactionRow>, String> {
    let unix_minute = super::types::unix_minute_for(row.created_at_ms);
    let event_id_in_minute = reaction::types::reaction_event_id_in_minute(
        &row.workspace_id,
        &row.author_user_id,
        &row.target_message_id,
        &row.removal_frontier_id,
        row.created_at_ms,
    );
    let Some(leaf) = local_history_node_secret::schema::get_leaf(
        store,
        row.workspace_id,
        row.removal_frontier_id,
        unix_minute,
        event_id_in_minute,
    )?
    else {
        return Ok(None);
    };
    if leaf.local_history_node_secret_id != row.local_history_node_secret_id {
        return Err(
            "sealed reaction local_history_node_secret_id does not match local leaf".to_string(),
        );
    }
    let event = reaction::types::ReactionEvent {
        workspace_id: row.workspace_id,
        created_at_ms: row.created_at_ms,
        target_message_id: row.target_message_id,
        author_user_id: row.author_user_id,
        removal_frontier_id: row.removal_frontier_id,
        local_history_node_secret_id: row.local_history_node_secret_id,
        nonce: row.nonce,
        ciphertext: row.ciphertext,
    };
    let plaintext = crypto::xchacha20poly1305_decrypt(
        &leaf.node_secret,
        &reaction::codec::associated_data(&event, row.signer_endpoint_shared_id),
        &event.nonce,
        &event.ciphertext,
    )
    .map_err(|err| format!("decrypt sealed reaction: {err}"))?;
    let emoji = reaction::codec::decode_emoji_slot(&plaintext)?;
    Ok(Some(reaction::types::ReactionRow {
        workspace_id: row.workspace_id,
        reaction_id: row.reaction_id,
        target_message_id: row.target_message_id,
        author_user_id: row.author_user_id,
        signer_endpoint_shared_id: row.signer_endpoint_shared_id,
        created_at_ms: row.created_at_ms,
        emoji,
    }))
}

pub fn resolve_selector(
    store: &Store,
    workspace_id: EventId,
    selector: &str,
) -> Result<EventId, String> {
    if let Some(rest) = selector.strip_prefix('#') {
        let number: usize = rest
            .parse()
            .map_err(|_| format!("invalid message selector: {selector}"))?;
        if number == 0 {
            return Err(format!("invalid message selector: {selector}"));
        }
        let messages = visible_message_rows(store, workspace_id)?;
        let row = messages
            .get(number - 1)
            .ok_or_else(|| format!("message #{number} does not exist"))?;
        Ok(row.message_id)
    } else {
        parse_hex_id(selector, "MESSAGE_SELECTOR")
    }
}

pub(crate) fn require_membership(
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MessageLeafKey {
    pub removal_frontier_id: EventId,
    pub local_history_node_secret_id: EventId,
    pub leaf_node_secret: local_key_secret::types::KeySecret,
}

/// Find the most recent local frontier for which this store has key material.
///
/// Senders need a frontier id to author messages; receivers do not call this
/// because they trust the message body to name the frontier id.
pub(crate) fn require_active_frontier_id(
    store: &Store,
    workspace_id: EventId,
) -> Result<EventId, String> {
    let mut candidates = Vec::new();
    for frontier in removal_frontier::schema::list_for_workspace(store, workspace_id)? {
        let Some(secret) =
            local_key_secret::schema::get(store, workspace_id, frontier.removal_frontier_id)?
        else {
            continue;
        };
        candidates.push((
            frontier.created_at_ms,
            frontier.removal_frontier_id,
            secret.local_key_secret_id,
        ));
    }
    candidates.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    let Some((_, removal_frontier_id, _)) = candidates.pop() else {
        return Err(
            "local content key is missing for workspace; run key-frontier or key-derive"
                .to_string(),
        );
    };
    Ok(removal_frontier_id)
}

/// Derive (or look up) the per-message minute_node and leaf for one
/// `(workspace_id, removal_frontier_id, created_at_ms, event_id_in_minute)`
/// quadruple.
///
/// The minute_node is shared across every message in the same `unix_minute`,
/// so first call admits it and subsequent calls reuse the row. The leaf is
/// per-message and never shared. The caller computes the deterministic
/// `event_id_in_minute` from canonical event fields (see
/// `message_event_id_in_minute`); two peers authoring the same logical
/// message reach the same leaf id by BLAKE3-keyed-hash determinism. Returns
/// the leaf id and the leaf's `node_secret` for AEAD use.
pub(crate) fn derive_message_leaf<R>(
    store: &Store,
    registry: &R,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    created_at_ms: u64,
    event_id_in_minute: EventId,
) -> Result<MessageLeafKey, String>
where
    R: crate::workers::pipeline_helpers::event_pipeline::EventRegistry,
{
    let output = encryption_worker::run(
        store,
        registry,
        encryption_worker::Work::DeriveMessageLeaf {
            workspace_id,
            removal_frontier_id,
            created_at_ms,
            event_id_in_minute,
        },
    )?;
    let encryption_worker::Output::DerivedMessageLeaf(report) = output else {
        return Err("unexpected encryption worker output".to_string());
    };
    let local_history_node_secret_id = report
        .local_history_node_secret_id
        .ok_or_else(|| "leaf history node secret id was not produced".to_string())?;
    let leaf_node_secret = report
        .leaf_node_secret
        .ok_or_else(|| "leaf history node secret material was not produced".to_string())?;
    Ok(MessageLeafKey {
        removal_frontier_id,
        local_history_node_secret_id,
        leaf_node_secret,
    })
}

pub(crate) fn next_timestamp(store: &Store, workspace_id: EventId) -> Result<u64, String> {
    let from_messages = max_timestamp_for_messages(store, workspace_id)?;
    let from_content =
        super::super::content_event::schema::max_timestamp_for_workspace(store, workspace_id)?;
    logical_clock::next_timestamp(store, from_messages.max(from_content))
}

fn max_timestamp_for_messages(store: &Store, workspace_id: EventId) -> Result<u64, String> {
    let mut max = 0u64;
    for row in visible_message_rows(store, workspace_id)? {
        if row.created_at_ms > max {
            max = row.created_at_ms;
        }
    }
    Ok(max)
}

fn user_name(store: &Store, workspace_id: EventId, user_id: EventId) -> Result<String, String> {
    let key = user::schema::user_key(&workspace_id, &user_id);
    let value = store
        .table_row(user::schema::USERS, &key)
        .map_err(|err| format!("load user: {err}"))?;
    match value {
        Some(value) => {
            let row = user::schema::decode_user_row(&key, &value)?;
            Ok(row.username)
        }
        None => Ok(format!("<{}>", short_id(user_id))),
    }
}

fn short_id(id: EventId) -> String {
    hex_id(id)[..8].to_string()
}

pub(crate) fn parse_hex_id(value: &str, usage: &str) -> Result<EventId, String> {
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

pub fn hex_id(id: EventId) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in id {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

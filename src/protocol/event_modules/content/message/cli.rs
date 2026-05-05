//! Message CLI: `send` and `messages`.
//!
//! `send` looks up the local endpoint's workspace membership, builds a signed
//! message, and admits it. `messages` is a read-only listing that joins users
//! and content/reaction/file projections so display matches the poc-7 contract
//! without scoped CLI helpers reaching across modules' write paths.

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::core::store::Store;
use crate::protocol::cli::Context;
use crate::protocol::event_modules::content::message_deletion::types::deletion_label_author;
use crate::protocol::event_modules::identity::{endpoint, endpoint_shared, user};
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker;

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
    pub author_username: String,
    pub created_at_ms: u64,
    pub text: String,
    pub reactions: Vec<String>,
    pub files: Vec<String>,
    pub deleted: bool,
}

impl MessageDisplay {
    pub fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        let suffix = if self.deleted { " (deleted)" } else { "" };
        lines.push(format!(
            "{}. [{}] {}{}: {}",
            self.index, self.created_at_ms, self.author_username, suffix, self.text
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
    let send = commands::send(commands::SendMessage {
        workspace_id,
        created_at_ms: timestamp,
        author_user_id: membership.user_authority_event_id,
        signer_endpoint_shared_id: membership.endpoint_shared_id,
        signer_private_key: local.signing_secret,
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
    let visible_count = messages.iter().filter(|message| !message.deleted).count();
    let mut lines = vec![format!("messages: {}", visible_count)];
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
    let mut messages = schema::list_for_workspace(store, workspace_id)?;
    let total = messages.len();
    let take = if limit == 0 || limit >= total {
        total
    } else {
        limit
    };
    let start = total - take;
    messages.drain(..start);
    let reactions =
        super::super::reaction::schema::reactions_grouped_by_message(store, workspace_id)?;
    let files = super::super::file::schema::files_grouped_by_message(store, workspace_id)?;
    let mut display = Vec::with_capacity(messages.len());
    for (idx, row) in messages.into_iter().enumerate() {
        let author_username = user_name(store, workspace_id, row.author_user_id)?;
        let deleted = is_deleted_by_author(store, &row.message_id, &row.author_user_id)?;
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
            author_username,
            created_at_ms: row.created_at_ms,
            text: row.text,
            reactions: reactions_for,
            files: files_for,
            deleted,
        });
    }
    Ok(display)
}

/// True iff the target message id has a deletion label authored by `author_user_id`.
///
/// Read-time filter for the delete-after-create case: the message row was
/// projected before the deletion arrived, so it sits in storage but display
/// queries hide it. The projector handles the delete-before-create case at
/// project time.
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
        let messages = schema::list_for_workspace(store, workspace_id)?;
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

pub(crate) fn next_timestamp(store: &Store, workspace_id: EventId) -> Result<u64, String> {
    let from_messages = max_timestamp_for_messages(store, workspace_id)?;
    let from_content =
        super::super::content_event::schema::max_timestamp_for_workspace(store, workspace_id)?;
    Ok(from_messages.max(from_content).saturating_add(1))
}

fn max_timestamp_for_messages(store: &Store, workspace_id: EventId) -> Result<u64, String> {
    let mut max = 0u64;
    for row in schema::list_for_workspace(store, workspace_id)? {
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

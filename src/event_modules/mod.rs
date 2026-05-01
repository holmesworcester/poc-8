use crate::pipeline::{ConnectionId, EventId, WorkspaceId};
use rusqlite::Connection;
use std::collections::HashMap;
use thiserror::Error;

pub const TYPE_WORKSPACE: u8 = 1;
pub const TYPE_MESSAGE: u8 = 2;
pub const TYPE_CONNECTION: u8 = 3;
pub const TYPE_SYNC_COMPARE: u8 = 4;
pub const TYPE_SYNC_HAVE: u8 = 5;
pub const TYPE_SYNC_NEED: u8 = 6;
pub const TYPE_REACTION: u8 = 7;
pub const TYPE_MESSAGE_DELETION: u8 = 8;
pub const TYPE_FILE: u8 = 9;
pub const TYPE_ACCOUNT: u8 = 10;
pub const TYPE_INVITE: u8 = 11;
pub const TYPE_INVITE_ACCEPTED: u8 = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Shared,
    Local,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Shared => "shared",
            Scope::Local => "local",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Workspace(WorkspaceEvent),
    Message(MessageEvent),
    Reaction(ReactionEvent),
    MessageDeletion(MessageDeletionEvent),
    File(FileEvent),
    Account(AccountEvent),
    Invite(InviteEvent),
    InviteAccepted(InviteAcceptedEvent),
    Connection(ConnectionEvent),
    SyncCompare(SyncCompareEvent),
    SyncHave(SyncHaveEvent),
    SyncNeed(SyncNeedEvent),
}

impl Event {
    pub fn scope(&self) -> Scope {
        match self {
            Event::Workspace(_)
            | Event::Message(_)
            | Event::Reaction(_)
            | Event::MessageDeletion(_)
            | Event::File(_)
            | Event::Account(_)
            | Event::Invite(_)
            | Event::InviteAccepted(_) => Scope::Shared,
            Event::Connection(_)
            | Event::SyncCompare(_)
            | Event::SyncHave(_)
            | Event::SyncNeed(_) => Scope::Local,
        }
    }

    pub fn workspace_id(&self) -> WorkspaceId {
        match self {
            Event::Workspace(e) => e.workspace_id,
            Event::Message(e) => e.workspace_id,
            Event::Reaction(e) => e.workspace_id,
            Event::MessageDeletion(e) => e.workspace_id,
            Event::File(e) => e.workspace_id,
            Event::Account(e) => e.workspace_id,
            Event::Invite(e) => e.workspace_id,
            Event::InviteAccepted(e) => e.workspace_id,
            Event::Connection(e) => e.workspace_id,
            Event::SyncCompare(e) => e.workspace_id,
            Event::SyncHave(e) => e.workspace_id,
            Event::SyncNeed(e) => e.workspace_id,
        }
    }

    pub fn dependency_ids(&self) -> Vec<EventId> {
        match self {
            Event::Workspace(_)
            | Event::SyncCompare(_)
            | Event::SyncHave(_)
            | Event::SyncNeed(_) => Vec::new(),
            Event::Message(e) => non_zero_ids([e.workspace_event_id, e.reply_to_event_id]),
            Event::Reaction(e) => non_zero_ids([e.message_event_id]),
            Event::MessageDeletion(e) => non_zero_ids([e.message_event_id]),
            Event::File(e) => non_zero_ids([e.workspace_event_id]),
            Event::Account(e) => non_zero_ids([e.workspace_event_id]),
            Event::Invite(e) => non_zero_ids([e.workspace_event_id]),
            Event::InviteAccepted(e) => non_zero_ids([e.invite_event_id]),
            Event::Connection(e) => non_zero_ids([e.workspace_event_id]),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceEvent {
    pub workspace_id: WorkspaceId,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEvent {
    pub workspace_id: WorkspaceId,
    pub workspace_event_id: EventId,
    pub reply_to_event_id: EventId,
    pub fanout_connection_id: ConnectionId,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactionEvent {
    pub workspace_id: WorkspaceId,
    pub message_event_id: EventId,
    pub emoji: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageDeletionEvent {
    pub workspace_id: WorkspaceId,
    pub message_event_id: EventId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEvent {
    pub workspace_id: WorkspaceId,
    pub workspace_event_id: EventId,
    pub name: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountEvent {
    pub workspace_id: WorkspaceId,
    pub workspace_event_id: EventId,
    pub account_id: [u8; 32],
    pub username: String,
    pub device_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteEvent {
    pub workspace_id: WorkspaceId,
    pub workspace_event_id: EventId,
    pub invite_id: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteAcceptedEvent {
    pub workspace_id: WorkspaceId,
    pub invite_event_id: EventId,
    pub account_id: [u8; 32],
    pub username: String,
    pub device_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionEvent {
    pub workspace_id: WorkspaceId,
    pub connection_id: ConnectionId,
    pub workspace_event_id: EventId,
    pub peer_id: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncCompareEvent {
    pub workspace_id: WorkspaceId,
    pub connection_id: ConnectionId,
    pub root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncHaveEvent {
    pub workspace_id: WorkspaceId,
    pub connection_id: ConnectionId,
    pub have_event_id: EventId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncNeedEvent {
    pub workspace_id: WorkspaceId,
    pub connection_id: ConnectionId,
    pub needed_event_id: EventId,
}

#[derive(Debug, Error)]
pub enum EventError {
    #[error("empty event")]
    Empty,
    #[error("unknown event type {0}")]
    UnknownType(u8),
    #[error("truncated event")]
    Truncated,
    #[error("invalid utf-8")]
    InvalidUtf8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEvent {
    pub event_id: EventId,
    pub event: Event,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionContext {
    pub origin_connection_id: Option<ConnectionId>,
    pub now_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Projection {
    pub row_ops: Vec<RowOp>,
    pub labels: Vec<LabelOp>,
    pub outbox: Vec<OutboxOp>,
    pub emitted_events: Vec<Vec<u8>>,
    pub purges: Vec<EventId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowOp {
    pub table: &'static str,
    pub columns: Vec<&'static str>,
    pub values: Vec<SqlValue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqlValue {
    Blob(Vec<u8>),
    Integer(i64),
    Text(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelOp {
    pub subject_event_id: EventId,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxOp {
    pub connection_id: ConnectionId,
    pub event_id: EventId,
}

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS workspaces (
            workspace_id BLOB PRIMARY KEY NOT NULL,
            name TEXT NOT NULL,
            source_event_id BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS messages (
            event_id BLOB PRIMARY KEY NOT NULL,
            workspace_id BLOB NOT NULL,
            reply_to_event_id BLOB NOT NULL,
            body TEXT NOT NULL,
            source_event_id BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_messages_workspace
            ON messages(workspace_id);
        CREATE TABLE IF NOT EXISTS reactions (
            event_id BLOB PRIMARY KEY NOT NULL,
            workspace_id BLOB NOT NULL,
            message_event_id BLOB NOT NULL,
            emoji TEXT NOT NULL,
            source_event_id BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_reactions_message
            ON reactions(message_event_id);
        CREATE TABLE IF NOT EXISTS deleted_messages (
            message_event_id BLOB PRIMARY KEY NOT NULL,
            deletion_event_id BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS files (
            event_id BLOB PRIMARY KEY NOT NULL,
            workspace_id BLOB NOT NULL,
            name TEXT NOT NULL,
            byte_len INTEGER NOT NULL,
            content_hash TEXT NOT NULL,
            bytes BLOB NOT NULL,
            source_event_id BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_files_workspace
            ON files(workspace_id);
        CREATE TABLE IF NOT EXISTS accounts (
            account_id BLOB PRIMARY KEY NOT NULL,
            workspace_id BLOB NOT NULL,
            username TEXT NOT NULL,
            device_name TEXT NOT NULL,
            source_event_id BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_accounts_workspace
            ON accounts(workspace_id);
        CREATE TABLE IF NOT EXISTS invites (
            event_id BLOB PRIMARY KEY NOT NULL,
            workspace_id BLOB NOT NULL,
            invite_id BLOB NOT NULL,
            source_event_id BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_invites_workspace
            ON invites(workspace_id);
        CREATE TABLE IF NOT EXISTS invite_acceptances (
            account_id BLOB PRIMARY KEY NOT NULL,
            workspace_id BLOB NOT NULL,
            invite_event_id BLOB NOT NULL,
            source_event_id BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_invite_acceptances_workspace
            ON invite_acceptances(workspace_id);
        CREATE TABLE IF NOT EXISTS connections (
            connection_id BLOB PRIMARY KEY NOT NULL,
            workspace_id BLOB NOT NULL,
            peer_id BLOB NOT NULL,
            source_event_id BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_connections_workspace
            ON connections(workspace_id);
        CREATE TABLE IF NOT EXISTS sync_compares (
            event_id BLOB PRIMARY KEY NOT NULL,
            workspace_id BLOB NOT NULL,
            connection_id BLOB NOT NULL,
            root BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sync_have (
            event_id BLOB PRIMARY KEY NOT NULL,
            workspace_id BLOB NOT NULL,
            connection_id BLOB NOT NULL,
            have_event_id BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sync_need (
            event_id BLOB PRIMARY KEY NOT NULL,
            workspace_id BLOB NOT NULL,
            connection_id BLOB NOT NULL,
            needed_event_id BLOB NOT NULL
        );
        ",
    )
}

pub fn project(
    event_id: EventId,
    event: &Event,
    _deps: &[ResolvedEvent],
    labels: &HashMap<EventId, Vec<String>>,
    context: &ProjectionContext,
) -> Projection {
    match event {
        Event::Workspace(e) => project_workspace(event_id, e),
        Event::Message(e) => project_message(event_id, e, labels),
        Event::Reaction(e) => project_reaction(event_id, e, labels),
        Event::MessageDeletion(e) => project_message_deletion(event_id, e),
        Event::File(e) => project_file(event_id, e),
        Event::Account(e) => project_account(event_id, e),
        Event::Invite(e) => project_invite(event_id, e),
        Event::InviteAccepted(e) => project_invite_accepted(event_id, e),
        Event::Connection(e) => project_connection(event_id, e),
        Event::SyncCompare(e) => project_sync_compare(event_id, e),
        Event::SyncHave(e) => project_sync_have(event_id, e),
        Event::SyncNeed(e) => project_sync_need(event_id, e, context),
    }
}

pub fn event_type_name(event: &Event) -> &'static str {
    match event {
        Event::Workspace(_) => "workspace",
        Event::Message(_) => "message",
        Event::Reaction(_) => "reaction",
        Event::MessageDeletion(_) => "message_deletion",
        Event::File(_) => "file",
        Event::Account(_) => "account",
        Event::Invite(_) => "invite",
        Event::InviteAccepted(_) => "invite_accepted",
        Event::Connection(_) => "connection",
        Event::SyncCompare(_) => "sync_compare",
        Event::SyncHave(_) => "sync_have",
        Event::SyncNeed(_) => "sync_need",
    }
}

fn project_workspace(event_id: EventId, event: &WorkspaceEvent) -> Projection {
    Projection {
        row_ops: vec![RowOp::upsert(
            "workspaces",
            &["workspace_id", "name", "source_event_id"],
            vec![
                SqlValue::Blob(event.workspace_id.to_vec()),
                SqlValue::Text(event.name.clone()),
                SqlValue::Blob(event_id.to_vec()),
            ],
        )],
        labels: vec![LabelOp {
            subject_event_id: event_id,
            label: "workspace".to_string(),
        }],
        ..Projection::default()
    }
}

fn project_message(
    event_id: EventId,
    event: &MessageEvent,
    labels: &HashMap<EventId, Vec<String>>,
) -> Projection {
    if labels
        .get(&event.reply_to_event_id)
        .is_some_and(|labels| labels.iter().any(|label| label == "deleted"))
    {
        return Projection::default();
    }

    let mut projection = Projection {
        row_ops: vec![RowOp::upsert(
            "messages",
            &[
                "event_id",
                "workspace_id",
                "reply_to_event_id",
                "body",
                "source_event_id",
            ],
            vec![
                SqlValue::Blob(event_id.to_vec()),
                SqlValue::Blob(event.workspace_id.to_vec()),
                SqlValue::Blob(event.reply_to_event_id.to_vec()),
                SqlValue::Text(event.body.clone()),
                SqlValue::Blob(event_id.to_vec()),
            ],
        )],
        labels: vec![LabelOp {
            subject_event_id: event_id,
            label: "message".to_string(),
        }],
        ..Projection::default()
    };

    if event.fanout_connection_id != [0; 32] {
        projection.outbox.push(OutboxOp {
            connection_id: event.fanout_connection_id,
            event_id,
        });
    }

    projection
}

fn project_reaction(
    event_id: EventId,
    event: &ReactionEvent,
    labels: &HashMap<EventId, Vec<String>>,
) -> Projection {
    if labels
        .get(&event.message_event_id)
        .is_some_and(|labels| labels.iter().any(|label| label == "deleted"))
    {
        return Projection::default();
    }

    Projection {
        row_ops: vec![RowOp::upsert(
            "reactions",
            &[
                "event_id",
                "workspace_id",
                "message_event_id",
                "emoji",
                "source_event_id",
            ],
            vec![
                SqlValue::Blob(event_id.to_vec()),
                SqlValue::Blob(event.workspace_id.to_vec()),
                SqlValue::Blob(event.message_event_id.to_vec()),
                SqlValue::Text(event.emoji.clone()),
                SqlValue::Blob(event_id.to_vec()),
            ],
        )],
        labels: vec![LabelOp {
            subject_event_id: event_id,
            label: "reaction".to_string(),
        }],
        ..Projection::default()
    }
}

fn project_message_deletion(event_id: EventId, event: &MessageDeletionEvent) -> Projection {
    Projection {
        row_ops: vec![RowOp::upsert(
            "deleted_messages",
            &["message_event_id", "deletion_event_id"],
            vec![
                SqlValue::Blob(event.message_event_id.to_vec()),
                SqlValue::Blob(event_id.to_vec()),
            ],
        )],
        labels: vec![
            LabelOp {
                subject_event_id: event.message_event_id,
                label: "deleted".to_string(),
            },
            LabelOp {
                subject_event_id: event_id,
                label: "message_deletion".to_string(),
            },
        ],
        ..Projection::default()
    }
}

fn project_file(event_id: EventId, event: &FileEvent) -> Projection {
    Projection {
        row_ops: vec![RowOp::upsert(
            "files",
            &[
                "event_id",
                "workspace_id",
                "name",
                "byte_len",
                "content_hash",
                "bytes",
                "source_event_id",
            ],
            vec![
                SqlValue::Blob(event_id.to_vec()),
                SqlValue::Blob(event.workspace_id.to_vec()),
                SqlValue::Text(event.name.clone()),
                SqlValue::Integer(event.bytes.len() as i64),
                SqlValue::Text(blake3::hash(&event.bytes).to_hex().to_string()),
                SqlValue::Blob(event.bytes.clone()),
                SqlValue::Blob(event_id.to_vec()),
            ],
        )],
        labels: vec![LabelOp {
            subject_event_id: event_id,
            label: "file".to_string(),
        }],
        ..Projection::default()
    }
}

fn project_account(event_id: EventId, event: &AccountEvent) -> Projection {
    Projection {
        row_ops: vec![account_row(
            event.account_id,
            event.workspace_id,
            &event.username,
            &event.device_name,
            event_id,
        )],
        labels: vec![LabelOp {
            subject_event_id: event_id,
            label: "account".to_string(),
        }],
        ..Projection::default()
    }
}

fn project_invite(event_id: EventId, event: &InviteEvent) -> Projection {
    Projection {
        row_ops: vec![RowOp::upsert(
            "invites",
            &["event_id", "workspace_id", "invite_id", "source_event_id"],
            vec![
                SqlValue::Blob(event_id.to_vec()),
                SqlValue::Blob(event.workspace_id.to_vec()),
                SqlValue::Blob(event.invite_id.to_vec()),
                SqlValue::Blob(event_id.to_vec()),
            ],
        )],
        labels: vec![LabelOp {
            subject_event_id: event_id,
            label: "invite".to_string(),
        }],
        ..Projection::default()
    }
}

fn project_invite_accepted(event_id: EventId, event: &InviteAcceptedEvent) -> Projection {
    Projection {
        row_ops: vec![
            account_row(
                event.account_id,
                event.workspace_id,
                &event.username,
                &event.device_name,
                event_id,
            ),
            RowOp::upsert(
                "invite_acceptances",
                &[
                    "account_id",
                    "workspace_id",
                    "invite_event_id",
                    "source_event_id",
                ],
                vec![
                    SqlValue::Blob(event.account_id.to_vec()),
                    SqlValue::Blob(event.workspace_id.to_vec()),
                    SqlValue::Blob(event.invite_event_id.to_vec()),
                    SqlValue::Blob(event_id.to_vec()),
                ],
            ),
        ],
        labels: vec![LabelOp {
            subject_event_id: event_id,
            label: "invite_accepted".to_string(),
        }],
        ..Projection::default()
    }
}

fn account_row(
    account_id: [u8; 32],
    workspace_id: WorkspaceId,
    username: &str,
    device_name: &str,
    source_event_id: EventId,
) -> RowOp {
    RowOp::upsert(
        "accounts",
        &[
            "account_id",
            "workspace_id",
            "username",
            "device_name",
            "source_event_id",
        ],
        vec![
            SqlValue::Blob(account_id.to_vec()),
            SqlValue::Blob(workspace_id.to_vec()),
            SqlValue::Text(username.to_string()),
            SqlValue::Text(device_name.to_string()),
            SqlValue::Blob(source_event_id.to_vec()),
        ],
    )
}

fn project_connection(event_id: EventId, event: &ConnectionEvent) -> Projection {
    Projection {
        row_ops: vec![RowOp::upsert(
            "connections",
            &[
                "connection_id",
                "workspace_id",
                "peer_id",
                "source_event_id",
            ],
            vec![
                SqlValue::Blob(event.connection_id.to_vec()),
                SqlValue::Blob(event.workspace_id.to_vec()),
                SqlValue::Blob(event.peer_id.to_vec()),
                SqlValue::Blob(event_id.to_vec()),
            ],
        )],
        labels: vec![LabelOp {
            subject_event_id: event_id,
            label: "connection".to_string(),
        }],
        ..Projection::default()
    }
}

fn project_sync_compare(event_id: EventId, event: &SyncCompareEvent) -> Projection {
    Projection {
        row_ops: vec![RowOp::upsert(
            "sync_compares",
            &["event_id", "workspace_id", "connection_id", "root"],
            vec![
                SqlValue::Blob(event_id.to_vec()),
                SqlValue::Blob(event.workspace_id.to_vec()),
                SqlValue::Blob(event.connection_id.to_vec()),
                SqlValue::Blob(event.root.to_vec()),
            ],
        )],
        labels: vec![LabelOp {
            subject_event_id: event_id,
            label: "sync_compare".to_string(),
        }],
        ..Projection::default()
    }
}

fn project_sync_have(event_id: EventId, event: &SyncHaveEvent) -> Projection {
    Projection {
        row_ops: vec![RowOp::upsert(
            "sync_have",
            &["event_id", "workspace_id", "connection_id", "have_event_id"],
            vec![
                SqlValue::Blob(event_id.to_vec()),
                SqlValue::Blob(event.workspace_id.to_vec()),
                SqlValue::Blob(event.connection_id.to_vec()),
                SqlValue::Blob(event.have_event_id.to_vec()),
            ],
        )],
        labels: vec![LabelOp {
            subject_event_id: event_id,
            label: "sync_have".to_string(),
        }],
        ..Projection::default()
    }
}

fn project_sync_need(
    event_id: EventId,
    event: &SyncNeedEvent,
    context: &ProjectionContext,
) -> Projection {
    let mut projection = Projection {
        row_ops: vec![RowOp::upsert(
            "sync_need",
            &[
                "event_id",
                "workspace_id",
                "connection_id",
                "needed_event_id",
            ],
            vec![
                SqlValue::Blob(event_id.to_vec()),
                SqlValue::Blob(event.workspace_id.to_vec()),
                SqlValue::Blob(event.connection_id.to_vec()),
                SqlValue::Blob(event.needed_event_id.to_vec()),
            ],
        )],
        labels: vec![LabelOp {
            subject_event_id: event_id,
            label: "sync_need".to_string(),
        }],
        ..Projection::default()
    };

    if Some(event.connection_id) != context.origin_connection_id {
        projection.outbox.push(OutboxOp {
            connection_id: event.connection_id,
            event_id,
        });
    }

    projection
}

impl RowOp {
    fn upsert(table: &'static str, columns: &[&'static str], values: Vec<SqlValue>) -> Self {
        Self {
            table,
            columns: columns.to_vec(),
            values,
        }
    }
}

pub fn encode_workspace(workspace_id: WorkspaceId, name: &str) -> Vec<u8> {
    let mut out = vec![TYPE_WORKSPACE];
    out.extend_from_slice(&workspace_id);
    put_string_u16(&mut out, name);
    out
}

pub fn encode_message(
    workspace_id: WorkspaceId,
    workspace_event_id: EventId,
    reply_to_event_id: EventId,
    fanout_connection_id: ConnectionId,
    body: &str,
) -> Vec<u8> {
    let mut out = vec![TYPE_MESSAGE];
    out.extend_from_slice(&workspace_id);
    out.extend_from_slice(&workspace_event_id);
    out.extend_from_slice(&reply_to_event_id);
    out.extend_from_slice(&fanout_connection_id);
    put_string_u32(&mut out, body);
    out
}

pub fn encode_connection(
    workspace_id: WorkspaceId,
    connection_id: ConnectionId,
    workspace_event_id: EventId,
    peer_id: [u8; 32],
) -> Vec<u8> {
    let mut out = vec![TYPE_CONNECTION];
    out.extend_from_slice(&workspace_id);
    out.extend_from_slice(&connection_id);
    out.extend_from_slice(&workspace_event_id);
    out.extend_from_slice(&peer_id);
    out
}

pub fn encode_reaction(
    workspace_id: WorkspaceId,
    message_event_id: EventId,
    emoji: &str,
) -> Vec<u8> {
    let mut out = vec![TYPE_REACTION];
    out.extend_from_slice(&workspace_id);
    out.extend_from_slice(&message_event_id);
    put_string_u16(&mut out, emoji);
    out
}

pub fn encode_message_deletion(workspace_id: WorkspaceId, message_event_id: EventId) -> Vec<u8> {
    let mut out = vec![TYPE_MESSAGE_DELETION];
    out.extend_from_slice(&workspace_id);
    out.extend_from_slice(&message_event_id);
    out
}

pub fn encode_file(
    workspace_id: WorkspaceId,
    workspace_event_id: EventId,
    name: &str,
    bytes: &[u8],
) -> Vec<u8> {
    let mut out = vec![TYPE_FILE];
    out.extend_from_slice(&workspace_id);
    out.extend_from_slice(&workspace_event_id);
    put_string_u16(&mut out, name);
    put_bytes_u64(&mut out, bytes);
    out
}

pub fn encode_account(
    workspace_id: WorkspaceId,
    workspace_event_id: EventId,
    account_id: [u8; 32],
    username: &str,
    device_name: &str,
) -> Vec<u8> {
    let mut out = vec![TYPE_ACCOUNT];
    out.extend_from_slice(&workspace_id);
    out.extend_from_slice(&workspace_event_id);
    out.extend_from_slice(&account_id);
    put_string_u16(&mut out, username);
    put_string_u16(&mut out, device_name);
    out
}

pub fn encode_invite(
    workspace_id: WorkspaceId,
    workspace_event_id: EventId,
    invite_id: [u8; 32],
) -> Vec<u8> {
    let mut out = vec![TYPE_INVITE];
    out.extend_from_slice(&workspace_id);
    out.extend_from_slice(&workspace_event_id);
    out.extend_from_slice(&invite_id);
    out
}

pub fn encode_invite_accepted(
    workspace_id: WorkspaceId,
    invite_event_id: EventId,
    account_id: [u8; 32],
    username: &str,
    device_name: &str,
) -> Vec<u8> {
    let mut out = vec![TYPE_INVITE_ACCEPTED];
    out.extend_from_slice(&workspace_id);
    out.extend_from_slice(&invite_event_id);
    out.extend_from_slice(&account_id);
    put_string_u16(&mut out, username);
    put_string_u16(&mut out, device_name);
    out
}

pub fn encode_sync_compare(
    workspace_id: WorkspaceId,
    connection_id: ConnectionId,
    root: [u8; 32],
) -> Vec<u8> {
    encode_three_id_event(TYPE_SYNC_COMPARE, workspace_id, connection_id, root)
}

pub fn encode_sync_have(
    workspace_id: WorkspaceId,
    connection_id: ConnectionId,
    have_event_id: EventId,
) -> Vec<u8> {
    encode_three_id_event(TYPE_SYNC_HAVE, workspace_id, connection_id, have_event_id)
}

pub fn encode_sync_need(
    workspace_id: WorkspaceId,
    connection_id: ConnectionId,
    needed_event_id: EventId,
) -> Vec<u8> {
    encode_three_id_event(TYPE_SYNC_NEED, workspace_id, connection_id, needed_event_id)
}

pub fn decode(bytes: &[u8]) -> Result<Event, EventError> {
    let (&kind, rest) = bytes.split_first().ok_or(EventError::Empty)?;
    let mut cursor = Cursor::new(rest);
    match kind {
        TYPE_WORKSPACE => {
            let workspace_id = cursor.id()?;
            let name = cursor.string_u16()?;
            cursor.finish()?;
            Ok(Event::Workspace(WorkspaceEvent { workspace_id, name }))
        }
        TYPE_MESSAGE => {
            let workspace_id = cursor.id()?;
            let workspace_event_id = cursor.id()?;
            let reply_to_event_id = cursor.id()?;
            let fanout_connection_id = cursor.id()?;
            let body = cursor.string_u32()?;
            cursor.finish()?;
            Ok(Event::Message(MessageEvent {
                workspace_id,
                workspace_event_id,
                reply_to_event_id,
                fanout_connection_id,
                body,
            }))
        }
        TYPE_REACTION => {
            let workspace_id = cursor.id()?;
            let message_event_id = cursor.id()?;
            let emoji = cursor.string_u16()?;
            cursor.finish()?;
            Ok(Event::Reaction(ReactionEvent {
                workspace_id,
                message_event_id,
                emoji,
            }))
        }
        TYPE_MESSAGE_DELETION => {
            let workspace_id = cursor.id()?;
            let message_event_id = cursor.id()?;
            cursor.finish()?;
            Ok(Event::MessageDeletion(MessageDeletionEvent {
                workspace_id,
                message_event_id,
            }))
        }
        TYPE_FILE => {
            let workspace_id = cursor.id()?;
            let workspace_event_id = cursor.id()?;
            let name = cursor.string_u16()?;
            let bytes = cursor.bytes_u64()?;
            cursor.finish()?;
            Ok(Event::File(FileEvent {
                workspace_id,
                workspace_event_id,
                name,
                bytes,
            }))
        }
        TYPE_ACCOUNT => {
            let workspace_id = cursor.id()?;
            let workspace_event_id = cursor.id()?;
            let account_id = cursor.id()?;
            let username = cursor.string_u16()?;
            let device_name = cursor.string_u16()?;
            cursor.finish()?;
            Ok(Event::Account(AccountEvent {
                workspace_id,
                workspace_event_id,
                account_id,
                username,
                device_name,
            }))
        }
        TYPE_INVITE => {
            let workspace_id = cursor.id()?;
            let workspace_event_id = cursor.id()?;
            let invite_id = cursor.id()?;
            cursor.finish()?;
            Ok(Event::Invite(InviteEvent {
                workspace_id,
                workspace_event_id,
                invite_id,
            }))
        }
        TYPE_INVITE_ACCEPTED => {
            let workspace_id = cursor.id()?;
            let invite_event_id = cursor.id()?;
            let account_id = cursor.id()?;
            let username = cursor.string_u16()?;
            let device_name = cursor.string_u16()?;
            cursor.finish()?;
            Ok(Event::InviteAccepted(InviteAcceptedEvent {
                workspace_id,
                invite_event_id,
                account_id,
                username,
                device_name,
            }))
        }
        TYPE_CONNECTION => {
            let workspace_id = cursor.id()?;
            let connection_id = cursor.id()?;
            let workspace_event_id = cursor.id()?;
            let peer_id = cursor.id()?;
            cursor.finish()?;
            Ok(Event::Connection(ConnectionEvent {
                workspace_id,
                connection_id,
                workspace_event_id,
                peer_id,
            }))
        }
        TYPE_SYNC_COMPARE => {
            let (workspace_id, connection_id, root) = cursor.three_ids()?;
            Ok(Event::SyncCompare(SyncCompareEvent {
                workspace_id,
                connection_id,
                root,
            }))
        }
        TYPE_SYNC_HAVE => {
            let (workspace_id, connection_id, have_event_id) = cursor.three_ids()?;
            Ok(Event::SyncHave(SyncHaveEvent {
                workspace_id,
                connection_id,
                have_event_id,
            }))
        }
        TYPE_SYNC_NEED => {
            let (workspace_id, connection_id, needed_event_id) = cursor.three_ids()?;
            Ok(Event::SyncNeed(SyncNeedEvent {
                workspace_id,
                connection_id,
                needed_event_id,
            }))
        }
        other => Err(EventError::UnknownType(other)),
    }
}

fn encode_three_id_event(
    kind: u8,
    workspace_id: WorkspaceId,
    connection_id: ConnectionId,
    third_id: [u8; 32],
) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&workspace_id);
    out.extend_from_slice(&connection_id);
    out.extend_from_slice(&third_id);
    out
}

fn non_zero_ids(ids: impl IntoIterator<Item = EventId>) -> Vec<EventId> {
    ids.into_iter().filter(|id| *id != [0; 32]).collect()
}

fn put_string_u16(out: &mut Vec<u8>, value: &str) {
    let len = u16::try_from(value.len()).expect("string too large for u16 codec");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}

fn put_string_u32(out: &mut Vec<u8>, value: &str) {
    let len = u32::try_from(value.len()).expect("string too large for u32 codec");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}

fn put_bytes_u64(out: &mut Vec<u8>, value: &[u8]) {
    let len = u64::try_from(value.len()).expect("bytes too large for u64 codec");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
}

struct Cursor<'a> {
    rest: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn new(rest: &'a [u8]) -> Self {
        Self { rest }
    }

    fn id(&mut self) -> Result<[u8; 32], EventError> {
        if self.rest.len() < 32 {
            return Err(EventError::Truncated);
        }
        let (head, tail) = self.rest.split_at(32);
        self.rest = tail;
        let mut id = [0; 32];
        id.copy_from_slice(head);
        Ok(id)
    }

    fn string_u16(&mut self) -> Result<String, EventError> {
        if self.rest.len() < 2 {
            return Err(EventError::Truncated);
        }
        let len = u16::from_be_bytes([self.rest[0], self.rest[1]]) as usize;
        self.rest = &self.rest[2..];
        self.string(len)
    }

    fn string_u32(&mut self) -> Result<String, EventError> {
        if self.rest.len() < 4 {
            return Err(EventError::Truncated);
        }
        let len =
            u32::from_be_bytes([self.rest[0], self.rest[1], self.rest[2], self.rest[3]]) as usize;
        self.rest = &self.rest[4..];
        self.string(len)
    }

    fn string(&mut self, len: usize) -> Result<String, EventError> {
        if self.rest.len() < len {
            return Err(EventError::Truncated);
        }
        let (head, tail) = self.rest.split_at(len);
        self.rest = tail;
        String::from_utf8(head.to_vec()).map_err(|_| EventError::InvalidUtf8)
    }

    fn bytes_u64(&mut self) -> Result<Vec<u8>, EventError> {
        if self.rest.len() < 8 {
            return Err(EventError::Truncated);
        }
        let len = u64::from_be_bytes([
            self.rest[0],
            self.rest[1],
            self.rest[2],
            self.rest[3],
            self.rest[4],
            self.rest[5],
            self.rest[6],
            self.rest[7],
        ]);
        self.rest = &self.rest[8..];
        let len = usize::try_from(len).map_err(|_| EventError::Truncated)?;
        if self.rest.len() < len {
            return Err(EventError::Truncated);
        }
        let (head, tail) = self.rest.split_at(len);
        self.rest = tail;
        Ok(head.to_vec())
    }

    fn three_ids(&mut self) -> Result<([u8; 32], [u8; 32], [u8; 32]), EventError> {
        let first = self.id()?;
        let second = self.id()?;
        let third = self.id()?;
        self.finish()?;
        Ok((first, second, third))
    }

    fn finish(&self) -> Result<(), EventError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(EventError::Truncated)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_codec_round_trips() {
        let workspace_id = [7; 32];
        let bytes = encode_workspace(workspace_id, "ops");

        assert_eq!(
            decode(&bytes).unwrap(),
            Event::Workspace(WorkspaceEvent {
                workspace_id,
                name: "ops".to_string()
            })
        );
    }

    #[test]
    fn message_dependencies_ignore_zero_reply() {
        let workspace_id = [1; 32];
        let workspace_event_id = [2; 32];
        let bytes = encode_message(workspace_id, workspace_event_id, [0; 32], [9; 32], "hello");
        let event = decode(&bytes).unwrap();

        assert_eq!(event.dependency_ids(), vec![workspace_event_id]);
    }

    #[test]
    fn reaction_depends_on_message() {
        let message_id = [4; 32];
        let bytes = encode_reaction([1; 32], message_id, "heart");
        let event = decode(&bytes).unwrap();

        assert_eq!(event.dependency_ids(), vec![message_id]);
        assert_eq!(event_type_name(&event), "reaction");
    }

    #[test]
    fn file_codec_round_trips_and_depends_on_workspace() {
        let workspace_id = [1; 32];
        let workspace_event_id = [2; 32];
        let bytes = encode_file(workspace_id, workspace_event_id, "a.bin", b"abc");
        let event = decode(&bytes).unwrap();

        assert_eq!(
            event,
            Event::File(FileEvent {
                workspace_id,
                workspace_event_id,
                name: "a.bin".to_string(),
                bytes: b"abc".to_vec(),
            })
        );
        assert_eq!(event.dependency_ids(), vec![workspace_event_id]);
        assert_eq!(event_type_name(&event), "file");
    }

    #[test]
    fn account_and_invite_codecs_express_dependencies() {
        let workspace_id = [1; 32];
        let workspace_event_id = [2; 32];
        let account_id = [3; 32];
        let invite_id = [4; 32];
        let account = decode(&encode_account(
            workspace_id,
            workspace_event_id,
            account_id,
            "alice",
            "laptop",
        ))
        .unwrap();
        let invite = decode(&encode_invite(workspace_id, workspace_event_id, invite_id)).unwrap();

        assert_eq!(account.dependency_ids(), vec![workspace_event_id]);
        assert_eq!(event_type_name(&account), "account");
        assert_eq!(invite.dependency_ids(), vec![workspace_event_id]);
        assert_eq!(event_type_name(&invite), "invite");
    }

    #[test]
    fn invite_accepted_depends_on_invite() {
        let workspace_id = [1; 32];
        let invite_event_id = [9; 32];
        let account_id = [3; 32];
        let event = decode(&encode_invite_accepted(
            workspace_id,
            invite_event_id,
            account_id,
            "bob",
            "phone",
        ))
        .unwrap();

        assert_eq!(event.dependency_ids(), vec![invite_event_id]);
        assert_eq!(event_type_name(&event), "invite_accepted");
    }
}

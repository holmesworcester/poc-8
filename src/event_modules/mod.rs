pub mod account;
pub mod codec;
pub mod connection;
pub mod file;
pub mod invite;
pub mod message;
pub mod message_deletion;
pub mod reaction;
pub mod sync;
pub mod workspace;

use crate::pipeline::{ConnectionId, EventId, WorkspaceId};
use std::collections::HashMap;
use thiserror::Error;

pub use account::{encode_account, AccountEvent};
pub use connection::{encode_connection, ConnectionEvent};
pub use file::{encode_file, FileEvent};
pub use invite::{encode_invite, encode_invite_accepted, InviteAcceptedEvent, InviteEvent};
pub use message::{encode_message, MessageEvent};
pub use message_deletion::{encode_message_deletion, MessageDeletionEvent};
pub use reaction::{encode_reaction, ReactionEvent};
pub use sync::{
    encode_sync_compare, encode_sync_have, encode_sync_need, SyncCompareEvent, SyncHaveEvent,
    SyncNeedEvent,
};
pub use workspace::{encode_workspace, WorkspaceEvent};

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

pub trait EventWriter {
    type Error;

    fn append_event(&mut self, bytes: Vec<u8>) -> Result<Admission, Self::Error>;

    fn append_apply(&mut self, bytes: Vec<u8>) -> Result<WriteResult, Self::Error>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission {
    pub event_id: EventId,
    pub status: AdmissionStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionStatus {
    Ready,
    Blocked { blocked_by: Vec<EventId> },
    Duplicate { status: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteResult {
    pub event_id: EventId,
    pub status: WriteStatus,
    pub emitted: Vec<EventId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteStatus {
    Applied,
    AlreadyApplied,
    Blocked { blocked_by: Vec<EventId> },
}

pub const MODULE_TABLES: &[&[&str]] = &[
    workspace::TABLES,
    message::TABLES,
    reaction::TABLES,
    message_deletion::TABLES,
    file::TABLES,
    account::TABLES,
    invite::TABLES,
    connection::TABLES,
    sync::TABLES,
];

pub fn schema_statements() -> impl Iterator<Item = &'static str> {
    MODULE_TABLES
        .iter()
        .flat_map(|tables| tables.iter().copied())
}

pub fn decode(bytes: &[u8]) -> Result<Event, EventError> {
    let (&kind, rest) = bytes.split_first().ok_or(EventError::Empty)?;
    let mut cursor = codec::Cursor::new(rest);
    match kind {
        workspace::TYPE_CODE => workspace::decode(&mut cursor).map(Event::Workspace),
        message::TYPE_CODE => message::decode(&mut cursor).map(Event::Message),
        reaction::TYPE_CODE => reaction::decode(&mut cursor).map(Event::Reaction),
        message_deletion::TYPE_CODE => {
            message_deletion::decode(&mut cursor).map(Event::MessageDeletion)
        }
        file::TYPE_CODE => file::decode(&mut cursor).map(Event::File),
        account::TYPE_CODE => account::decode(&mut cursor).map(Event::Account),
        invite::TYPE_INVITE => invite::decode_invite(&mut cursor).map(Event::Invite),
        invite::TYPE_INVITE_ACCEPTED => {
            invite::decode_invite_accepted(&mut cursor).map(Event::InviteAccepted)
        }
        connection::TYPE_CODE => connection::decode(&mut cursor).map(Event::Connection),
        sync::TYPE_COMPARE => sync::decode_compare(&mut cursor).map(Event::SyncCompare),
        sync::TYPE_HAVE => sync::decode_have(&mut cursor).map(Event::SyncHave),
        sync::TYPE_NEED => sync::decode_need(&mut cursor).map(Event::SyncNeed),
        other => Err(EventError::UnknownType(other)),
    }
}

pub fn project(
    event_id: EventId,
    event: &Event,
    _deps: &[ResolvedEvent],
    labels: &HashMap<EventId, Vec<String>>,
    context: &ProjectionContext,
) -> Projection {
    match event {
        Event::Workspace(e) => workspace::project(event_id, e),
        Event::Message(e) => message::project(event_id, e, labels, context),
        Event::Reaction(e) => reaction::project(event_id, e, labels),
        Event::MessageDeletion(e) => message_deletion::project(event_id, e),
        Event::File(e) => file::project(event_id, e),
        Event::Account(e) => account::project(event_id, e),
        Event::Invite(e) => invite::project_invite(event_id, e),
        Event::InviteAccepted(e) => invite::project_invite_accepted(event_id, e),
        Event::Connection(e) => connection::project(event_id, e),
        Event::SyncCompare(e) => sync::project_compare(event_id, e),
        Event::SyncHave(e) => sync::project_have(event_id, e),
        Event::SyncNeed(e) => sync::project_need(event_id, e, context),
    }
}

pub fn event_type_name(event: &Event) -> &'static str {
    match event {
        Event::Workspace(_) => workspace::TYPE_NAME,
        Event::Message(_) => message::TYPE_NAME,
        Event::Reaction(_) => reaction::TYPE_NAME,
        Event::MessageDeletion(_) => message_deletion::TYPE_NAME,
        Event::File(_) => file::TYPE_NAME,
        Event::Account(_) => account::TYPE_NAME,
        Event::Invite(_) => invite::INVITE_TYPE_NAME,
        Event::InviteAccepted(_) => invite::INVITE_ACCEPTED_TYPE_NAME,
        Event::Connection(_) => connection::TYPE_NAME,
        Event::SyncCompare(_) => sync::COMPARE_TYPE_NAME,
        Event::SyncHave(_) => sync::HAVE_TYPE_NAME,
        Event::SyncNeed(_) => sync::NEED_TYPE_NAME,
    }
}

impl RowOp {
    pub(crate) fn upsert(
        table: &'static str,
        columns: &[&'static str],
        values: Vec<SqlValue>,
    ) -> Self {
        Self {
            table,
            columns: columns.to_vec(),
            values,
        }
    }
}

fn non_zero_ids(ids: impl IntoIterator<Item = EventId>) -> Vec<EventId> {
    ids.into_iter().filter(|id| *id != [0; 32]).collect()
}

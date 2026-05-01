use std::collections::HashMap;

use crate::pipeline::{ConnectionId, EventId, WorkspaceId};

use super::{LabelOp, OutboxOp, Projection, ProjectionContext, RowOp, SqlValue};

pub const TYPE_CODE: u8 = 2;
pub const TYPE_NAME: &str = "message";
pub const TABLES: &[&str] = &[
    "
    CREATE TABLE IF NOT EXISTS messages (
        event_id BLOB PRIMARY KEY NOT NULL,
        workspace_id BLOB NOT NULL,
        reply_to_event_id BLOB NOT NULL,
        body TEXT NOT NULL,
        source_event_id BLOB NOT NULL
    );
    ",
    "CREATE INDEX IF NOT EXISTS idx_messages_workspace ON messages(workspace_id);",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEvent {
    pub workspace_id: WorkspaceId,
    pub workspace_event_id: EventId,
    pub reply_to_event_id: EventId,
    pub fanout_connection_id: ConnectionId,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendMessageInput {
    pub workspace_id: WorkspaceId,
    pub workspace_event_id: EventId,
    pub reply_to_event_id: EventId,
    pub fanout_connection_id: ConnectionId,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendMessageOutput {
    pub event_id: EventId,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateMessagesInput {
    pub workspace_id: WorkspaceId,
    pub workspace_event_id: EventId,
    pub count: usize,
    pub prefix: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateMessagesOutput {
    pub written_events: usize,
    pub applied_events: usize,
}

pub fn send<W: super::EventWriter>(
    writer: &mut W,
    input: SendMessageInput,
) -> Result<SendMessageOutput, W::Error> {
    let bytes = encode_message(
        input.workspace_id,
        input.workspace_event_id,
        input.reply_to_event_id,
        input.fanout_connection_id,
        &input.body,
    );
    let written = writer.append_apply(bytes)?;
    Ok(SendMessageOutput {
        event_id: written.event_id,
        body: input.body,
    })
}

pub fn generate<W: super::EventWriter>(
    writer: &mut W,
    input: GenerateMessagesInput,
) -> Result<GenerateMessagesOutput, W::Error> {
    let mut written_events = 0;
    let mut applied_events = 0;
    for idx in 0..input.count {
        let body = format!("{} {idx:06}", input.prefix);
        let bytes = encode_message(
            input.workspace_id,
            input.workspace_event_id,
            [0; 32],
            [0; 32],
            &body,
        );
        let written = writer.append_apply(bytes)?;
        match written.status {
            super::WriteStatus::Applied => {
                written_events += 1;
                applied_events += 1;
            }
            super::WriteStatus::Blocked { .. } => written_events += 1,
            super::WriteStatus::AlreadyApplied => {}
        }
    }
    Ok(GenerateMessagesOutput {
        written_events,
        applied_events,
    })
}

pub fn encode_message(
    workspace_id: WorkspaceId,
    workspace_event_id: EventId,
    reply_to_event_id: EventId,
    fanout_connection_id: ConnectionId,
    body: &str,
) -> Vec<u8> {
    let mut out = vec![TYPE_CODE];
    out.extend_from_slice(&workspace_id);
    out.extend_from_slice(&workspace_event_id);
    out.extend_from_slice(&reply_to_event_id);
    out.extend_from_slice(&fanout_connection_id);
    super::codec::put_string_u32(&mut out, body);
    out
}

pub fn decode(cursor: &mut super::codec::Cursor<'_>) -> Result<MessageEvent, super::EventError> {
    let workspace_id = cursor.id()?;
    let workspace_event_id = cursor.id()?;
    let reply_to_event_id = cursor.id()?;
    let fanout_connection_id = cursor.id()?;
    let body = cursor.string_u32()?;
    cursor.finish()?;
    Ok(MessageEvent {
        workspace_id,
        workspace_event_id,
        reply_to_event_id,
        fanout_connection_id,
        body,
    })
}

pub fn project(
    event_id: EventId,
    event: &MessageEvent,
    labels: &HashMap<EventId, Vec<String>>,
    context: &ProjectionContext,
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
            label: TYPE_NAME.to_string(),
        }],
        ..Projection::default()
    };

    if event.fanout_connection_id != [0; 32]
        && Some(event.fanout_connection_id) != context.origin_connection_id
    {
        projection.outbox.push(OutboxOp {
            connection_id: event.fanout_connection_id,
            event_id,
        });
    }

    projection
}

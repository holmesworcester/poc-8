use std::collections::HashMap;

use crate::pipeline::{EventId, WorkspaceId};

use super::{LabelOp, Projection, RowOp, SqlValue};

pub const TYPE_CODE: u8 = 7;
pub const TYPE_NAME: &str = "reaction";
pub const TABLES: &[&str] = &[
    "
    CREATE TABLE IF NOT EXISTS reactions (
        event_id BLOB PRIMARY KEY NOT NULL,
        workspace_id BLOB NOT NULL,
        message_event_id BLOB NOT NULL,
        emoji TEXT NOT NULL,
        source_event_id BLOB NOT NULL
    );
    ",
    "CREATE INDEX IF NOT EXISTS idx_reactions_message ON reactions(message_event_id);",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactionEvent {
    pub workspace_id: WorkspaceId,
    pub message_event_id: EventId,
    pub emoji: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactInput {
    pub workspace_id: WorkspaceId,
    pub message_event_id: EventId,
    pub emoji: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactOutput {
    pub event_id: EventId,
}

pub fn react<W: super::EventWriter>(
    writer: &mut W,
    input: ReactInput,
) -> Result<ReactOutput, W::Error> {
    let bytes = encode_reaction(input.workspace_id, input.message_event_id, &input.emoji);
    let written = writer.append_apply(bytes)?;
    Ok(ReactOutput {
        event_id: written.event_id,
    })
}

pub fn encode_reaction(
    workspace_id: WorkspaceId,
    message_event_id: EventId,
    emoji: &str,
) -> Vec<u8> {
    let mut out = vec![TYPE_CODE];
    out.extend_from_slice(&workspace_id);
    out.extend_from_slice(&message_event_id);
    super::codec::put_string_u16(&mut out, emoji);
    out
}

pub fn decode(cursor: &mut super::codec::Cursor<'_>) -> Result<ReactionEvent, super::EventError> {
    let workspace_id = cursor.id()?;
    let message_event_id = cursor.id()?;
    let emoji = cursor.string_u16()?;
    cursor.finish()?;
    Ok(ReactionEvent {
        workspace_id,
        message_event_id,
        emoji,
    })
}

pub fn project(
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
            label: TYPE_NAME.to_string(),
        }],
        ..Projection::default()
    }
}

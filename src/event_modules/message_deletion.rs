use crate::pipeline::{EventId, WorkspaceId};

use super::{LabelOp, Projection, RowOp, SqlValue};

pub const TYPE_CODE: u8 = 8;
pub const TYPE_NAME: &str = "message_deletion";
pub const TABLES: &[&str] = &["
    CREATE TABLE IF NOT EXISTS deleted_messages (
        message_event_id BLOB PRIMARY KEY NOT NULL,
        deletion_event_id BLOB NOT NULL
    );
"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageDeletionEvent {
    pub workspace_id: WorkspaceId,
    pub message_event_id: EventId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteMessageInput {
    pub workspace_id: WorkspaceId,
    pub message_event_id: EventId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteMessageOutput {
    pub event_id: EventId,
}

pub fn delete<W: super::EventWriter>(
    writer: &mut W,
    input: DeleteMessageInput,
) -> Result<DeleteMessageOutput, W::Error> {
    let bytes = encode_message_deletion(input.workspace_id, input.message_event_id);
    let written = writer.append_apply(bytes)?;
    Ok(DeleteMessageOutput {
        event_id: written.event_id,
    })
}

pub fn encode_message_deletion(workspace_id: WorkspaceId, message_event_id: EventId) -> Vec<u8> {
    let mut out = vec![TYPE_CODE];
    out.extend_from_slice(&workspace_id);
    out.extend_from_slice(&message_event_id);
    out
}

pub fn decode(
    cursor: &mut super::codec::Cursor<'_>,
) -> Result<MessageDeletionEvent, super::EventError> {
    let workspace_id = cursor.id()?;
    let message_event_id = cursor.id()?;
    cursor.finish()?;
    Ok(MessageDeletionEvent {
        workspace_id,
        message_event_id,
    })
}

pub fn project(event_id: EventId, event: &MessageDeletionEvent) -> Projection {
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
                label: TYPE_NAME.to_string(),
            },
        ],
        ..Projection::default()
    }
}

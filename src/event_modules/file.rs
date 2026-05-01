use crate::pipeline::{EventId, WorkspaceId};

use super::{LabelOp, Projection, RowOp, SqlValue};

pub const TYPE_CODE: u8 = 9;
pub const TYPE_NAME: &str = "file";
pub const TABLES: &[&str] = &[
    "
    CREATE TABLE IF NOT EXISTS files (
        event_id BLOB PRIMARY KEY NOT NULL,
        workspace_id BLOB NOT NULL,
        name TEXT NOT NULL,
        byte_len INTEGER NOT NULL,
        content_hash TEXT NOT NULL,
        bytes BLOB NOT NULL,
        source_event_id BLOB NOT NULL
    );
    ",
    "CREATE INDEX IF NOT EXISTS idx_files_workspace ON files(workspace_id);",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEvent {
    pub workspace_id: WorkspaceId,
    pub workspace_event_id: EventId,
    pub name: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendFileInput {
    pub workspace_id: WorkspaceId,
    pub workspace_event_id: EventId,
    pub name: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendFileOutput {
    pub event_id: EventId,
    pub name: String,
    pub byte_len: usize,
    pub content_hash: String,
}

pub fn send<W: super::EventWriter>(
    writer: &mut W,
    input: SendFileInput,
) -> Result<SendFileOutput, W::Error> {
    let content_hash = blake3::hash(&input.bytes).to_hex().to_string();
    let byte_len = input.bytes.len();
    let bytes = encode_file(
        input.workspace_id,
        input.workspace_event_id,
        &input.name,
        &input.bytes,
    );
    let written = writer.append_apply(bytes)?;
    Ok(SendFileOutput {
        event_id: written.event_id,
        name: input.name,
        byte_len,
        content_hash,
    })
}

pub fn encode_file(
    workspace_id: WorkspaceId,
    workspace_event_id: EventId,
    name: &str,
    bytes: &[u8],
) -> Vec<u8> {
    let mut out = vec![TYPE_CODE];
    out.extend_from_slice(&workspace_id);
    out.extend_from_slice(&workspace_event_id);
    super::codec::put_string_u16(&mut out, name);
    super::codec::put_bytes_u64(&mut out, bytes);
    out
}

pub fn decode(cursor: &mut super::codec::Cursor<'_>) -> Result<FileEvent, super::EventError> {
    let workspace_id = cursor.id()?;
    let workspace_event_id = cursor.id()?;
    let name = cursor.string_u16()?;
    let bytes = cursor.bytes_u64()?;
    cursor.finish()?;
    Ok(FileEvent {
        workspace_id,
        workspace_event_id,
        name,
        bytes,
    })
}

pub fn project(event_id: EventId, event: &FileEvent) -> Projection {
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
            label: TYPE_NAME.to_string(),
        }],
        ..Projection::default()
    }
}

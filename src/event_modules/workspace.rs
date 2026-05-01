use crate::pipeline::{EventId, WorkspaceId};

use super::{LabelOp, Projection, RowOp, SqlValue};

pub const TYPE_CODE: u8 = 1;
pub const TYPE_NAME: &str = "workspace";
pub const TABLES: &[&str] = &["
    CREATE TABLE IF NOT EXISTS workspaces (
        workspace_id BLOB PRIMARY KEY NOT NULL,
        name TEXT NOT NULL,
        source_event_id BLOB NOT NULL
    );
"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceEvent {
    pub workspace_id: WorkspaceId,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateWorkspaceOutput {
    pub workspace_id: WorkspaceId,
    pub event_id: EventId,
    pub name: String,
}

pub fn create<W: super::EventWriter>(
    writer: &mut W,
    name: &str,
) -> Result<CreateWorkspaceOutput, W::Error> {
    let workspace_id = deterministic_workspace_id(name);
    let bytes = encode_workspace(workspace_id, name);
    let written = writer.append_apply(bytes)?;
    Ok(CreateWorkspaceOutput {
        workspace_id,
        event_id: written.event_id,
        name: name.to_string(),
    })
}

pub fn encode_workspace(workspace_id: WorkspaceId, name: &str) -> Vec<u8> {
    let mut out = vec![TYPE_CODE];
    out.extend_from_slice(&workspace_id);
    super::codec::put_string_u16(&mut out, name);
    out
}

fn deterministic_workspace_id(name: &str) -> WorkspaceId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"workspace:");
    hasher.update(name.as_bytes());
    *hasher.finalize().as_bytes()
}

pub fn decode(cursor: &mut super::codec::Cursor<'_>) -> Result<WorkspaceEvent, super::EventError> {
    let workspace_id = cursor.id()?;
    let name = cursor.string_u16()?;
    cursor.finish()?;
    Ok(WorkspaceEvent { workspace_id, name })
}

pub fn project(event_id: EventId, event: &WorkspaceEvent) -> Projection {
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
            label: TYPE_NAME.to_string(),
        }],
        ..Projection::default()
    }
}

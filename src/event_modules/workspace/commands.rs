use crate::event_modules::EventWriter;
use crate::pipeline::{EventId, WorkspaceId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateWorkspaceOutput {
    pub workspace_id: WorkspaceId,
    pub event_id: EventId,
    pub name: String,
}

pub fn create<W: EventWriter>(
    writer: &mut W,
    name: &str,
) -> Result<CreateWorkspaceOutput, W::Error> {
    let workspace_id = deterministic_workspace_id(name);
    let bytes = super::codec::encode_workspace(workspace_id, name);
    let written = writer.append_apply(bytes)?;
    Ok(CreateWorkspaceOutput {
        workspace_id,
        event_id: written.event_id,
        name: name.to_string(),
    })
}

fn deterministic_workspace_id(name: &str) -> WorkspaceId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"workspace:");
    hasher.update(name.as_bytes());
    *hasher.finalize().as_bytes()
}

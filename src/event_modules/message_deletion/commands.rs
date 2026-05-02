use crate::event_modules::EventWriter;
use crate::pipeline::{EventId, WorkspaceId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteMessageInput {
    pub workspace_id: WorkspaceId,
    pub message_event_id: EventId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteMessageOutput {
    pub event_id: EventId,
}

pub fn delete<W: EventWriter>(
    writer: &mut W,
    input: DeleteMessageInput,
) -> Result<DeleteMessageOutput, W::Error> {
    let bytes = super::codec::encode_message_deletion(input.workspace_id, input.message_event_id);
    let written = writer.append_apply(bytes)?;
    Ok(DeleteMessageOutput {
        event_id: written.event_id,
    })
}

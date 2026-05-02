use crate::event_modules::EventWriter;
use crate::pipeline::{EventId, WorkspaceId};

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

pub fn react<W: EventWriter>(writer: &mut W, input: ReactInput) -> Result<ReactOutput, W::Error> {
    let bytes =
        super::codec::encode_reaction(input.workspace_id, input.message_event_id, &input.emoji);
    let written = writer.append_apply(bytes)?;
    Ok(ReactOutput {
        event_id: written.event_id,
    })
}

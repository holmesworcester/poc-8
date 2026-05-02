use crate::event_modules::{EventWriter, WriteStatus};
use crate::pipeline::{ConnectionId, EventId, WorkspaceId};

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

pub fn send<W: EventWriter>(
    writer: &mut W,
    input: SendMessageInput,
) -> Result<SendMessageOutput, W::Error> {
    let bytes = super::codec::encode_message(
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

pub fn generate<W: EventWriter>(
    writer: &mut W,
    input: GenerateMessagesInput,
) -> Result<GenerateMessagesOutput, W::Error> {
    let mut written_events = 0;
    let mut applied_events = 0;
    for idx in 0..input.count {
        let body = format!("{} {idx:06}", input.prefix);
        let bytes = super::codec::encode_message(
            input.workspace_id,
            input.workspace_event_id,
            [0; 32],
            [0; 32],
            &body,
        );
        let written = writer.append_apply(bytes)?;
        match written.status {
            WriteStatus::Applied => {
                written_events += 1;
                applied_events += 1;
            }
            WriteStatus::Blocked { .. } => written_events += 1,
            WriteStatus::AlreadyApplied => {}
        }
    }
    Ok(GenerateMessagesOutput {
        written_events,
        applied_events,
    })
}

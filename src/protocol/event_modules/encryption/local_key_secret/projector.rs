//! Projector for local key-secret events.

use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

use super::super::removal_frontier;
use super::{codec, schema};

pub fn project(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let local = codec::decode(&event.record.canonical_bytes)?;
    if event.record.workspace_id != Some(local.workspace_id) {
        return Err("local key secret workspace metadata does not match event body".to_string());
    }
    let frontier_record = event
        .context
        .dependency(&local.removal_frontier_id)
        .ok_or_else(|| "local key secret removal frontier dependency is missing".to_string())?;
    let frontier_envelope =
        removal_frontier::codec::decode_signed(&frontier_record.canonical_bytes)
            .map_err(|_| "local key secret dependency is not a removal frontier".to_string())?;
    let frontier = removal_frontier::codec::decode(&frontier_envelope.payload)
        .map_err(|_| "local key secret dependency is not a removal frontier".to_string())?;
    if frontier.workspace_id != local.workspace_id {
        return Err("local key secret removal frontier workspace does not match event".to_string());
    }

    Ok(ProjectionOutput::rows(vec![schema::local_key_secret_row(
        event.context.event_id,
        &local,
    )]))
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::types::{event_id, EventId};
    use crate::protocol::event_modules::worker::{
        DependencyContext, EventContext, EventWithContext,
    };

    use super::super::commands;
    use super::*;

    type Record = crate::protocol::event_modules::types::EventRecord;

    fn frontier_record(workspace_id: [u8; 32]) -> (EventId, Record) {
        let record =
            removal_frontier::commands::create(removal_frontier::commands::CreateRemovalFrontier {
                workspace_id,
                created_at_ms: 5,
                authority_admin_id: [3; 32],
                signer_endpoint_shared_id: [4; 32],
                signer_private_key: [9; 32],
                removal_event_ids: Vec::new(),
            })
            .expect("create frontier")
            .events[0]
                .record()
                .clone();
        (event_id(&record.canonical_bytes), record)
    }

    fn event_with_context<'a>(
        record: &'a Record,
        frontier_id: EventId,
        frontier_record: Record,
    ) -> EventWithContext<'a> {
        EventWithContext {
            record,
            context: EventContext {
                event_id: event_id(&record.canonical_bytes),
                dependencies: vec![DependencyContext {
                    event_id: frontier_id,
                    record: frontier_record,
                }],
                labels: Vec::new(),
                receive: None,
            },
        }
    }

    #[test]
    fn projects_local_secret_row_for_frontier() {
        let (frontier_id, frontier_record) = frontier_record([1; 32]);
        let record = commands::from_key_secret([1; 32], frontier_id, [7; 32])
            .expect("create local")
            .events[0]
            .record()
            .clone();
        let event = event_with_context(&record, frontier_id, frontier_record);

        let output = project(&event).expect("project local secret");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::LOCAL_KEY_SECRETS);
        let row = schema::decode_local_key_secret_row(&output.rows[0].key, &output.rows[0].value)
            .expect("decode row");
        assert_eq!(row.workspace_id, [1; 32]);
        assert_eq!(row.removal_frontier_id, frontier_id);
        assert_eq!(row.local_key_secret_id, event.context.event_id);
    }

    #[test]
    fn rejects_frontier_from_other_workspace() {
        let (frontier_id, frontier_record) = frontier_record([2; 32]);
        let record = commands::from_key_secret([1; 32], frontier_id, [7; 32])
            .expect("create local")
            .events[0]
            .record()
            .clone();
        let event = event_with_context(&record, frontier_id, frontier_record);

        assert_eq!(
            project(&event).expect_err("wrong workspace must fail"),
            "local key secret removal frontier workspace does not match event"
        );
    }
}

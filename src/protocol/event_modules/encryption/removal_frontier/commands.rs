//! Commands for removal frontier events.
//!
//! Phase one creates an empty frontier as the first content-key boundary. The
//! wire type already carries sorted removal refs so later removal facts can use
//! the same `removal_frontier_id` vocabulary. Those refs should be a compact
//! removal boundary, not a list of every event that happened before the key was
//! created.

use crate::core::crypto::Ed25519PrivateKey;
use crate::protocol::event_modules::types::{event_id, EventId};
use crate::protocol::event_modules::worker::CommandOutput;

use super::codec;
use super::types::RemovalFrontierEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateRemovalFrontier {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub authority_admin_id: EventId,
    pub signer_endpoint_shared_id: EventId,
    pub signer_private_key: Ed25519PrivateKey,
    pub removal_event_ids: Vec<EventId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateRemovalFrontierOutput {
    pub removal_frontier_id: EventId,
    pub workspace_id: EventId,
    pub authority_admin_id: EventId,
    pub removal_event_ids: Vec<EventId>,
}

pub fn create(
    input: CreateRemovalFrontier,
) -> Result<CommandOutput<CreateRemovalFrontierOutput>, String> {
    validate_id("workspace_id", &input.workspace_id)?;
    validate_id("authority_admin_id", &input.authority_admin_id)?;
    validate_id(
        "signer_endpoint_shared_id",
        &input.signer_endpoint_shared_id,
    )?;
    let event = RemovalFrontierEvent {
        workspace_id: input.workspace_id,
        created_at_ms: input.created_at_ms,
        authority_admin_id: input.authority_admin_id,
        removal_event_ids: input.removal_event_ids,
    };
    let payload = codec::encode(&event)?;
    let envelope = codec::sign(
        input.signer_endpoint_shared_id,
        &input.signer_private_key,
        payload,
    );
    let bytes = codec::encode_signed(&envelope);
    let record = codec::signed_record_from_bytes(bytes)?;
    let value = CreateRemovalFrontierOutput {
        removal_frontier_id: event_id(&record.canonical_bytes),
        workspace_id: event.workspace_id,
        authority_admin_id: event.authority_admin_id,
        removal_event_ids: event.removal_event_ids,
    };
    Ok(CommandOutput::with_events(value, vec![record]))
}

fn validate_id(name: &str, id: &EventId) -> Result<(), String> {
    if id.iter().all(|byte| *byte == 0) {
        return Err(format!("{name} cannot be empty"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::types::EventScope;

    use super::*;

    #[test]
    fn create_proposes_signed_shared_frontier() {
        let output = create(CreateRemovalFrontier {
            workspace_id: [1; 32],
            created_at_ms: 10,
            authority_admin_id: [2; 32],
            signer_endpoint_shared_id: [3; 32],
            signer_private_key: [9; 32],
            removal_event_ids: Vec::new(),
        })
        .expect("create");

        assert_eq!(output.events.len(), 1);
        let record = output.events[0].record();
        assert_eq!(record.scope, EventScope::Shared);
        assert_eq!(record.workspace_id, Some([1; 32]));
        assert_eq!(record.dependencies, vec![[3; 32], [1; 32], [2; 32]]);
        assert_eq!(
            output.value.removal_frontier_id,
            output.events[0].event_id()
        );
    }

    #[test]
    fn create_rejects_empty_workspace() {
        let err = create(CreateRemovalFrontier {
            workspace_id: [0; 32],
            created_at_ms: 10,
            authority_admin_id: [2; 32],
            signer_endpoint_shared_id: [3; 32],
            signer_private_key: [9; 32],
            removal_event_ids: Vec::new(),
        })
        .expect_err("empty workspace must fail");

        assert_eq!(err, "workspace_id cannot be empty");
    }
}

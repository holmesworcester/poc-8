//! Commands for workspace events.
//!
//! This leaf can create the shared workspace root event when the caller already
//! has a real workspace public key. Generating/signing the full creator auth
//! graph belongs to the signed/user/device/admin leaves once those real crypto
//! boundaries exist.

use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::{CommandOutput, ProposedEvent};

use super::codec;
use super::types::{WorkspaceEvent, WorkspacePublicKey};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateWorkspace {
    pub created_at_ms: u64,
    pub public_key: WorkspacePublicKey,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateWorkspaceOutput {
    pub workspace_id: EventId,
}

pub fn create(input: CreateWorkspace) -> Result<CommandOutput<CreateWorkspaceOutput>, String> {
    let event = WorkspaceEvent {
        created_at_ms: input.created_at_ms,
        public_key: input.public_key,
        name: input.name,
    };
    let bytes = codec::encode(&event)?;
    let record = codec::record_from_bytes(bytes)?;
    let proposed = ProposedEvent::new(record);
    let workspace_id = proposed.event_id();

    Ok(CommandOutput::with_proposed_events(
        CreateWorkspaceOutput { workspace_id },
        vec![proposed],
    ))
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::types::event_id;

    use super::*;

    // Invariant: create returns consistent event id and record.
    #[test]
    fn create_returns_consistent_event_id_and_record() {
        let output = create(CreateWorkspace {
            created_at_ms: 77,
            public_key: [5; 32],
            name: "Design".to_string(),
        })
        .expect("create workspace");

        assert_eq!(output.events.len(), 1);
        let proposed = &output.events[0];
        assert_eq!(output.value.workspace_id, proposed.event_id());
        assert_eq!(
            proposed.event_id(),
            event_id(&proposed.record().canonical_bytes)
        );

        let decoded =
            codec::decode(&proposed.record().canonical_bytes).expect("decode proposed workspace");
        assert_eq!(decoded.created_at_ms, 77);
        assert_eq!(decoded.public_key, [5; 32]);
        assert_eq!(decoded.name, "Design");
    }

    // Invariant: create rejects non canonical workspace name.
    #[test]
    fn create_rejects_non_canonical_workspace_name() {
        let err = create(CreateWorkspace {
            created_at_ms: 77,
            public_key: [5; 32],
            name: "bad\0name".to_string(),
        })
        .expect_err("reject NUL name");
        assert!(err.contains("NUL"));
    }
}

//! Commands for signed recipient key tombstones.
//!
//! The command creates one shared retirement fact signed by the endpoint that
//! owns the key being retired. It does not delete private material, derive new
//! keys, or remove already-projected wraps; those are local worker/retention
//! questions after the shared tombstone applies.

use crate::core::crypto::Ed25519PrivateKey;
use crate::protocol::event_modules::types::{event_id, EventId};
use crate::protocol::event_modules::worker::CommandOutput;

use super::{codec, types::RecipientKeyTombstoneEvent};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TombstoneRecipientKey {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub endpoint_shared_id: EventId,
    pub signer_private_key: Ed25519PrivateKey,
    pub old_recipient_key_id: EventId,
    pub new_recipient_key_id: EventId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientKeyTombstoneOutput {
    pub recipient_key_tombstone_id: EventId,
    pub old_recipient_key_id: EventId,
    pub new_recipient_key_id: EventId,
}

pub fn tombstone(
    input: TombstoneRecipientKey,
) -> Result<CommandOutput<RecipientKeyTombstoneOutput>, String> {
    validate_id("workspace_id", &input.workspace_id)?;
    validate_id("endpoint_shared_id", &input.endpoint_shared_id)?;
    validate_id("old_recipient_key_id", &input.old_recipient_key_id)?;
    validate_id("new_recipient_key_id", &input.new_recipient_key_id)?;
    if input.old_recipient_key_id == input.new_recipient_key_id {
        return Err("recipient key tombstone must name different keys".to_string());
    }

    let event = RecipientKeyTombstoneEvent {
        workspace_id: input.workspace_id,
        created_at_ms: input.created_at_ms,
        endpoint_shared_id: input.endpoint_shared_id,
        old_recipient_key_id: input.old_recipient_key_id,
        new_recipient_key_id: input.new_recipient_key_id,
    };
    let payload = codec::encode(&event);
    let envelope = codec::sign(input.endpoint_shared_id, &input.signer_private_key, payload);
    let bytes = codec::encode_signed(&envelope);
    let record = codec::signed_record_from_bytes(bytes)?;
    let value = RecipientKeyTombstoneOutput {
        recipient_key_tombstone_id: event_id(&record.canonical_bytes),
        old_recipient_key_id: event.old_recipient_key_id,
        new_recipient_key_id: event.new_recipient_key_id,
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
    fn tombstone_proposes_signed_shared_event_depending_on_old_and_new_keys() {
        let output = tombstone(TombstoneRecipientKey {
            workspace_id: [1; 32],
            created_at_ms: 10,
            endpoint_shared_id: [2; 32],
            signer_private_key: [7; 32],
            old_recipient_key_id: [3; 32],
            new_recipient_key_id: [4; 32],
        })
        .expect("tombstone");

        let record = output.events[0].record();
        assert_eq!(record.scope, EventScope::Shared);
        assert_eq!(record.workspace_id, Some([1; 32]));
        assert_eq!(
            record.dependencies,
            vec![[2; 32], [1; 32], [3; 32], [4; 32]]
        );
        assert_eq!(
            output.value.recipient_key_tombstone_id,
            output.events[0].event_id()
        );
    }

    #[test]
    fn tombstone_rejects_empty_or_same_key_ids() {
        let mut input = TombstoneRecipientKey {
            workspace_id: [1; 32],
            created_at_ms: 10,
            endpoint_shared_id: [2; 32],
            signer_private_key: [7; 32],
            old_recipient_key_id: [3; 32],
            new_recipient_key_id: [3; 32],
        };
        assert_eq!(
            tombstone(input.clone()).expect_err("same key must fail"),
            "recipient key tombstone must name different keys"
        );
        input.new_recipient_key_id = [0; 32];
        assert_eq!(
            tombstone(input).expect_err("empty key must fail"),
            "new_recipient_key_id cannot be empty"
        );
    }
}

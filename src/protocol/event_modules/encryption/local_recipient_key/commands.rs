//! Commands for local recipient keys.
//!
//! Creation uses OS randomness through core crypto and returns one local-only
//! event. The command does not publish the public key; shared recipient-key
//! authorization will be a separate event type.

use crate::core::crypto;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::CommandOutput;

use super::codec;
use super::types::LocalRecipientKey;

pub fn create(workspace_id: EventId) -> Result<CommandOutput<LocalRecipientKey>, String> {
    if workspace_id.iter().all(|byte| *byte == 0) {
        return Err("local recipient key workspace cannot be empty".to_string());
    }
    let recipient_secret = crypto::random_x25519_private_key();
    let event = LocalRecipientKey {
        workspace_id,
        recipient_key: crypto::x25519_public_key(&recipient_secret),
        recipient_secret,
    };
    let bytes = codec::encode(&event);
    Ok(CommandOutput::with_events(
        event.clone(),
        vec![codec::record_from_bytes(bytes).expect("encoded local recipient key is valid")],
    ))
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::types::EventScope;

    use super::*;

    #[test]
    fn create_proposes_local_only_matching_key_event() {
        let output = create([1; 32]).expect("create");

        assert_eq!(output.events.len(), 1);
        let record = output.events[0].record();
        assert_eq!(record.scope, EventScope::Local);
        assert!(!record.scope.is_shared());
        assert_eq!(record.workspace_id, Some([1; 32]));

        let decoded = codec::decode(&record.canonical_bytes).expect("decode");
        assert_eq!(decoded, output.value);
        assert_eq!(
            crypto::x25519_public_key(&decoded.recipient_secret),
            decoded.recipient_key
        );
    }

    #[test]
    fn create_rejects_empty_workspace_without_panicking() {
        let err = create([0; 32]).expect_err("empty workspace must fail");

        assert_eq!(err, "local recipient key workspace cannot be empty");
    }
}

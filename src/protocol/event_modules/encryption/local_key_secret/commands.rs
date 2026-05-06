//! Commands for local key-secret events.
//!
//! Commands either mint fresh local content-key material or wrap caller-supplied
//! material into the same event shape. They return proposed local events and do
//! not write secret rows themselves, which keeps key creation inside the common
//! dependency/admission path.

use crate::core::crypto;
use crate::protocol::event_modules::types::{event_id, EventId};
use crate::protocol::event_modules::worker::CommandOutput;

use super::codec;
use super::types::{KeySecret, LocalKeySecret};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalKeySecretOutput {
    pub local_key_secret_id: EventId,
    pub event: LocalKeySecret,
}

pub fn create(
    workspace_id: EventId,
    removal_frontier_id: EventId,
) -> Result<CommandOutput<LocalKeySecretOutput>, String> {
    from_key_secret(
        workspace_id,
        removal_frontier_id,
        crypto::random_xchacha20poly1305_key(),
    )
}

pub fn from_key_secret(
    workspace_id: EventId,
    removal_frontier_id: EventId,
    key_secret: KeySecret,
) -> Result<CommandOutput<LocalKeySecretOutput>, String> {
    validate_id("workspace_id", &workspace_id)?;
    validate_id("removal_frontier_id", &removal_frontier_id)?;
    validate_id("key_secret", &key_secret)?;
    let event = LocalKeySecret {
        workspace_id,
        removal_frontier_id,
        key_secret,
    };
    let bytes = codec::encode(&event);
    let record = codec::record_from_bytes(bytes)?;
    let value = LocalKeySecretOutput {
        local_key_secret_id: event_id(&record.canonical_bytes),
        event,
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
    fn create_proposes_local_only_secret_for_frontier() {
        let output = create([1; 32], [2; 32]).expect("create");

        assert_eq!(output.events.len(), 1);
        let record = output.events[0].record();
        assert_eq!(record.scope, EventScope::Local);
        assert_eq!(record.workspace_id, Some([1; 32]));
        assert_eq!(record.dependencies, vec![[2; 32]]);
        assert_eq!(
            output.value.local_key_secret_id,
            output.events[0].event_id()
        );
    }

    #[test]
    fn from_key_secret_is_deterministic_for_same_frontier_and_secret() {
        let key_secret = [7; 32];
        let left = from_key_secret([1; 32], [2; 32], key_secret)
            .expect("left")
            .value
            .local_key_secret_id;
        let right = from_key_secret([1; 32], [2; 32], key_secret)
            .expect("right")
            .value
            .local_key_secret_id;

        assert_eq!(left, right);
    }
}

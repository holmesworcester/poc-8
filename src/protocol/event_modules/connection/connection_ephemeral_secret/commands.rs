//! Constructors for local connection-handshake ephemeral secret events.

use crate::core::crypto;
use crate::protocol::event_modules::identity::endpoint::types::EndpointId;
use crate::protocol::event_modules::worker::CommandOutput;

use super::codec;
use super::types::EphemeralSecretEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateEphemeral {
    pub owner_endpoint: EndpointId,
    pub created_at_ms: u64,
}

pub fn create(input: CreateEphemeral) -> Result<CommandOutput<EphemeralSecretEvent>, String> {
    let ephemeral_private_key = crypto::random_x25519_private_key();
    let event = EphemeralSecretEvent {
        owner_endpoint: input.owner_endpoint,
        ephemeral_private_key,
        ephemeral_public_key: crypto::x25519_public_key(&ephemeral_private_key),
        created_at_ms: input.created_at_ms,
    };
    Ok(CommandOutput::with_events(
        event,
        vec![codec::record_from_bytes(codec::encode(&event))?],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_records_matching_public_key() {
        let output = create(CreateEphemeral {
            owner_endpoint: [1; 32],
            created_at_ms: 9,
        })
        .expect("create ephemeral");

        assert_eq!(output.events.len(), 1);
        assert_eq!(
            output.value.ephemeral_public_key,
            crypto::x25519_public_key(&output.value.ephemeral_private_key)
        );
    }
}

//! Connection-handshake ephemeral key event fields.

use crate::core::crypto::{X25519PrivateKey, X25519PublicKey};
use crate::protocol::event_modules::identity::endpoint::types::EndpointId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EphemeralSecretEvent {
    pub owner_endpoint: EndpointId,
    pub ephemeral_private_key: X25519PrivateKey,
    pub ephemeral_public_key: X25519PublicKey,
    pub created_at_ms: u64,
}

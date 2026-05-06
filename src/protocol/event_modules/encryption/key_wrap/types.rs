//! Key-wrap event types.
//!
//! A key wrap is a shared fact for one recipient key and one removal frontier.
//! It carries sealed key-secret bytes plus the event id the receiver must
//! recreate as a local key-secret event after opening the wrap.

use crate::core::crypto::{
    Ed25519PublicKey, Ed25519Signature, X25519PublicKey, XChaCha20Poly1305Nonce,
};
use crate::protocol::event_modules::types::EventId;

pub const KEY_WRAP_CIPHERTEXT_BYTES: usize = 48;
pub type KeyWrapCiphertext = [u8; KEY_WRAP_CIPHERTEXT_BYTES];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyWrapEvent {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub removal_frontier_id: EventId,
    pub local_key_secret_id: EventId,
    pub recipient_key_id: EventId,
    pub sender_wrap_public_key: X25519PublicKey,
    pub nonce: XChaCha20Poly1305Nonce,
    pub ciphertext: KeyWrapCiphertext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedKeyWrapEnvelope {
    pub signer_endpoint_shared_id: EventId,
    pub signer_public_key: Ed25519PublicKey,
    pub payload: Vec<u8>,
    pub signature: Ed25519Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyWrapRow {
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    pub recipient_key_id: EventId,
    pub key_wrap_id: EventId,
    pub created_at_ms: u64,
    pub signer_endpoint_shared_id: EventId,
    pub signer_public_key: Ed25519PublicKey,
    pub local_key_secret_id: EventId,
    pub sender_wrap_public_key: X25519PublicKey,
    pub nonce: XChaCha20Poly1305Nonce,
    pub ciphertext: KeyWrapCiphertext,
}

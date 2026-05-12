//! Transit wrap commands.
//!
//! This is the active boundary between connection state and network bytes. It
//! accepts explicit endpoint keys and connection context, then returns opaque
//! transit bytes. It does not admit events or mutate schema; event admission and
//! transit out decide what to do with the result.

use crate::protocol::event_modules::identity::endpoint::types::EndpointId;
use crate::protocol::event_modules::identity::endpoint::types::EndpointKeypair;

use crate::core::crypto;
use crate::protocol::event_modules::types::EventId;

use super::super::types::ConnectionId;
use super::codec;
use super::types::{TransitEnvelope, BOOTSTRAP_PURPOSE, CONNECTION_PURPOSE};

pub fn create_bootstrap(
    local: &EndpointKeypair,
    recipient_endpoint: EndpointId,
    inner: &[u8],
) -> Result<Vec<u8>, String> {
    // Bootstrap frames are addressed directly to an endpoint because a
    // connection id does not exist yet.
    let nonce = crypto::random_xchacha20poly1305_nonce();
    let envelope = TransitEnvelope::Bootstrap {
        sender_endpoint: local.endpoint,
        recipient_endpoint,
        nonce,
        ciphertext: Vec::new(),
    };
    let ciphertext = crypto::x25519_xchacha20poly1305_encrypt(
        &local.secret,
        &recipient_endpoint,
        BOOTSTRAP_PURPOSE,
        &codec::associated_data(&envelope),
        &nonce,
        inner,
    )?;
    Ok(codec::encode(&TransitEnvelope::Bootstrap {
        sender_endpoint: local.endpoint,
        recipient_endpoint,
        nonce,
        ciphertext,
    }))
}

pub fn create_connection_batch(
    sender_endpoint: EndpointId,
    recipient_endpoint: EndpointId,
    connection_id: ConnectionId,
    connection_secret: &[u8; 32],
    inners: Vec<Vec<u8>>,
) -> Result<Vec<u8>, String> {
    // Ordinary frames bind sender, recipient, and connection id into the
    // authenticated envelope before encrypting the inner event bytes. The
    // plaintext is a small fixed-format list so one transit envelope can carry a
    // coherent batch of canonical events without making TCP understand them.
    let nonce = crypto::random_xchacha20poly1305_nonce();
    let envelope = TransitEnvelope::Connection {
        connection_id,
        sender_endpoint,
        recipient_endpoint,
        nonce,
        ciphertext: Vec::new(),
    };
    let plaintext = codec::encode_inner_events(&inners)?;
    let associated_data = codec::associated_data(&envelope);
    let key = crypto::hkdf_sha256_key(connection_secret, CONNECTION_PURPOSE, &associated_data)?;
    let ciphertext = crypto::xchacha20poly1305_encrypt(&key, &associated_data, &nonce, &plaintext)?;
    Ok(codec::encode(&TransitEnvelope::Connection {
        connection_id,
        sender_endpoint,
        recipient_endpoint,
        nonce,
        ciphertext,
    }))
}

pub(crate) fn create_connection_handshake_response(
    sender_endpoint: EndpointId,
    recipient_endpoint: EndpointId,
    request_id: EventId,
    responder_ephemeral_public_key: EndpointId,
    response_key: &[u8; 32],
    connection_event_bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let nonce = crypto::random_xchacha20poly1305_nonce();
    let envelope = TransitEnvelope::ConnectionHandshakeResponse {
        request_id,
        sender_endpoint,
        recipient_endpoint,
        responder_ephemeral_public_key,
        nonce,
        ciphertext: Vec::new(),
    };
    let associated_data = codec::associated_data(&envelope);
    let ciphertext = crypto::xchacha20poly1305_encrypt(
        response_key,
        &associated_data,
        &nonce,
        connection_event_bytes,
    )?;
    Ok(codec::encode(
        &TransitEnvelope::ConnectionHandshakeResponse {
            request_id,
            sender_endpoint,
            recipient_endpoint,
            responder_ephemeral_public_key,
            nonce,
            ciphertext,
        },
    ))
}

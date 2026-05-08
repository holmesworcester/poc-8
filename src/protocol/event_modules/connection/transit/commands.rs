//! Transit wrap commands.
//!
//! This is the active boundary between connection state and network bytes. It
//! accepts explicit endpoint keys and connection context, then returns opaque
//! transit bytes. It does not admit events or mutate schema; event admission and
//! transit out decide what to do with the result.

use crate::protocol::event_modules::identity::endpoint::types::EndpointId;
use crate::protocol::event_modules::identity::endpoint::types::EndpointKeypair;

use crate::core::crypto;
use crate::protocol::event_modules::connection::connection_response;
use crate::protocol::event_modules::identity::invite;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::Writer;

use super::super::types::ConnectionId;
use super::codec;
use super::types::{TransitEnvelope, BOOTSTRAP_PURPOSE, INVITE_BOOTSTRAP_PURPOSE};

const TRAFFIC_KEY_PURPOSE: &[u8] = b"topo-connection-traffic-key-v1";
const INITIATOR_TO_RESPONDER: &[u8] = b"initiator->responder";
const RESPONDER_TO_INITIATOR: &[u8] = b"responder->initiator";

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

pub fn create_invite_bootstrap_batch(
    local: &EndpointKeypair,
    recipient_endpoint: EndpointId,
    bootstrap_secret: &[u8; 32],
    workspace_id: EventId,
    invite_event_id: EventId,
    inners: Vec<Vec<u8>>,
) -> Result<Vec<u8>, String> {
    // Invite bootstrap is deliberately not an endpoint X25519 handshake. The
    // copied invite secret is the authority, and the envelope binds it to one
    // workspace/invite pair before any inner canonical bytes are admitted.
    let bootstrap_hash = invite::types::bootstrap_secret_hash(bootstrap_secret);
    let nonce = crypto::random_xchacha20poly1305_nonce();
    let envelope = TransitEnvelope::InviteBootstrap {
        sender_endpoint: local.endpoint,
        recipient_endpoint,
        bootstrap_hash,
        workspace_id,
        invite_event_id,
        nonce,
        ciphertext: Vec::new(),
    };
    let associated_data = codec::associated_data(&envelope);
    let key =
        crypto::hkdf_sha256_key(bootstrap_secret, INVITE_BOOTSTRAP_PURPOSE, &associated_data)?;
    let plaintext = codec::encode_inner_events(&inners)?;
    let ciphertext = crypto::xchacha20poly1305_encrypt(&key, &associated_data, &nonce, &plaintext)?;
    Ok(codec::encode(&TransitEnvelope::InviteBootstrap {
        sender_endpoint: local.endpoint,
        recipient_endpoint,
        bootstrap_hash,
        workspace_id,
        invite_event_id,
        nonce,
        ciphertext,
    }))
}

pub fn create_connection_batch(
    local_endpoint: EndpointId,
    connection: &connection_response::types::ResponseEvent,
    connection_id: ConnectionId,
    inners: Vec<Vec<u8>>,
) -> Result<Vec<u8>, String> {
    // Ordinary frames bind sender, recipient, and connection id into the
    // authenticated envelope before encrypting the inner event bytes. The
    // plaintext is a small fixed-format list so one transit envelope can carry a
    // coherent batch of canonical events without making TCP understand them.
    let recipient_endpoint = recipient_endpoint_for_sender(connection, local_endpoint)?;
    let nonce = crypto::random_xchacha20poly1305_nonce();
    let envelope = TransitEnvelope::Connection {
        connection_id,
        sender_endpoint: local_endpoint,
        recipient_endpoint,
        nonce,
        ciphertext: Vec::new(),
    };
    let plaintext = codec::encode_inner_events(&inners)?;
    let associated_data = codec::associated_data(&envelope);
    let key = derive_directional_key(
        connection,
        connection_id,
        local_endpoint,
        recipient_endpoint,
    )?;
    let ciphertext = crypto::xchacha20poly1305_encrypt(&key, &associated_data, &nonce, &plaintext)?;
    Ok(codec::encode(&TransitEnvelope::Connection {
        connection_id,
        sender_endpoint: local_endpoint,
        recipient_endpoint,
        nonce,
        ciphertext,
    }))
}

fn recipient_endpoint_for_sender(
    event: &connection_response::types::ResponseEvent,
    sender_endpoint: EndpointId,
) -> Result<EndpointId, String> {
    if sender_endpoint == event.from_endpoint {
        return Ok(event.to_endpoint);
    }
    if sender_endpoint == event.to_endpoint {
        return Ok(event.from_endpoint);
    }
    Err("connection transit sender is not part of connection".to_string())
}

fn derive_directional_key(
    event: &connection_response::types::ResponseEvent,
    connection_id: ConnectionId,
    sender_endpoint: EndpointId,
    recipient_endpoint: EndpointId,
) -> Result<crypto::XChaCha20Poly1305Key, String> {
    let direction = if sender_endpoint == event.to_endpoint
        && recipient_endpoint == event.from_endpoint
    {
        INITIATOR_TO_RESPONDER
    } else if sender_endpoint == event.from_endpoint && recipient_endpoint == event.to_endpoint {
        RESPONDER_TO_INITIATOR
    } else {
        return Err("connection transit direction does not match connection".to_string());
    };

    let mut info = Writer::with_capacity(32 * 4 + direction.len());
    info.id(&connection_id);
    info.id(&event.request_id);
    info.id(&event.to_endpoint);
    info.id(&event.from_endpoint);
    info.raw(direction);
    crypto::hkdf_sha256_key(&event.traffic_secret, TRAFFIC_KEY_PURPOSE, &info.finish())
}

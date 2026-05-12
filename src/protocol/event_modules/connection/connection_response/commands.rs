//! Commands and validation helpers for completing a connection handshake.
//!
//! The worker decides when a response should be sent and supplies explicit
//! dependency context. This module owns the canonical response event
//! construction and the native Noise-like key schedule:
//!
//! ```text
//! invite secret
//!   + request transcript
//!   + DH(initiator_eph, responder_eph)
//!   + DH(initiator_eph, responder_static)
//!   -> response encryption key
//!   -> connection secret stored in the response event
//! ```
//!
//! The command deliberately does not read or write storage. The response event
//! is admitted through the common event pipeline, and the transit frame is only
//! the encrypted carrier that gets the response bytes back to the requester.

use crate::core::crypto::{self, XChaCha20Poly1305Key, XChaCha20Poly1305Nonce};
use crate::protocol::event_modules::connection::connection_ephemeral_secret;
use crate::protocol::event_modules::connection::connection_request;
use crate::protocol::event_modules::connection::transit;
use crate::protocol::event_modules::connection::types;
use crate::protocol::event_modules::identity::{endpoint, invite};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::CommandOutput;
use crate::protocol::wire::Writer;

use super::codec;
use super::types::ResponseEvent;

const HANDSHAKE_PURPOSE: &[u8] = b"topo-connection-handshake-v1";
const CONNECTION_SECRET_PURPOSE: &[u8] = b"topo-connection-secret-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundResponse {
    pub bytes: Vec<u8>,
    pub connection_id: types::ConnectionId,
    pub request_id: EventId,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CreateForRequest<'a> {
    pub local: endpoint::types::EndpointKeypair,
    pub request_id: EventId,
    pub request: &'a connection_request::types::RequestEvent,
    pub invite_secret: &'a invite::types::InviteSecretEvent,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DecryptHandshakeResponse<'a> {
    pub request_id: EventId,
    pub request: &'a connection_request::types::RequestEvent,
    pub invite_secret: &'a invite::types::InviteSecretEvent,
    pub initiator_ephemeral: &'a connection_ephemeral_secret::types::EphemeralSecretEvent,
    pub responder_ephemeral_public_key: EventId,
    pub associated_data: &'a [u8],
    pub nonce: &'a XChaCha20Poly1305Nonce,
    pub ciphertext: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HandshakeMaterial {
    pub response_key: XChaCha20Poly1305Key,
    pub handshake_hash: EventId,
    pub connection_secret: EventId,
}

pub(crate) fn create_for_request(
    input: CreateForRequest<'_>,
) -> Result<CommandOutput<OutboundResponse>, String> {
    if input.request.to_endpoint != input.local.endpoint {
        return Err("connection request is addressed to another endpoint".to_string());
    }
    let responder_ephemeral = connection_ephemeral_secret::commands::create(
        connection_ephemeral_secret::commands::CreateEphemeral {
            owner_endpoint: input.local.endpoint,
            created_at_ms: 0,
        },
    )?;
    let responder_ephemeral_event_id = responder_ephemeral.events[0].event_id();
    let material = responder_material(
        input.request_id,
        input.request,
        input.invite_secret,
        &input.local.secret,
        &responder_ephemeral.value.ephemeral_private_key,
        &responder_ephemeral.value.ephemeral_public_key,
    )?;
    let event = ResponseEvent {
        from_endpoint: input.local.endpoint,
        to_endpoint: input.request.from_endpoint,
        request_id: input.request_id,
        invite_secret_event_id: input.request.invite_secret_event_id,
        initiator_ephemeral_secret_event_id: input.request.initiator_ephemeral_secret_event_id,
        responder_ephemeral_secret_event_id: responder_ephemeral_event_id,
        responder_ephemeral_public_key: responder_ephemeral.value.ephemeral_public_key,
        handshake_hash: material.handshake_hash,
        connection_secret: material.connection_secret,
    };
    let response_bytes = codec::encode(&event);
    let connection_id = types::event_id(&response_bytes);
    let response_record = codec::record_from_bytes(response_bytes.clone())?;
    let response_frame = transit::commands::create_connection_handshake_response(
        input.local.endpoint,
        input.request.from_endpoint,
        input.request_id,
        responder_ephemeral.value.ephemeral_public_key,
        &material.response_key,
        &response_bytes,
    )?;
    let mut events = responder_ephemeral
        .events
        .into_iter()
        .map(|event| event.into_record())
        .collect::<Vec<_>>();
    events.push(response_record);
    Ok(CommandOutput::with_events(
        OutboundResponse {
            bytes: response_frame,
            connection_id,
            request_id: input.request_id,
        },
        events,
    ))
}

pub(crate) fn decrypt_handshake_response(
    input: DecryptHandshakeResponse<'_>,
) -> Result<Vec<u8>, String> {
    let material = initiator_material(
        input.request_id,
        input.request,
        input.invite_secret,
        input.initiator_ephemeral,
        &input.responder_ephemeral_public_key,
    )?;
    let plaintext = crypto::xchacha20poly1305_decrypt(
        &material.response_key,
        input.associated_data,
        input.nonce,
        input.ciphertext,
    )?;
    validate_decrypted_response(input.request_id, input.request, &material, &plaintext)?;
    Ok(plaintext)
}

pub(crate) fn initiator_material(
    request_id: EventId,
    request: &connection_request::types::RequestEvent,
    invite_secret: &invite::types::InviteSecretEvent,
    initiator_ephemeral: &connection_ephemeral_secret::types::EphemeralSecretEvent,
    responder_ephemeral_public_key: &EventId,
) -> Result<HandshakeMaterial, String> {
    if initiator_ephemeral.owner_endpoint != request.from_endpoint {
        return Err("initiator ephemeral owner does not match request".to_string());
    }
    if initiator_ephemeral.ephemeral_public_key != request.initiator_ephemeral_public_key {
        return Err("initiator ephemeral public key does not match request".to_string());
    }
    let ee = crypto::x25519_diffie_hellman(
        &initiator_ephemeral.ephemeral_private_key,
        responder_ephemeral_public_key,
    );
    let es = crypto::x25519_diffie_hellman(
        &initiator_ephemeral.ephemeral_private_key,
        &request.to_endpoint,
    );
    material(
        request_id,
        request,
        invite_secret,
        responder_ephemeral_public_key,
        ee,
        es,
    )
}

pub(crate) fn responder_material(
    request_id: EventId,
    request: &connection_request::types::RequestEvent,
    invite_secret: &invite::types::InviteSecretEvent,
    responder_static_secret: &crypto::X25519PrivateKey,
    responder_ephemeral_secret: &crypto::X25519PrivateKey,
    responder_ephemeral_public_key: &EventId,
) -> Result<HandshakeMaterial, String> {
    let ee = crypto::x25519_diffie_hellman(
        responder_ephemeral_secret,
        &request.initiator_ephemeral_public_key,
    );
    let es = crypto::x25519_diffie_hellman(
        responder_static_secret,
        &request.initiator_ephemeral_public_key,
    );
    material(
        request_id,
        request,
        invite_secret,
        responder_ephemeral_public_key,
        ee,
        es,
    )
}

pub(crate) fn public_handshake_hash(
    request_id: EventId,
    request: &connection_request::types::RequestEvent,
    responder_ephemeral_public_key: &EventId,
) -> EventId {
    crypto::hash(&public_transcript(
        request_id,
        request,
        responder_ephemeral_public_key,
    ))
}

fn material(
    request_id: EventId,
    request: &connection_request::types::RequestEvent,
    invite_secret: &invite::types::InviteSecretEvent,
    responder_ephemeral_public_key: &EventId,
    ee: [u8; 32],
    es: [u8; 32],
) -> Result<HandshakeMaterial, String> {
    if invite_secret.bootstrap_hash != request.bootstrap_hash {
        return Err("connection handshake invite secret does not match request".to_string());
    }
    let transcript = public_transcript(request_id, request, responder_ephemeral_public_key);
    let mut ikm = Vec::with_capacity(32 * 4);
    ikm.extend_from_slice(&invite_secret.bootstrap_secret);
    ikm.extend_from_slice(&ee);
    ikm.extend_from_slice(&es);
    ikm.extend_from_slice(&request.bootstrap_hash);
    let response_key = crypto::hkdf_sha256_key(&ikm, HANDSHAKE_PURPOSE, &transcript)?;
    let handshake_hash = crypto::hash(&transcript);
    let connection_secret =
        crypto::hkdf_sha256_key(&response_key, CONNECTION_SECRET_PURPOSE, &handshake_hash)?;
    Ok(HandshakeMaterial {
        response_key,
        handshake_hash,
        connection_secret,
    })
}

fn public_transcript(
    request_id: EventId,
    request: &connection_request::types::RequestEvent,
    responder_ephemeral_public_key: &EventId,
) -> Vec<u8> {
    let mut out = Writer::new();
    out.raw(b"topo-native-connection-handshake-v1");
    out.id(&request_id);
    out.id(&request.from_endpoint);
    out.id(&request.to_endpoint);
    out.id(&request.nonce);
    out.id(&request.invite_event_id);
    out.id(&request.bootstrap_hash);
    out.raw(&request.invite_signature);
    out.id(&request.invite_secret_event_id);
    out.id(&request.initiator_ephemeral_secret_event_id);
    out.id(&request.initiator_ephemeral_public_key);
    out.id(responder_ephemeral_public_key);
    out.finish()
}

fn validate_decrypted_response(
    request_id: EventId,
    request: &connection_request::types::RequestEvent,
    material: &HandshakeMaterial,
    plaintext: &[u8],
) -> Result<(), String> {
    let response = codec::decode(plaintext)?;
    if response.request_id != request_id {
        return Err("connection response answers another request".to_string());
    }
    if response.from_endpoint != request.to_endpoint
        || response.to_endpoint != request.from_endpoint
    {
        return Err("connection response endpoint direction does not match request".to_string());
    }
    if response.invite_secret_event_id != request.invite_secret_event_id
        || response.initiator_ephemeral_secret_event_id
            != request.initiator_ephemeral_secret_event_id
    {
        return Err("connection response copied request dependencies incorrectly".to_string());
    }
    if response.handshake_hash != material.handshake_hash {
        return Err("connection response handshake hash does not match transcript".to_string());
    }
    if response.connection_secret != material.connection_secret {
        return Err("connection response secret does not match handshake".to_string());
    }
    Ok(())
}

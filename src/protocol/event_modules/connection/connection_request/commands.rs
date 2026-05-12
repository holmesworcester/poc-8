//! Commands for initiating connection requests.
//!
//! This module is the active boundary that turns a human-copyable invite link
//! into local facts:
//!
//! ```text
//! invite link + local endpoint
//!   -> local invite-secret fact
//!   -> local connection-request fact depending on that secret
//! ```
//!
//! The command deliberately does not write rows, open sockets, run projectors,
//! or decide whether the remote side should accept the request. Those decisions
//! belong to the common event pipeline and the request projector. This command
//! only creates the facts and returns the request id and invite route a caller
//! can hand to `transit_out`.
//!
//! Invariants:
//!
//! - The request's `invite_secret_event_id` is the deterministic id of the
//!   local invite-secret fact proposed immediately before it.
//! - Bootstrap authorization is carried by the request dependency edge plus a
//!   transcript-bound signature by the invite private key. The secret itself
//!   never appears in the request or transit frame.
//! - The returned request id lets the caller correlate the later encrypted
//!   connection response. That response event id becomes the connection id.

use std::net::SocketAddr;

use crate::core::crypto;
use crate::protocol::event_modules::connection::connection_ephemeral_secret;
use crate::protocol::event_modules::identity::{endpoint, invite};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::CommandOutput;
use crate::protocol::wire::Writer;

use super::super::types;
use super::codec;
use super::types::RequestEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundRequest {
    /// Deterministic id of the connection request event.
    pub request_id: EventId,
    /// Socket address advertised by the invite link.
    pub addr: std::net::SocketAddr,
}

/// Create a connection request from an explicit local endpoint and invite link.
///
/// This function is intentionally pure with respect to storage. It parses the
/// invite, builds the local invite-secret event and the dependent request
/// event, and returns them as `CommandOutput`. The caller must admit the
/// proposed events before treating the request as local fact graph state.
pub fn create(
    local: endpoint::types::EndpointKeypair,
    invite_link: &str,
    from_listen_addr: Option<SocketAddr>,
) -> Result<CommandOutput<OutboundRequest>, String> {
    // The invite link gives this endpoint local bootstrap authority. Propose
    // that local fact first, then make the request depend on it explicitly.
    let invite = invite::commands::parse(invite_link)?;
    let invite_secret = if invite.identity_scope {
        invite::types::InviteSecretEvent::scoped_with_addr(
            invite.bootstrap_secret,
            invite.workspace_id,
            invite.invite_event_id,
            invite.addr,
        )
    } else {
        invite::types::InviteSecretEvent::new_with_addr(invite.bootstrap_secret, invite.addr)
    };
    let invite_secret_bytes = invite::codec::encode(&invite_secret);
    let invite_secret_event_id = types::event_id(&invite_secret_bytes);
    let invite_secret_record = invite::codec::record_from_bytes(invite_secret_bytes)?;
    let ephemeral = connection_ephemeral_secret::commands::create(
        connection_ephemeral_secret::commands::CreateEphemeral {
            owner_endpoint: local.endpoint,
            created_at_ms: 0,
        },
    )?;
    let ephemeral_event_id = ephemeral.events[0].event_id();
    let event = sign_with_invite(
        RequestEvent {
            from_endpoint: local.endpoint,
            to_endpoint: invite.endpoint,
            nonce: nonce32(),
            invite_event_id: invite.invite_event_id,
            bootstrap_hash: invite_secret.bootstrap_hash,
            invite_signature: [0; crypto::ED25519_SIGNATURE_BYTES],
            invite_secret_event_id,
            initiator_ephemeral_secret_event_id: ephemeral_event_id,
            initiator_ephemeral_public_key: ephemeral.value.ephemeral_public_key,
            from_listen_addr,
        },
        &invite_secret,
    )?;
    let inner = codec::encode(&event);
    let request_id = types::event_id(&inner);
    let record = codec::record_from_bytes(inner.clone())?;
    let mut events = vec![invite_secret_record];
    events.extend(
        ephemeral
            .events
            .into_iter()
            .map(|event| event.into_record()),
    );
    events.push(record);
    Ok(CommandOutput::with_events(
        OutboundRequest {
            request_id,
            addr: invite.addr,
        },
        events,
    ))
}

/// Create a request, creating or loading the local endpoint as explicit context.
///
/// Endpoint creation remains a command-produced fact as well: if no local
/// endpoint exists, the endpoint command's proposed local event is prepended so
/// admission sees the endpoint material before the request uses it.
///
/// `from_listen_addr` is the local steady-state listener advertised inside the
/// request body. Callers read it from `connection::schema::local_listen_addr`
/// before invoking this command; passing `None` keeps the request asymmetric
/// and still bootstraps correctly when no daemon is running.
pub fn create_with_local(
    context: &impl endpoint::commands::LocalEndpointRead,
    invite_link: &str,
    from_listen_addr: Option<SocketAddr>,
) -> Result<CommandOutput<OutboundRequest>, String> {
    let local = endpoint::commands::local_or_create(context)?;
    Ok(create(local.value, invite_link, from_listen_addr)?.prepend_events(local.events))
}

/// Generate the request nonce that separates repeated requests to the same
/// invite endpoint.
fn nonce32() -> [u8; 32] {
    crypto::random_bytes_32()
}

pub(crate) fn sign_with_invite(
    mut event: RequestEvent,
    invite_secret: &invite::types::InviteSecretEvent,
) -> Result<RequestEvent, String> {
    validate_invite_context(&event, invite_secret)?;
    event.invite_signature = crypto::ed25519_sign(
        &invite_secret.bootstrap_secret,
        &invite_signing_transcript(&event),
    );
    Ok(event)
}

pub(crate) fn validate_invite_signature(
    event: &RequestEvent,
    invite_secret: &invite::types::InviteSecretEvent,
) -> Result<(), String> {
    validate_invite_context(event, invite_secret)?;
    let public_key = crypto::ed25519_public_key(&invite_secret.bootstrap_secret);
    if !crypto::ed25519_verify(
        &public_key,
        &invite_signing_transcript(event),
        &event.invite_signature,
    ) {
        return Err("connection request invite signature is not authorized".to_string());
    }
    Ok(())
}

fn validate_invite_context(
    event: &RequestEvent,
    invite_secret: &invite::types::InviteSecretEvent,
) -> Result<(), String> {
    if invite_secret.bootstrap_hash != event.bootstrap_hash {
        return Err("connection request bootstrap hash is not authorized".to_string());
    }
    if let Some(invite_event_id) = invite_secret.invite_event_id {
        if invite_event_id != event.invite_event_id {
            return Err("connection request invite id is not authorized".to_string());
        }
    }
    Ok(())
}

fn invite_signing_transcript(event: &RequestEvent) -> Vec<u8> {
    let mut out = Writer::new();
    out.raw(b"topo-connection-request-invite-signing-transcript-v1");
    out.id(&event.from_endpoint);
    out.id(&event.to_endpoint);
    out.id(&event.nonce);
    out.id(&event.invite_event_id);
    out.id(&event.bootstrap_hash);
    out.id(&event.invite_secret_event_id);
    out.id(&event.initiator_ephemeral_secret_event_id);
    out.id(&event.initiator_ephemeral_public_key);
    match event.from_listen_addr {
        None => {
            out.u8(0);
            out.raw(&[0u8; 16]);
            out.u16(0);
        }
        Some(addr) => {
            encode_socket_addr(&mut out, addr);
        }
    }
    out.finish()
}

fn encode_socket_addr(out: &mut Writer, addr: SocketAddr) {
    match addr.ip() {
        std::net::IpAddr::V4(ip) => {
            out.u8(4);
            let mut padded = [0u8; 16];
            padded[..4].copy_from_slice(&ip.octets());
            out.raw(&padded);
            out.u16(addr.port());
        }
        std::net::IpAddr::V6(ip) => {
            out.u8(6);
            out.raw(&ip.octets());
            out.u16(addr.port());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    #[test]
    fn create_proposes_local_invite_secret_before_request() {
        let connector = endpoint::commands::create_local_keypair().value;
        let inviter = endpoint::commands::create_local_keypair().value;
        let addr = "127.0.0.1:49000".parse::<SocketAddr>().expect("test addr");
        let invite_link = invite::commands::create(inviter, addr).value;

        let output = create(connector, &invite_link, None).expect("create request");

        assert_eq!(output.events.len(), 3);
        let invite_secret_event_id = output.events[0].event_id();
        let ephemeral_event_id = output.events[1].event_id();
        let request =
            codec::decode(&output.events[2].record().canonical_bytes).expect("decode request");
        let invite_secret =
            invite::codec::decode(&output.events[0].record().canonical_bytes).expect("invite");
        assert_eq!(invite_secret.addr, Some(addr));
        assert_eq!(output.value.addr, addr);
        assert_eq!(request.invite_secret_event_id, invite_secret_event_id);
        assert_eq!(
            request.initiator_ephemeral_secret_event_id,
            ephemeral_event_id
        );
        validate_invite_signature(&request, &invite_secret).expect("invite signature");
        assert_eq!(
            output.events[2].record().dependencies,
            vec![invite_secret_event_id, ephemeral_event_id]
        );
        assert!(request.from_listen_addr.is_none());
    }

    #[test]
    fn create_advertises_local_listen_addr_when_provided() {
        let connector = endpoint::commands::create_local_keypair().value;
        let inviter = endpoint::commands::create_local_keypair().value;
        let invite_addr = "127.0.0.1:49000".parse::<SocketAddr>().expect("test addr");
        let invite_link = invite::commands::create(inviter, invite_addr).value;
        let local_listen = "127.0.0.1:50000".parse::<SocketAddr>().expect("listen");

        let output = create(connector, &invite_link, Some(local_listen)).expect("create request");
        let request =
            codec::decode(&output.events[2].record().canonical_bytes).expect("decode request");

        assert_eq!(request.from_listen_addr, Some(local_listen));
    }
}

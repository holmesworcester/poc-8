//! Commands for initiating connection requests.
//!
//! This module is the active boundary that turns a human-copyable invite link
//! into two local facts and one opaque bootstrap frame:
//!
//! ```text
//! invite link + local endpoint
//!   -> local invite-secret fact
//!   -> local connection-request fact depending on that secret
//!   -> bootstrap transit bytes carrying the request fact
//! ```
//!
//! The command deliberately does not write rows, open sockets, run projectors,
//! or decide whether the remote side should accept the request. Those decisions
//! belong to the common event pipeline and the request projector. This command
//! only creates the facts and returns the route/bytes a caller can hand to
//! `transit_out`.
//!
//! Invariants:
//!
//! - The request's `invite_secret_event_id` is the deterministic id of the
//!   local invite-secret fact proposed immediately before it.
//! - Bootstrap authorization is carried by the request dependency edge, not by
//!   transit code reconstructing secret state from projected rows.
//! - The returned connection id is derived from `(request_id, invite endpoint)`
//!   so the local requester can name the same connection fact before any later
//!   traffic arrives.
//! - The returned bytes are transport bytes only. They are not stored as the
//!   semantic fact; the inner request event is.

use crate::core::crypto;
use crate::protocol::event_modules::identity::{endpoint, invite};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::CommandOutput;

use super::super::transit;
use super::super::types;
use super::codec;
use super::types::RequestEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundRequest {
    /// Bootstrap transit envelope carrying the connection request event.
    pub bytes: Vec<u8>,
    /// Deterministic id of the connection request event.
    pub request_id: EventId,
    /// Local view of the connection id derived from the request and invite
    /// endpoint.
    pub connection_id: types::ConnectionId,
    /// Socket address advertised by the invite link.
    pub addr: std::net::SocketAddr,
}

/// Create a connection request from an explicit local endpoint and invite link.
///
/// This function is intentionally pure with respect to storage. It parses the
/// invite, builds the local invite-secret event and the dependent request
/// event, wraps the request in a bootstrap transit envelope, and returns all of
/// that as `CommandOutput`. The caller must admit the proposed events before
/// treating the request as local fact graph state.
pub fn create(
    local: endpoint::types::EndpointKeypair,
    invite_link: &str,
) -> Result<CommandOutput<OutboundRequest>, String> {
    // The invite link gives this endpoint local bootstrap authority. Propose
    // that local fact first, then make the request depend on it explicitly.
    let invite = invite::commands::parse(invite_link)?;
    let invite_secret = invite::types::InviteSecretEvent::new(invite.bootstrap_secret);
    let invite_secret_bytes = invite::codec::encode(&invite_secret);
    let invite_secret_event_id = types::event_id(&invite_secret_bytes);
    let invite_secret_record = invite::codec::record_from_bytes(invite_secret_bytes)?;
    let event = RequestEvent {
        from_endpoint: local.endpoint,
        to_endpoint: invite.endpoint,
        nonce: nonce32(),
        bootstrap_hash: invite_secret.bootstrap_hash,
        invite_secret_event_id,
    };
    let inner = codec::encode(&event);
    let request_id = types::event_id(&inner);
    let connection_id = types::connection_id(&request_id, &invite.endpoint);
    let record = codec::record_from_bytes(inner.clone())?;
    Ok(CommandOutput::with_events(
        OutboundRequest {
            bytes: transit::commands::create_bootstrap(&local, invite.endpoint, &inner)?,
            request_id,
            connection_id,
            addr: invite.addr,
        },
        vec![invite_secret_record, record],
    ))
}

/// Create a request, creating or loading the local endpoint as explicit context.
///
/// Endpoint creation remains a command-produced fact as well: if no local
/// endpoint exists, the endpoint command's proposed local event is prepended so
/// admission sees the endpoint material before the request uses it.
pub fn create_with_local(
    context: &impl endpoint::commands::LocalEndpointRead,
    invite_link: &str,
) -> Result<CommandOutput<OutboundRequest>, String> {
    let local = endpoint::commands::local_or_create(context)?;
    Ok(create(local.value, invite_link)?.prepend_events(local.events))
}

/// Generate the request nonce that separates repeated requests to the same
/// invite endpoint.
fn nonce32() -> [u8; 32] {
    crypto::random_bytes_32()
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    // Invariant: create proposes local invite secret before request.
    #[test]
    fn create_proposes_local_invite_secret_before_request() {
        let connector = endpoint::commands::create_local_keypair().value;
        let inviter = endpoint::commands::create_local_keypair().value;
        let addr = "127.0.0.1:49000".parse::<SocketAddr>().expect("test addr");
        let invite_link = invite::commands::create(inviter, addr).value;

        let output = create(connector, &invite_link).expect("create request");

        assert_eq!(output.events.len(), 2);
        let invite_secret_event_id = output.events[0].event_id();
        let request =
            codec::decode(&output.events[1].record().canonical_bytes).expect("decode request");
        assert_eq!(request.invite_secret_event_id, invite_secret_event_id);
        assert_eq!(
            output.events[1].record().dependencies,
            vec![invite_secret_event_id]
        );
    }
}

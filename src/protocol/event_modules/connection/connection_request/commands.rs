//! Commands for initiating and accepting connection requests.
//!
//! Commands create proposed events and return any immediate bytes needed by the
//! caller. They do not write rows. The accept path receives its authorization
//! decision as a parameter, which keeps policy queries in the worker and keeps
//! this file a pure transformation over explicit inputs.

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
    pub bytes: Vec<u8>,
    pub request_id: EventId,
    pub local_endpoint: endpoint::types::EndpointId,
    pub addr: std::net::SocketAddr,
}

pub fn create(
    local: endpoint::types::EndpointKeypair,
    invite_link: &str,
) -> Result<CommandOutput<OutboundRequest>, String> {
    // The bootstrap hash proves knowledge of the invite secret without placing
    // that secret on the wire. The request event is proposed locally so the
    // eventual ack can be checked against the exact bytes we sent.
    let invite = invite::commands::parse(invite_link)?;
    let event = RequestEvent {
        from_endpoint: local.endpoint,
        to_endpoint: invite.endpoint,
        nonce: nonce32(),
        bootstrap_hash: invite::commands::secret_hash(&invite.bootstrap_secret),
    };
    let inner = codec::encode(&event);
    let request_id = types::event_id(&inner);
    let record = codec::record_from_bytes(inner.clone())?;
    Ok(CommandOutput::with_events(
        OutboundRequest {
            bytes: transit::commands::create_bootstrap(&local, invite.endpoint, &inner)?,
            request_id,
            local_endpoint: local.endpoint,
            addr: invite.addr,
        },
        vec![record],
    ))
}

pub fn create_with_local(
    context: &impl endpoint::commands::LocalEndpointRead,
    invite_link: &str,
) -> Result<CommandOutput<OutboundRequest>, String> {
    let local = endpoint::commands::local_or_create(context)?;
    Ok(create(local.value, invite_link)?.prepend_events(local.events))
}

pub(crate) fn accept(
    local: endpoint::types::EndpointKeypair,
    bootstrap_hash_is_authorized: bool,
    bytes: Vec<u8>,
) -> Result<CommandOutput<types::InboundConnection>, String> {
    // Authorization has already been checked by the worker against local invite
    // state. Once accepted, the response ack is just another proposed event
    // plus immediate return bytes for the caller to send back.
    let event = codec::decode(&bytes)?;
    if event.to_endpoint != local.endpoint {
        return Err("connection request addressed to a different endpoint".to_string());
    }
    if !bootstrap_hash_is_authorized {
        return Err("invite private key rejected".to_string());
    }

    let request_id = types::event_id(&bytes);
    let connection_id = types::connection_id(&request_id, &local.endpoint);
    let ack = super::super::connection_ack::types::AckEvent {
        from_endpoint: local.endpoint,
        to_endpoint: event.from_endpoint,
        request_id,
        connection_id,
    };
    let ack_bytes = super::super::connection_ack::codec::encode(&ack);
    let outgoing = vec![transit::commands::create_bootstrap(
        &local,
        event.from_endpoint,
        &ack_bytes,
    )?];
    let ack_record = super::super::connection_ack::codec::record_from_bytes(ack_bytes)?;
    Ok(CommandOutput::with_events(
        types::InboundConnection {
            outgoing,
            connection_id: Some(connection_id),
        },
        vec![ack_record],
    ))
}

fn nonce32() -> [u8; 32] {
    crypto::random_bytes_32()
}

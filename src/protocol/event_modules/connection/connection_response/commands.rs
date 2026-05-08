//! Commands for answering connection requests.
//!
//! A response is the connection event: its canonical bytes carry the
//! per-connection traffic secret, and its event id is the connection id. The
//! command returns both the local event record and endpoint-bootstrap transit
//! bytes that can be sent back on the stream that delivered the request.

use crate::core::crypto;
use crate::protocol::event_modules::identity::endpoint;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::CommandOutput;

use super::super::connection_request;
use super::super::transit;
use super::super::types;
use super::codec;
use super::types::ResponseEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundResponse {
    /// Bootstrap transit envelope carrying the connection event.
    pub bytes: Vec<u8>,
    /// Event id of the connection event.
    pub connection_id: types::ConnectionId,
}

pub fn create(
    local: endpoint::types::EndpointKeypair,
    request_id: EventId,
    request: connection_request::types::RequestEvent,
) -> Result<CommandOutput<OutboundResponse>, String> {
    if local.endpoint != request.to_endpoint {
        return Err(
            "connection response local endpoint does not match request recipient".to_string(),
        );
    }
    let event = ResponseEvent {
        from_endpoint: local.endpoint,
        to_endpoint: request.from_endpoint,
        request_id,
        traffic_secret: crypto::random_xchacha20poly1305_key(),
    };
    let inner = codec::encode(&event);
    let connection_id = types::event_id(&inner);
    let record = codec::record_from_bytes(inner.clone())?;
    Ok(CommandOutput::with_events(
        OutboundResponse {
            bytes: transit::commands::create_bootstrap(&local, request.from_endpoint, &inner)?,
            connection_id,
        },
        vec![record],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_id_is_response_event_id_and_commits_to_secret() {
        let local = endpoint::commands::create_local_keypair().value;
        let request = connection_request::types::RequestEvent {
            from_endpoint: [1; 32],
            to_endpoint: local.endpoint,
            nonce: [2; 32],
            bootstrap_hash: [3; 32],
            invite_secret_event_id: [4; 32],
            from_listen_addr: None,
        };

        let output = create(local, [9; 32], request).expect("create response");
        let record = output.events[0].record();
        let response = codec::decode(&record.canonical_bytes).expect("decode response");

        assert_eq!(
            output.value.connection_id,
            types::event_id(&record.canonical_bytes)
        );
        assert_eq!(response.request_id, [9; 32]);
        assert_ne!(response.traffic_secret, [0; 32]);
    }
}

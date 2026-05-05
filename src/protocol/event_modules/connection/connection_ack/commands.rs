//! Command for accepting a connection ack.
//!
//! The command checks only facts available in the ack itself and the local
//! endpoint. The deeper request relationship is a declared event dependency and
//! is validated by the projector through standard dependency context.

use crate::protocol::event_modules::identity::endpoint;
use crate::protocol::event_modules::worker::CommandOutput;

use super::super::types;
use super::codec;

pub(crate) fn accept(
    local: endpoint::types::EndpointKeypair,
    bytes: Vec<u8>,
) -> Result<CommandOutput<types::InboundConnection>, String> {
    let event = codec::decode(&bytes)?;
    if event.to_endpoint != local.endpoint {
        return Err("connection ack addressed to a different endpoint".to_string());
    }
    let expected_connection_id = types::connection_id(&event.request_id, &event.from_endpoint);
    if event.connection_id != expected_connection_id {
        return Err("connection ack has an invalid connection id".to_string());
    }

    Ok(CommandOutput::with_events(
        types::InboundConnection {
            outgoing: Vec::new(),
            connection_id: Some(event.connection_id),
        },
        Vec::new(),
    ))
}

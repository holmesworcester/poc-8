//! Wire codec for connection response events.
//!
//! Responses are local protocol history. They exist for the fact-graph model
//! of connection establishment: "endpoint B answered request R and committed
//! to connection id C".
//!
//! The request id is both a body field and the event dependency. That is the
//! important boundary: the response projector validates the request/response
//! relationship from dependency context, not by querying a connection table or
//! trusting transit metadata. Transit may prove who sent the bytes, but only
//! this record's dependency edge proves which request is being answered.
//!
//! This codec only encodes/decodes canonical bytes and declares record metadata.
//! It does not establish a connection, learn a route, or decide whether a
//! response is useful; the projector owns those checks.

use crate::protocol::event_modules::types::{EventRecord, EventScope};
use crate::protocol::wire_schema::{Field, WireSchema};

use super::types::ResponseEvent;

pub const TYPE_CONNECTION_RESPONSE: u8 = 133;
pub const TAG: u8 = TYPE_CONNECTION_RESPONSE;

pub const SCHEMA: WireSchema = WireSchema::new(
    "connection.response",
    TYPE_CONNECTION_RESPONSE,
    &[
        Field::id("from_endpoint"),
        Field::id("to_endpoint"),
        Field::id("request_id"),
        Field::id("invite_secret_event_id"),
        Field::id("initiator_ephemeral_secret_event_id"),
        Field::id("responder_ephemeral_secret_event_id"),
        Field::id("responder_ephemeral_public_key"),
        Field::id("handshake_hash"),
        Field::id("connection_secret"),
    ],
);

pub fn encode(event: &ResponseEvent) -> Vec<u8> {
    SCHEMA
        .encoder()
        .id(&event.from_endpoint)
        .id(&event.to_endpoint)
        .id(&event.request_id)
        .id(&event.invite_secret_event_id)
        .id(&event.initiator_ephemeral_secret_event_id)
        .id(&event.responder_ephemeral_secret_event_id)
        .id(&event.responder_ephemeral_public_key)
        .id(&event.handshake_hash)
        .id(&event.connection_secret)
        .finish()
}

/// Decode canonical response bytes and reject malformed tags/trailing bytes.
pub fn decode(bytes: &[u8]) -> Result<ResponseEvent, String> {
    let v = SCHEMA.parse(bytes)?;
    Ok(ResponseEvent {
        from_endpoint: v.id("from_endpoint")?,
        to_endpoint: v.id("to_endpoint")?,
        request_id: v.id("request_id")?,
        invite_secret_event_id: v.id("invite_secret_event_id")?,
        initiator_ephemeral_secret_event_id: v.id("initiator_ephemeral_secret_event_id")?,
        responder_ephemeral_secret_event_id: v.id("responder_ephemeral_secret_event_id")?,
        responder_ephemeral_public_key: v.id("responder_ephemeral_public_key")?,
        handshake_hash: v.id("handshake_hash")?,
        connection_secret: v.id("connection_secret")?,
    })
}

/// Fast tag check used by registry dispatch.
pub fn is_response(bytes: &[u8]) -> bool {
    bytes.first() == Some(&TYPE_CONNECTION_RESPONSE)
}

/// Build the common event record for response admission.
///
/// Response facts are local because they are connection state for this node,
/// not workspace history for global sharing. The request dependency is what
/// lets the projector validate endpoint direction and the derived connection id
/// before writing any connection rows.
pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let event = decode(&bytes)?;
    Ok(EventRecord {
        timestamp: 0,
        body_len: 0,
        canonical_bytes: bytes,
        dependencies: vec![
            event.request_id,
            event.invite_secret_event_id,
            event.responder_ephemeral_secret_event_id,
        ],
        workspace_id: None,
        scope: EventScope::Local,
    })
}

pub fn received_record_from_bytes(
    _store: &crate::core::store::Store,
    bytes: Vec<u8>,
    request_id: [u8; 32],
) -> Result<EventRecord, String> {
    let event = decode(&bytes)?;
    if event.request_id != request_id {
        return Err("connection event does not answer transit request".to_string());
    }
    Ok(EventRecord {
        timestamp: 0,
        body_len: 0,
        canonical_bytes: bytes,
        dependencies: vec![
            event.request_id,
            event.invite_secret_event_id,
            event.initiator_ephemeral_secret_event_id,
        ],
        workspace_id: None,
        scope: EventScope::Local,
    })
}

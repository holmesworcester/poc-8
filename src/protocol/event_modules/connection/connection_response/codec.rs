//! Wire codec for connection response events.
//!
//! Responses use the same connection magic as requests and are local protocol
//! history. They exist for the fact-graph model of connection establishment:
//! "endpoint B answered request R and committed to connection id C".
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
use crate::protocol::wire::{Reader, Writer};

use super::super::types::EVENT_MAGIC;
use super::types::ResponseEvent;

pub const TAG: u8 = 2;

pub fn encode(event: &ResponseEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(10 + 1 + 32 * 10);
    out.raw(EVENT_MAGIC);
    out.u8(TAG);
    out.id(&event.from_endpoint);
    out.id(&event.to_endpoint);
    out.id(&event.request_id);
    out.id(&event.invite_secret_event_id);
    out.id(&event.initiator_ephemeral_secret_event_id);
    out.id(&event.responder_ephemeral_secret_event_id);
    out.id(&event.responder_ephemeral_public_key);
    out.id(&event.handshake_hash);
    out.id(&event.connection_secret);
    out.finish()
}

/// Decode canonical response bytes and reject malformed tags/trailing bytes.
pub fn decode(bytes: &[u8]) -> Result<ResponseEvent, String> {
    if !bytes.starts_with(EVENT_MAGIC) {
        return Err("not a connection event".to_string());
    }
    let mut reader = Reader::new(&bytes[EVENT_MAGIC.len()..], "connection response");
    let tag = reader.u8()?;
    if tag != TAG {
        return Err("expected connection response".to_string());
    }
    let event = ResponseEvent {
        from_endpoint: reader.id()?,
        to_endpoint: reader.id()?,
        request_id: reader.id()?,
        invite_secret_event_id: reader.id()?,
        initiator_ephemeral_secret_event_id: reader.id()?,
        responder_ephemeral_secret_event_id: reader.id()?,
        responder_ephemeral_public_key: reader.id()?,
        handshake_hash: reader.id()?,
        connection_secret: reader.id()?,
    };
    reader.finish()?;
    Ok(event)
}

/// Fast tag check used by registry dispatch.
pub fn is_response(bytes: &[u8]) -> bool {
    bytes.starts_with(EVENT_MAGIC) && bytes.get(EVENT_MAGIC.len()) == Some(&TAG)
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

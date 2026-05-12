//! Connection response event fields.
//!
//! The response is the connection event. Its event id is the connection id, and
//! its body carries the short-lived connection secret used by normal transit
//! until TTL purge removes this local event.
//!
//! Field meanings:
//!
//! - `from_endpoint`: endpoint answering the request.
//! - `to_endpoint`: endpoint that created the request.
//! - `request_id`: dependency edge to the request being answered.
//! - `connection_secret`: symmetric root secret for connection transit.
//! - `handshake_hash`: public transcript hash both peers can recompute.
//!
//! The socket address used to deliver a response is intentionally absent. Route
//! state is receive metadata projected locally, not part of the canonical fact.

use crate::protocol::event_modules::identity::endpoint::types::EndpointId;
use crate::protocol::event_modules::types::EventId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseEvent {
    /// Endpoint answering the request.
    pub from_endpoint: EndpointId,
    /// Endpoint that originally created the request.
    pub to_endpoint: EndpointId,
    /// Event id of the request this response answers.
    pub request_id: EventId,
    /// Request's invite-secret dependency, copied so this event can name the
    /// dependency directly without relying on transitive context.
    pub invite_secret_event_id: EventId,
    /// Requester's local ephemeral dependency, copied for receive-side
    /// validation on the requester.
    pub initiator_ephemeral_secret_event_id: EventId,
    /// Responder's local ephemeral dependency, used by the responder's local
    /// projection before this event is sent.
    pub responder_ephemeral_secret_event_id: EventId,
    /// Public half of the responder ephemeral key.
    pub responder_ephemeral_public_key: EndpointId,
    /// Hash of the public request/response handshake transcript.
    pub handshake_hash: EventId,
    /// Root secret used to derive normal connection transit keys.
    pub connection_secret: EventId,
}

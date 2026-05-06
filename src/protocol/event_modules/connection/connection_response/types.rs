//! Connection response event fields.
//!
//! The response is the accepting endpoint's commitment to a specific request
//! and derived connection id. Both peers can recompute the id, so a mismatched
//! response is rejected before any connection row is projected.
//!
//! Field meanings:
//!
//! - `from_endpoint`: endpoint answering the request.
//! - `to_endpoint`: endpoint that created the request.
//! - `request_id`: dependency edge to the request being answered.
//! - `connection_id`: deterministic `connection_id(request_id, from_endpoint)`.
//!
//! The socket address used to deliver a response is intentionally absent. Route
//! state is receive metadata projected locally, not part of the canonical fact.

use crate::protocol::event_modules::connection::types::ConnectionId;
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
    /// Deterministic id derived from the request id and responder endpoint.
    pub connection_id: ConnectionId,
}

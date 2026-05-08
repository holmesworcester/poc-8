//! Connection response event fields.
//!
//! The response is the connection event. Its event id is the connection id, and
//! its canonical bytes carry the local-only traffic secret needed to decrypt
//! later connection transit frames. Projection can cache endpoint/route rows,
//! but decrypting a transit frame only needs to load this event by id.
//!
//! Field meanings:
//!
//! - `from_endpoint`: endpoint answering the request.
//! - `to_endpoint`: endpoint that created the request.
//! - `request_id`: dependency edge to the request being answered.
//! - `traffic_secret`: per-connection secret used to derive directional transit
//!   keys.
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
    /// Local-only per-connection secret. The response event id commits to this
    /// value, and transit derives directional keys from it.
    pub traffic_secret: [u8; 32],
}

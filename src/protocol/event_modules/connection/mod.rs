//! Connection domain.
//!
//! Connection events establish the semantic relationship between two endpoints.
//! They are distinct from transport targets, which are merely addresses where
//! bytes might be sent right now. The domain owns request/ack event syntax,
//! route facts, transit wrapping helpers, and the connection worker that bridges
//! opaque network frames to canonical event bytes.

pub mod cli;
pub mod connection_ack;
pub mod connection_request;
pub mod queries;
pub mod schema;
pub mod transit;
pub mod types;
pub use crate::workers::connection as worker;

use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

pub fn is_projection_record(bytes: &[u8]) -> bool {
    connection_request::codec::is_request(bytes) || connection_ack::codec::is_ack(bytes)
}

pub fn project_record(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let bytes = &event.record.canonical_bytes;
    if connection_request::codec::is_request(bytes) {
        return connection_request::projector::project(event);
    }
    if connection_ack::codec::is_ack(bytes) {
        return connection_ack::projector::project(event);
    }
    Err("not a connection projection record".to_string())
}

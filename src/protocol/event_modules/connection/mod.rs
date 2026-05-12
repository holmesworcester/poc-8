//! Connection domain.
//!
//! Connection events establish the semantic relationship between two endpoints.
//! They are distinct from transport targets, which are merely addresses where
//! bytes might be sent right now. The domain owns request/response event
//! syntax, route facts, and transit wrapping helpers. Scheduled transit workers
//! live under `src/workers` and bridge opaque network frames to canonical event
//! bytes without owning connection semantics.

pub mod cli;
pub mod connection_ephemeral_secret;
pub mod connection_request;
pub mod connection_response;
pub mod queries;
pub mod schema;
pub mod transit;
pub mod types;

use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

pub fn is_projection_record(bytes: &[u8]) -> bool {
    connection_ephemeral_secret::codec::is_ephemeral_secret(bytes)
        || connection_request::codec::is_request(bytes)
        || connection_response::codec::is_response(bytes)
}

pub fn project_record(event: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let bytes = &event.record.canonical_bytes;
    if connection_ephemeral_secret::codec::is_ephemeral_secret(bytes) {
        return Ok(ProjectionOutput::default());
    }
    if connection_request::codec::is_request(bytes) {
        return connection_request::projector::project(event);
    }
    if connection_response::codec::is_response(bytes) {
        return connection_response::projector::project(event);
    }
    Err("not a connection projection record".to_string())
}

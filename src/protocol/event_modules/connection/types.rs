//! Shared connection-domain types.
//!
//! The connection id is the event id of the accepted connection response event.

use crate::protocol::event_modules::types::EventId;

pub type ConnectionId = [u8; 32];

pub(crate) fn event_id(bytes: &[u8]) -> EventId {
    *blake3::hash(bytes).as_bytes()
}

pub(crate) fn connection_id_from_bytes(bytes: &[u8]) -> Result<ConnectionId, String> {
    bytes
        .try_into()
        .map_err(|_| "connection id must be 32 bytes".to_string())
}

//! Local history range-node key types.
//!
//! These local-only events let filesystem history keys be ordinary events.
//! Their dependency ids make the common event worker sort parent/sibling key
//! material before the node that relies on it.

use crate::core::crypto::XChaCha20Poly1305Key;
use crate::protocol::event_modules::types::EventId;

pub type HistoryNodeSecret = XChaCha20Poly1305Key;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHistoryNodeSecret {
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    pub source_secret_id: EventId,
    pub range_start: u64,
    pub range_width: u64,
    pub tombstone_node_id: Option<EventId>,
    pub node_secret: HistoryNodeSecret,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHistoryNodeSecretRow {
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    pub local_history_node_secret_id: EventId,
    pub source_secret_id: EventId,
    pub range_start: u64,
    pub range_width: u64,
    pub tombstone_node_id: Option<EventId>,
    pub node_secret: HistoryNodeSecret,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHistoryNodeTombstoneRow {
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    pub tombstone_node_id: EventId,
    pub replacement_node_id: EventId,
}

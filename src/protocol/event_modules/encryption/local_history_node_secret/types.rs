//! Local history range-node key types.
//!
//! These local-only events let filesystem history keys be ordinary events.
//! Their dependency ids make the common event worker sort parent/sibling key
//! material before the node that relies on it.
//!
//! After the per-message FS leaf-coord redesign each leaf is keyed by
//! `(workspace_id, removal_frontier_id, unix_minute, leaf_nonce)`. The
//! `event_id_in_minute` field is `Some(leaf_nonce)` for a per-message leaf
//! and `None` for the per-minute coarse cover node that sits between the
//! frontier root and the message leaves.

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
    pub event_id_in_minute: Option<EventId>,
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
    pub event_id_in_minute: Option<EventId>,
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

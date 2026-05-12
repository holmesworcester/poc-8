//! Types for the workspace-wide `disappearing_messages_setting` event.
//!
//! A setting event is a shared admin-signed fact that supersedes the
//! workspace event's initial TTL. The active setting is the latest
//! admitted setting event for a given `workspace_id` under the
//! deterministic `(created_at_ms, event_id)` ordering. Late-arriving
//! settings do not retroactively rewrite already-stamped messages -
//! every authored message commits to its own `expires_at_minute` in
//! canonical bytes (see slice 1).

use crate::core::crypto::{Ed25519PublicKey, Ed25519Signature};
use crate::protocol::event_modules::types::EventId;

/// Number of unix-minutes after which a workspace's time-tree subtree is
/// sealed: no straggler can plausibly deliver messages this old, so the
/// sibling cover for the range becomes dead weight. Slice 5: the
/// `disappearing_floor_dispatcher` worker chops the prefix
/// `[0, now_minute - COVER_HORIZON_MINUTES)` once per workspace per tick
/// (in addition to chopping for any newly-tightened admin setting).
///
/// Set to 30 days. The exact value is a policy knob; the structural cost
/// is O(log time_tree_root_width) per chop regardless of horizon size, so
/// shrinking or growing it does not change the per-tick cost — only the
/// amount of in-tree state retained for late-delivery cover.
pub const COVER_HORIZON_MINUTES: u64 = 30 * 24 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisappearingMessagesSettingEvent {
    pub created_at_ms: u64,
    pub workspace_id: EventId,
    pub ttl_minutes: u32,
    /// Admin event id authorizing this setting. Validated by the projector
    /// against the workspace admin set so a non-admin signer is rejected.
    pub authority_admin_event_id: EventId,
    /// `floor(created_at_ms / 60_000)`. Carried in canonical bytes for
    /// deterministic comparison without re-deriving from `created_at_ms`.
    pub effective_at_minute: u64,
    /// Monotonic deletion floor: any message whose
    /// `floor(created_at_ms / UNIX_MINUTE_MS) < expires_at_or_before_minute`
    /// is considered deleted regardless of its per-message stamp. The
    /// projector validates this is non-decreasing across successive admitted
    /// settings (chain-checked via `previous_setting_id`).
    pub expires_at_or_before_minute: u64,
    /// `Some(id)` names the predecessor setting whose floor this setting
    /// must not regress. `None` (sentinel `[0; 32]` on the wire) is allowed
    /// only when no setting has yet been admitted for this workspace; in
    /// that case the new floor is unconstrained from below.
    pub previous_setting_id: Option<EventId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDisappearingMessagesSettingEnvelope {
    pub authority_admin_event_id: EventId,
    pub signer_public_key: Ed25519PublicKey,
    pub payload: Vec<u8>,
    pub signature: Ed25519Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveSettingRow {
    pub workspace_id: EventId,
    pub setting_event_id: EventId,
    pub ttl_minutes: u32,
    pub effective_at_minute: u64,
    pub created_at_ms: u64,
    pub expires_at_or_before_minute: u64,
}

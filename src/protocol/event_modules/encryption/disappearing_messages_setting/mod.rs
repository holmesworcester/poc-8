//! Shared admin-signed `disappearing_messages_setting` event module.
//!
//! Scope: workspace-wide TTL for disappearing messages, authored by an
//! authorized workspace admin. The active setting for a workspace is the
//! latest admitted setting under deterministic `(created_at_ms,
//! event_id)` ordering. Late-arriving settings do not retroactively
//! rewrite already-stamped messages — every authored message commits to
//! its own `expires_at_minute` in canonical bytes (slice 1).
//!
//! Dependencies: workspace event and the authority admin event; both
//! must be `Applied` before this event projects.
//!
//! Projection writes one row per admitted setting, keyed so the active
//! setting can be looked up via a single bounded prefix scan. Older rows
//! survive so projection is order-independent and convergent across
//! peers.
//!
//! Non-responsibilities: this module does NOT decide authoring-time
//! expiry (the message command stamps `expires_at_minute` from the
//! active setting at authoring time), does NOT own the workspace event's
//! initial TTL field (that lives on the workspace event), and does NOT
//! implement TTL enforcement (the `disappearing_minute_expiry` worker
//! does that purely by reading already-stamped `expires_at_minute`).

pub mod codec;
pub mod commands;
pub mod projector;
pub mod queries;
pub mod schema;
pub mod types;

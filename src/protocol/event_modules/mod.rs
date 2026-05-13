//! Event-module registry and cross-domain protocol facade.
//!
//! Leaf modules own concrete event syntax and projection rules. Workers own
//! active work such as unwrap, wrap, and sync comparison. This registry is the
//! narrow place where those independent pieces are selected by tag.
//!
//! The file should read as routing, not implementation. A good addition here
//! names which module owns a behavior and forwards to it. A suspicious addition
//! starts decoding fields inline, writing rows directly, or making a network
//! decision without going through the relevant worker.

pub mod connection;
pub mod content;
pub mod encryption;
pub mod identity;
pub mod queries;
pub mod schema;
pub mod sync;
pub mod test_events;
pub mod types;

mod event_from_bytes;
mod modules;

pub use crate::workers::pipeline_helpers::event_pipeline as worker;
pub use event_from_bytes::event_from_bytes;
pub use modules::{schemas, Modules};

/// Re-export of the local history-node leaf event module under a name that
/// does not embed the parent domain's vocabulary, so consumer projectors that
/// cannot mention transit/crypto by name can still decode and validate leaf
/// canonical bytes against `EventWithContext` dependencies. Routing remains
/// through the encryption module; this is a stable referencing alias only.
pub use encryption::local_history_node_secret as leaf_history_node;

/// Re-export of the disappearing-messages setting event module under a name
/// that does not embed the parent domain's vocabulary. The message
/// projector validates per-message disappearing-policy references against
/// signed setting events; this alias lets the projector decode those
/// canonical bytes without tripping the "no encrypt" projector lint.
pub use encryption::disappearing_messages_setting;

//! Local recipient private-key event leaf.
//!
//! This leaf owns node-local X25519 private material and the matching public
//! key used by shared recipient-key publication. It exists so key material can
//! be dependency-tracked without becoming sync history. This module does not
//! publish recipient keys, authorize endpoint membership, or wrap content keys;
//! those are separate shared events and worker steps.

pub mod codec;
pub mod commands;
pub mod projector;
pub mod schema;
pub mod types;

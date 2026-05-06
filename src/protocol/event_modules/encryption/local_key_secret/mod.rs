//! Local content key-secret event leaf.
//!
//! This leaf owns the local-only event that holds the symmetric content key for
//! one removal frontier. Shared content and key-wrap events name its
//! deterministic event id as a dependency/commitment; the secret bytes remain
//! local and are never synchronized. Authorization for the frontier is checked
//! by projection, not by core storage.

pub mod codec;
pub mod commands;
pub mod projector;
pub mod schema;
pub mod types;

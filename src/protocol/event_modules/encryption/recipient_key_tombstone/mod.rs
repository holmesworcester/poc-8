//! Recipient key tombstone event leaf.
//!
//! Tombstones are signed shared facts that retire one recipient public key in
//! favor of another for the same endpoint membership. This leaf owns the event
//! shape, validation, and row/delete projection. It does not erase local
//! private keys or already-derived content keys; those are retention and worker
//! responsibilities.

pub mod codec;
pub mod commands;
pub mod projector;
pub mod queries;
pub mod schema;
pub mod types;

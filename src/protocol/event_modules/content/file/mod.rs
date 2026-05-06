//! File descriptor event leaf.
//!
//! This leaf owns the signed metadata event that binds a random `file_id` to
//! one workspace message, a byte length, a slice budget, and a BAO root hash.
//! It does not own the file bytes themselves; those are `file_slice` events.
//! The invariant is that every projected descriptor is authorized by the same
//! workspace identity graph as messages, and every slice resolves back to this
//! descriptor before its bytes can be trusted.

pub mod cli;
pub mod codec;
pub mod commands;
pub mod projector;
pub mod schema;
pub mod types;

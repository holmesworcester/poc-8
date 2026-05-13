//! Removal frontier event leaf.
//!
//! A removal frontier is the shared authorization boundary for one content-key
//! generation. It is a compact causal boundary, not a list of all previous
//! workspace events: non-empty frontiers name only enough removal refs for their
//! dependency closure to cover the removals this key generation incorporates.
//!
//! This leaf owns the signed frontier event and projected row; key secrets,
//! wraps, and encrypted content name the frontier id but do not define it. The
//! current slice validates ref closure and workspace membership, while the
//! shared removal fact vocabulary can later tighten what counts as a removal
//! boundary.

pub mod codec;
pub mod commands;
pub mod projector;
pub mod queries;
pub mod schema;
pub mod types;

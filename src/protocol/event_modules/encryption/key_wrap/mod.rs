//! Key-wrap event leaf.
//!
//! Scope: workspace-shared, recipient-targeted wraps of a frontier-bound
//! local key-secret. Projection writes one wrap row per admitted event
//! plus a `PENDING_KEY_UNWRAPS` indicator row the encryption worker
//! drains to materialize the recipient-side local key-secret. Reads
//! (listing wraps, joining a wrap with its pending row) live in
//! `queries.rs`; row mutation only happens in the projector or the
//! encryption worker.

pub mod codec;
pub mod commands;
pub mod projector;
pub mod queries;
pub mod schema;
pub mod types;

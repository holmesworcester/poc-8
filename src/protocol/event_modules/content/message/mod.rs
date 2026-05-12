//! Message event leaf.
//!
//! This leaf owns the signed, encrypted workspace chat message event and its
//! local plaintext projection. Message authority comes from identity
//! dependencies supplied by the common event pipeline; content-key availability
//! comes from local encryption events. The module does not perform sync,
//! retention purge, or cross-content workflows; those stay in workers and the
//! content domain root.

pub mod cli;
pub mod codec;
pub mod commands;
pub mod projector;
pub mod queries;
pub mod schema;
pub mod types;

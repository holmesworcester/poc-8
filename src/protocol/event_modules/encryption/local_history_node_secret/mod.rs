//! Local history node secret event leaf.
//!
//! This leaf models range-derived history secrets as local-only events so they
//! use the same dependency and projection machinery as shared facts. It owns
//! deterministic derivation inputs, row encoding, and optional local tombstone
//! rows for replaced nodes. It does not create shared removal facts or send
//! secret material across sync.

pub mod codec;
pub mod commands;
pub mod projector;
pub mod queries;
pub mod schema;
pub mod types;

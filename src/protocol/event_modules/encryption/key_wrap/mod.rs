//! Shared key-wrap event leaf.
//!
//! A key wrap is the shared fact that makes one local content key available to
//! one recipient key under one removal frontier. This leaf owns the canonical
//! signed wrap, its commitment row, and projection-time authority checks. It
//! does not open wraps or mint local key-secret events; bounded derivation lives
//! in the encryption worker and re-enters the common event pipeline.

pub mod codec;
pub mod commands;
pub mod projector;
pub mod schema;
pub mod types;

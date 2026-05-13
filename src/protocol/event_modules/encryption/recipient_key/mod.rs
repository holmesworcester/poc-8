//! Shared recipient key event leaf.
//!
//! A recipient key publishes the public X25519 key for one endpoint membership
//! in one workspace. This leaf owns the signed shared fact and projection row;
//! it relies on identity endpoint_shared rows for authority. It does not store
//! private material and does not decide which key secrets should be wrapped.

pub mod codec;
pub mod commands;
pub mod projector;
pub mod queries;
pub mod schema;
pub mod types;

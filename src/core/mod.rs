//! Protocol-neutral substrate.
//!
//! Core is the part of the program a different protocol should be able to
//! reuse unchanged. It supplies a small row store, opaque byte queues for raw
//! network traffic, a TCP pump that moves length-prefixed frames, and a tiny
//! Crux command runner. It must not learn the vocabulary or validity rules of
//! whatever protocol sits above it.

pub mod cli;
pub mod crux_runner;
pub mod crypto;
pub mod network_queues;
pub mod store;
pub mod tcp;

// BAO verified streaming is a generic primitive. Re-exporting the public
// surface here lets row-only projectors call into it without naming the
// hash module in their imports.
pub use crypto::{bao_extract_slice, bao_outboard, bao_verify_slice};

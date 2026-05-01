//! Tiny POC kernel.
//!
//! The live core is intentionally small:
//! - [`pipeline`] owns canonical events, dependency blocking, projector apply,
//!   labels, outbox rows, and module-declared tables.
//! - [`control_loop`] owns bounded scheduling over pipeline queues.
//! - [`network`] owns per-connection sending and byte transport.
//! - [`event_modules`] owns all domain behavior.

pub mod control_loop;
pub mod event_modules;
pub mod network;
pub mod pipeline;

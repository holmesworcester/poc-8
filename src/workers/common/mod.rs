//! Shared worker common modules.
//!
//! This module is only the namespace boundary for worker-owned common code. The
//! files beneath it own concrete responsibilities: event admission/projection
//! mechanics live in `event_pipeline`, and local retention cleanup lives in
//! `retention`. Protocol table definitions stay in schema modules; domain policy
//! stays in the domain worker or event module that can justify it.

pub mod event_pipeline;
pub(crate) mod retention;

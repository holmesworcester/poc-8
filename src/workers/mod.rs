//! Topo worker catalog.
//!
//! Workers are fundamental runtime boundaries. Their implementations live in
//! this directory so reviewers can see every active queue/status/index drain in
//! one place. Event modules still own event syntax, schemas, commands, and
//! projectors; workers own bounded movement between explicit inputs and outputs.
//!
//! See `src/workers/README.md` for the universal worker contract and the plan to
//! split the current coarse workers into the target worker set.

pub mod connection;
pub mod events;
pub mod sync;

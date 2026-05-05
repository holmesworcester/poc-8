//! Topo worker catalog.
//!
//! Workers are fundamental runtime boundaries. Their implementations live in
//! this directory so reviewers can see every active queue/status/index drain in
//! one place. Event modules still own event syntax, schemas, commands, and
//! projectors; workers own bounded movement between explicit inputs and outputs.
//!
//! See `src/workers/README.md` for the universal worker contract, current
//! queues, and remaining scheduler migration work.

pub mod connection;
pub mod connection_egress;
pub mod connection_ingress;
pub mod dependency_wake;
pub mod event_admission;
pub mod event_projection;
pub mod events;
pub mod sync;
pub mod sync_index;
pub mod sync_protocol;

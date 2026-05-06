//! Message deletion event leaf.
//!
//! Deletion is a signed protocol fact, not the local retention purge. This leaf
//! owns the canonical deletion event and the generic label it projects onto the
//! target message id. The content purge worker later consumes those durable
//! facts to remove local rows and event bytes when it is safe; this module does
//! not delete event-store history directly.

pub mod cli;
pub mod codec;
pub mod commands;
pub mod projector;
pub mod schema;
pub mod types;

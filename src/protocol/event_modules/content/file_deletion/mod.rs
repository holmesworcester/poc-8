//! File deletion event leaf.
//!
//! File deletion mirrors message deletion: a signed protocol fact that
//! authorizes purging the named file event's bytes plus its slice rows. The
//! leaf owns the canonical event and the generic label it projects onto the
//! target file event id. The content purge worker later consumes those
//! durable facts to remove projection rows and event bytes when it is safe;
//! this module does not delete event-store history directly.
//!
//! File deletions are also authored automatically as a cascade from
//! `message_deletion`: when a message is deleted, every file that named
//! that message as its parent is also retired so the file's per-event leaf
//! is purged alongside the message's leaf.

pub mod cli;
pub mod codec;
pub mod commands;
pub mod projector;
pub mod types;

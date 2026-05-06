//! Sync CLI command registry.
//!
//! Manual finite sync serving is deprecated. Ongoing sync starts and responds
//! from the daemon's `sync_tick` worker.

use crate::core::cli::CliCommand;
use crate::protocol::cli::Context;

pub fn commands() -> Vec<CliCommand<Context>> {
    Vec::new()
}

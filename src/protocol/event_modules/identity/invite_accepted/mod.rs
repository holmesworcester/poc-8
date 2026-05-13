//! Local invite-acceptance event module.
//!
//! This leaf owns the durable local fact that an endpoint accepted an
//! out-of-band identity invite for a workspace. It deliberately does not own the
//! shared invite event, membership event, TCP stream, route learning, or
//! bootstrap response construction. Those remain with their existing modules.
//!
//! The module exists so replay can reconstruct acceptance provenance from
//! canonical local events instead of relying on hidden CLI state:
//!
//! ```text
//! invite link
//!   -> invite_secret local event
//!   -> invite_accepted local event
//!   -> ordinary connection sync may admit shared identity facts
//! ```
//!
//! `invite_secret` owns secret material. `invite_accepted` owns the scoped
//! provenance row tying that secret to the endpoint, workspace, and invite id.

pub mod codec;
pub mod commands;
pub mod projector;
pub mod queries;
pub mod schema;
pub mod types;

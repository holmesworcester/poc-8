//! Content domain.
//!
//! Content events are signed workspace-scoped payload events. Each leaf module
//! owns its own outer signed-envelope tag plus an inner content tag, and
//! projection enforces the shared-event auth rule: signers must be endpoint
//! memberships in the workspace.

pub mod cli;
pub mod content_event;
pub mod file;
pub mod file_slice;
pub mod message;
pub mod message_deletion;
pub mod prepare;
pub mod reaction;

use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

pub fn project_record(event: &EventWithContext<'_>) -> Result<Option<ProjectionOutput>, String> {
    let bytes = &event.record.canonical_bytes;
    match bytes.first().copied() {
        Some(content_event::codec::TYPE_SIGNED_CONTENT) => {
            Ok(Some(content_event::projector::project(event)?))
        }
        Some(message::codec::TYPE_SIGNED_MESSAGE) => {
            let prepared = prepare::prepare_message(event)?;
            Ok(Some(message::projector::project(
                &prepared,
                &event.context.labels,
            )?))
        }
        Some(reaction::codec::TYPE_SIGNED_REACTION) => {
            let prepared = prepare::prepare_reaction(event)?;
            Ok(Some(reaction::projector::project(&prepared)?))
        }
        Some(message_deletion::codec::TYPE_SIGNED_MESSAGE_DELETION) => {
            Ok(Some(message_deletion::projector::project(event)?))
        }
        Some(file::codec::TYPE_SIGNED_FILE) => Ok(Some(file::projector::project(event)?)),
        Some(file_slice::codec::TYPE_SIGNED_FILE_SLICE) => {
            Ok(Some(file_slice::projector::project(event)?))
        }
        _ => Ok(None),
    }
}

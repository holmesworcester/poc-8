//! Projector for shared workspace events.
//!
//! Projection is row-only: decode the event and write one workspace row keyed by
//! workspace id. The workspace id is the deterministic id of the canonical
//! event bytes.

use crate::protocol::event_modules::types::event_id;
use crate::protocol::event_modules::worker::ProjectionOutput;

use super::{codec, schema};

pub fn project(bytes: &[u8]) -> Result<ProjectionOutput, String> {
    let event = codec::decode(bytes)?;
    let workspace_id = event_id(bytes);
    Ok(ProjectionOutput::rows(vec![schema::workspace_row(
        workspace_id,
        event.created_at_ms,
        event.public_key,
        event.disappearing_ttl_minutes,
        &event.name,
    )?]))
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::types::event_id;

    use super::super::types::WorkspaceEvent;
    use super::*;

    #[test]
    fn projects_one_workspace_row_keyed_by_workspace_id() {
        let event = WorkspaceEvent {
            created_at_ms: 100,
            public_key: [3; 32],
            disappearing_ttl_minutes: 7,
            name: "Research".to_string(),
        };
        let bytes = codec::encode(&event).expect("encode workspace");
        let output = project(&bytes).expect("project workspace");

        assert_eq!(output.labels.len(), 0);
        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::WORKSPACES);
        assert_eq!(output.rows[0].key, event_id(&bytes));
    }
}

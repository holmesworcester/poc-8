//! Projector for dependency-cascade test events.
//!
//! Staged events write their inner shared event bytes into a local replay table.
//! Actual shared dependency events need no projection rows; their purpose is to
//! exercise admission, blocking, and unblocking in the common worker.

use crate::core::store::TableRow;
use crate::protocol::event_modules::worker::ProjectionOutput;

use super::codec;
use super::schema;

pub fn project(bytes: &[u8]) -> Result<ProjectionOutput, String> {
    if bytes.first().copied() == Some(codec::TYPE_STAGED_EVENT_WITH_DEPS) {
        let event = codec::decode_staged(bytes)?;
        return Ok(ProjectionOutput::rows(vec![TableRow {
            table: schema::STAGED_EVENTS_WITH_DEPS,
            key: event.index.to_be_bytes().to_vec(),
            value: event.inner_bytes,
        }]));
    }
    codec::decode(bytes)?;
    Ok(ProjectionOutput::default())
}

#[cfg(test)]
mod tests {
    use super::super::types::{EventWithDeps, StagedEventWithDeps, PAYLOAD_BYTES};
    use super::*;

    fn inner_bytes_fixture() -> Vec<u8> {
        codec::encode(&EventWithDeps {
            timestamp: 42,
            dependencies: vec![[1; 32], [2; 32]],
            payload: [7; PAYLOAD_BYTES],
        })
    }

    // Invariant: shared event projects no rows.
    #[test]
    fn shared_event_projects_no_rows() {
        let output = project(&inner_bytes_fixture()).expect("project shared");

        assert!(output.rows.is_empty());
        assert!(output.labels.is_empty());
    }

    // Invariant: staged event projects inner bytes by index.
    #[test]
    fn staged_event_projects_inner_bytes_by_index() {
        let inner_bytes = inner_bytes_fixture();
        let staged = codec::encode_staged(&StagedEventWithDeps {
            index: 17,
            inner_bytes: inner_bytes.clone(),
        });

        let output = project(&staged).expect("project staged");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, schema::STAGED_EVENTS_WITH_DEPS);
        assert_eq!(output.rows[0].key, 17u64.to_be_bytes());
        assert_eq!(output.rows[0].value, inner_bytes);
    }

    // Invariant: rejects malformed bytes.
    #[test]
    fn rejects_malformed_bytes() {
        let err = project(&[codec::TYPE_EVENT_WITH_DEPS]).expect_err("reject");

        assert!(err.contains("length mismatch"));
    }
}

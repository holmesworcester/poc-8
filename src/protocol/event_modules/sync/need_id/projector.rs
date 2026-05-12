//! Projector for sync need-id events.
//!
//! A locally proposed need-id is sent to the peer like any other
//! connection-scoped event. A received need-id becomes sync work; the sync
//! worker answers it by queuing the requested durable event id, not by
//! manufacturing a data packet.

use crate::protocol::event_modules::connection;
use crate::protocol::event_modules::types::{ConnectionScope, EventScope};
use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};
use crate::protocol::workers::schema as worker_schema;

use super::codec;

pub fn project(envelope: &EventWithContext<'_>) -> Result<ProjectionOutput, String> {
    let bytes = &envelope.record.canonical_bytes;
    let need = codec::decode(bytes)?;
    match envelope.record.scope {
        EventScope::Connection(ConnectionScope::Outgoing { connection_id }) => {
            ensure_connection(need.connection_id, connection_id)?;
            Ok(ProjectionOutput::rows(vec![
                connection::schema::connection_scoped_event_row(
                    envelope.context.event_id,
                    bytes.to_vec(),
                ),
                worker_schema::transit_out_row(connection_id, envelope.context.event_id),
            ]))
        }
        EventScope::Connection(ConnectionScope::Incoming { connection_id }) => {
            ensure_connection(need.connection_id, connection_id)?;
            Ok(ProjectionOutput::rows(vec![
                worker_schema::sync_in_event_row(
                    connection_id,
                    envelope.context.event_id,
                    bytes.to_vec(),
                ),
            ]))
        }
        _ => Err("sync need-id requires connection scope".to_string()),
    }
}

fn ensure_connection(actual: [u8; 32], scoped: [u8; 32]) -> Result<(), String> {
    if actual == scoped {
        Ok(())
    } else {
        Err("sync need-id connection scope mismatch".to_string())
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::connection;
    use crate::protocol::event_modules::types::{event_id, EventRecord};
    use crate::protocol::event_modules::worker::EventContext;
    use crate::protocol::workers::schema as worker_schema;

    use super::super::types::NeedIdEvent;
    use super::*;

    fn need_event() -> NeedIdEvent {
        NeedIdEvent {
            connection_id: [4; 32],
            id: [8; 32],
        }
    }

    fn context_for(record: &EventRecord) -> EventWithContext<'_> {
        EventWithContext {
            record,
            context: EventContext {
                event_id: event_id(&record.canonical_bytes),
                dependencies: Vec::new(),
                labels: Vec::new(),
                receive: None,
                now_unix_minute: None,
            },
        }
    }

    #[test]
    fn outgoing_need_id_projects_cached_event_and_transit_out_rows() {
        let record = codec::outbound_record(need_event()).expect("record");
        let output = project(&context_for(&record)).expect("project outgoing");

        assert_eq!(output.rows.len(), 2);
        assert_eq!(
            output.rows[0].table,
            connection::schema::CONNECTION_SCOPED_EVENTS
        );
        assert_eq!(output.rows[1].table, worker_schema::TRANSIT_OUT);
    }

    #[test]
    fn incoming_need_id_projects_inbound_sync_work_row() {
        let bytes = codec::encode(&need_event());
        let record = codec::inbound_record_from_wire(bytes).expect("record");
        let output = project(&context_for(&record)).expect("project incoming");

        assert_eq!(output.rows.len(), 1);
        assert_eq!(output.rows[0].table, worker_schema::SYNC_IN_EVENTS);
        assert_eq!(output.rows[0].value, record.canonical_bytes);
    }

    #[test]
    fn need_id_rejects_connection_scope_mismatch() {
        let mut record = codec::outbound_record(need_event()).expect("record");
        record.scope = EventScope::Connection(ConnectionScope::Outgoing {
            connection_id: [9; 32],
        });

        let err = project(&context_for(&record)).expect_err("reject");
        assert!(err.contains("connection scope mismatch"));
    }
}

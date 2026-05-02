use crate::event_modules::{LabelOp, OutboxOp, Projection, ProjectionContext, RowOp, SqlValue};
use crate::pipeline::EventId;

use super::codec::{SyncNeedEvent, TYPE_NAME};

pub const TABLE: &str = "
    CREATE TABLE IF NOT EXISTS sync_need (
        event_id BLOB PRIMARY KEY NOT NULL,
        workspace_id BLOB NOT NULL,
        connection_id BLOB NOT NULL,
        needed_event_id BLOB NOT NULL
    );
    ";

pub fn project(
    event_id: EventId,
    event: &SyncNeedEvent,
    context: &ProjectionContext,
) -> Projection {
    let mut projection = Projection {
        row_ops: vec![RowOp::upsert(
            "sync_need",
            &[
                "event_id",
                "workspace_id",
                "connection_id",
                "needed_event_id",
            ],
            vec![
                SqlValue::Blob(event_id.to_vec()),
                SqlValue::Blob(event.workspace_id.to_vec()),
                SqlValue::Blob(event.connection_id.to_vec()),
                SqlValue::Blob(event.needed_event_id.to_vec()),
            ],
        )],
        labels: vec![LabelOp {
            subject_event_id: event_id,
            label: TYPE_NAME.to_string(),
        }],
        ..Projection::default()
    };

    if Some(event.connection_id) != context.origin_connection_id {
        projection.outbox.push(OutboxOp {
            connection_id: event.connection_id,
            event_id,
        });
    }

    projection
}

use crate::pipeline::{ConnectionId, EventId, WorkspaceId};

use super::{LabelOp, OutboxOp, Projection, ProjectionContext, RowOp, SqlValue};

pub const TYPE_COMPARE: u8 = 4;
pub const TYPE_HAVE: u8 = 5;
pub const TYPE_NEED: u8 = 6;
pub const COMPARE_TYPE_NAME: &str = "sync_compare";
pub const HAVE_TYPE_NAME: &str = "sync_have";
pub const NEED_TYPE_NAME: &str = "sync_need";
pub const TABLES: &[&str] = &[
    "
    CREATE TABLE IF NOT EXISTS sync_compares (
        event_id BLOB PRIMARY KEY NOT NULL,
        workspace_id BLOB NOT NULL,
        connection_id BLOB NOT NULL,
        root BLOB NOT NULL
    );
    ",
    "
    CREATE TABLE IF NOT EXISTS sync_have (
        event_id BLOB PRIMARY KEY NOT NULL,
        workspace_id BLOB NOT NULL,
        connection_id BLOB NOT NULL,
        have_event_id BLOB NOT NULL
    );
    ",
    "
    CREATE TABLE IF NOT EXISTS sync_need (
        event_id BLOB PRIMARY KEY NOT NULL,
        workspace_id BLOB NOT NULL,
        connection_id BLOB NOT NULL,
        needed_event_id BLOB NOT NULL
    );
    ",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncCompareEvent {
    pub workspace_id: WorkspaceId,
    pub connection_id: ConnectionId,
    pub root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncHaveEvent {
    pub workspace_id: WorkspaceId,
    pub connection_id: ConnectionId,
    pub have_event_id: EventId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncNeedEvent {
    pub workspace_id: WorkspaceId,
    pub connection_id: ConnectionId,
    pub needed_event_id: EventId,
}

pub fn encode_sync_compare(
    workspace_id: WorkspaceId,
    connection_id: ConnectionId,
    root: [u8; 32],
) -> Vec<u8> {
    super::codec::encode_three_id_event(TYPE_COMPARE, workspace_id, connection_id, root)
}

pub fn encode_sync_have(
    workspace_id: WorkspaceId,
    connection_id: ConnectionId,
    have_event_id: EventId,
) -> Vec<u8> {
    super::codec::encode_three_id_event(TYPE_HAVE, workspace_id, connection_id, have_event_id)
}

pub fn encode_sync_need(
    workspace_id: WorkspaceId,
    connection_id: ConnectionId,
    needed_event_id: EventId,
) -> Vec<u8> {
    super::codec::encode_three_id_event(TYPE_NEED, workspace_id, connection_id, needed_event_id)
}

pub fn decode_compare(
    cursor: &mut super::codec::Cursor<'_>,
) -> Result<SyncCompareEvent, super::EventError> {
    let (workspace_id, connection_id, root) = cursor.three_ids()?;
    Ok(SyncCompareEvent {
        workspace_id,
        connection_id,
        root,
    })
}

pub fn decode_have(
    cursor: &mut super::codec::Cursor<'_>,
) -> Result<SyncHaveEvent, super::EventError> {
    let (workspace_id, connection_id, have_event_id) = cursor.three_ids()?;
    Ok(SyncHaveEvent {
        workspace_id,
        connection_id,
        have_event_id,
    })
}

pub fn decode_need(
    cursor: &mut super::codec::Cursor<'_>,
) -> Result<SyncNeedEvent, super::EventError> {
    let (workspace_id, connection_id, needed_event_id) = cursor.three_ids()?;
    Ok(SyncNeedEvent {
        workspace_id,
        connection_id,
        needed_event_id,
    })
}

pub fn project_compare(event_id: EventId, event: &SyncCompareEvent) -> Projection {
    Projection {
        row_ops: vec![RowOp::upsert(
            "sync_compares",
            &["event_id", "workspace_id", "connection_id", "root"],
            vec![
                SqlValue::Blob(event_id.to_vec()),
                SqlValue::Blob(event.workspace_id.to_vec()),
                SqlValue::Blob(event.connection_id.to_vec()),
                SqlValue::Blob(event.root.to_vec()),
            ],
        )],
        labels: vec![LabelOp {
            subject_event_id: event_id,
            label: COMPARE_TYPE_NAME.to_string(),
        }],
        ..Projection::default()
    }
}

pub fn project_have(event_id: EventId, event: &SyncHaveEvent) -> Projection {
    Projection {
        row_ops: vec![RowOp::upsert(
            "sync_have",
            &["event_id", "workspace_id", "connection_id", "have_event_id"],
            vec![
                SqlValue::Blob(event_id.to_vec()),
                SqlValue::Blob(event.workspace_id.to_vec()),
                SqlValue::Blob(event.connection_id.to_vec()),
                SqlValue::Blob(event.have_event_id.to_vec()),
            ],
        )],
        labels: vec![LabelOp {
            subject_event_id: event_id,
            label: HAVE_TYPE_NAME.to_string(),
        }],
        ..Projection::default()
    }
}

pub fn project_need(
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
            label: NEED_TYPE_NAME.to_string(),
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

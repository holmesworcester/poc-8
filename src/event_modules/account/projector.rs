use crate::event_modules::{LabelOp, Projection, RowOp, SqlValue};
use crate::pipeline::{EventId, WorkspaceId};

use super::codec::{AccountEvent, TYPE_NAME};

pub const TABLES: &[&str] = &[
    "
    CREATE TABLE IF NOT EXISTS accounts (
        account_id BLOB PRIMARY KEY NOT NULL,
        workspace_id BLOB NOT NULL,
        username TEXT NOT NULL,
        device_name TEXT NOT NULL,
        source_event_id BLOB NOT NULL
    );
    ",
    "CREATE INDEX IF NOT EXISTS idx_accounts_workspace ON accounts(workspace_id);",
];

pub fn account_row(
    account_id: [u8; 32],
    workspace_id: WorkspaceId,
    username: &str,
    device_name: &str,
    source_event_id: EventId,
) -> RowOp {
    RowOp::upsert(
        "accounts",
        &[
            "account_id",
            "workspace_id",
            "username",
            "device_name",
            "source_event_id",
        ],
        vec![
            SqlValue::Blob(account_id.to_vec()),
            SqlValue::Blob(workspace_id.to_vec()),
            SqlValue::Text(username.to_string()),
            SqlValue::Text(device_name.to_string()),
            SqlValue::Blob(source_event_id.to_vec()),
        ],
    )
}

pub fn project(event_id: EventId, event: &AccountEvent) -> Projection {
    Projection {
        row_ops: vec![account_row(
            event.account_id,
            event.workspace_id,
            &event.username,
            &event.device_name,
            event_id,
        )],
        labels: vec![LabelOp {
            subject_event_id: event_id,
            label: TYPE_NAME.to_string(),
        }],
        ..Projection::default()
    }
}

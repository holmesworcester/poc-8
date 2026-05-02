use crate::event_modules::{account, LabelOp, Projection, RowOp, SqlValue};
use crate::pipeline::EventId;

use super::codec::{InviteAcceptedEvent, InviteEvent, INVITE_ACCEPTED_TYPE_NAME, INVITE_TYPE_NAME};

pub const TABLES: &[&str] = &[
    "
    CREATE TABLE IF NOT EXISTS invites (
        event_id BLOB PRIMARY KEY NOT NULL,
        workspace_id BLOB NOT NULL,
        invite_id BLOB NOT NULL,
        source_event_id BLOB NOT NULL
    );
    ",
    "CREATE INDEX IF NOT EXISTS idx_invites_workspace ON invites(workspace_id);",
    "
    CREATE TABLE IF NOT EXISTS invite_acceptances (
        account_id BLOB PRIMARY KEY NOT NULL,
        workspace_id BLOB NOT NULL,
        invite_event_id BLOB NOT NULL,
        source_event_id BLOB NOT NULL
    );
    ",
    "CREATE INDEX IF NOT EXISTS idx_invite_acceptances_workspace ON invite_acceptances(workspace_id);",
];

pub fn project_invite(event_id: EventId, event: &InviteEvent) -> Projection {
    Projection {
        row_ops: vec![RowOp::upsert(
            "invites",
            &["event_id", "workspace_id", "invite_id", "source_event_id"],
            vec![
                SqlValue::Blob(event_id.to_vec()),
                SqlValue::Blob(event.workspace_id.to_vec()),
                SqlValue::Blob(event.invite_id.to_vec()),
                SqlValue::Blob(event_id.to_vec()),
            ],
        )],
        labels: vec![LabelOp {
            subject_event_id: event_id,
            label: INVITE_TYPE_NAME.to_string(),
        }],
        ..Projection::default()
    }
}

pub fn project_invite_accepted(event_id: EventId, event: &InviteAcceptedEvent) -> Projection {
    Projection {
        row_ops: vec![
            account::account_row(
                event.account_id,
                event.workspace_id,
                &event.username,
                &event.device_name,
                event_id,
            ),
            RowOp::upsert(
                "invite_acceptances",
                &[
                    "account_id",
                    "workspace_id",
                    "invite_event_id",
                    "source_event_id",
                ],
                vec![
                    SqlValue::Blob(event.account_id.to_vec()),
                    SqlValue::Blob(event.workspace_id.to_vec()),
                    SqlValue::Blob(event.invite_event_id.to_vec()),
                    SqlValue::Blob(event_id.to_vec()),
                ],
            ),
        ],
        labels: vec![LabelOp {
            subject_event_id: event_id,
            label: INVITE_ACCEPTED_TYPE_NAME.to_string(),
        }],
        ..Projection::default()
    }
}

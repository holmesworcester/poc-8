//! Schema and rows for projected user invites.
//!
//! Rows are keyed by `workspace_id || user_invite_id`, keeping invite authority
//! scoped to a workspace without recreating removed p7 scope state.

use crate::core::store::{Schema, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::{Reader, Writer};

use super::types::{UserInviteEvent, UserInviteRow};

pub const USER_INVITES: TableName = TableName::new("identity.user_invites");

pub const SCHEMAS: &[Schema] = &[Schema::durable_row_table(
    "identity.user_invites.v1",
    USER_INVITES,
)];

pub fn user_invite_key(workspace_id: &EventId, user_invite_id: &EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(workspace_id);
    key.extend_from_slice(user_invite_id);
    key
}

pub fn user_invite_row(user_invite_id: EventId, event: &UserInviteEvent) -> TableRow {
    TableRow {
        table: USER_INVITES,
        key: user_invite_key(&event.workspace_id, &user_invite_id),
        value: encode_user_invite_value(event),
    }
}

pub fn decode_user_invite_row(key: &[u8], value: &[u8]) -> Result<UserInviteRow, String> {
    let (workspace_id, user_invite_id) = decode_user_invite_key(key)?;
    let mut reader = Reader::new(value, "user_invite row");
    let created_at_ms = reader.u64()?;
    let public_key = reader.id()?;
    let authority_event_id = reader.id()?;
    reader.finish()?;
    Ok(UserInviteRow {
        workspace_id,
        user_invite_id,
        created_at_ms,
        public_key,
        authority_event_id,
    })
}

fn encode_user_invite_value(event: &UserInviteEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(8 + 32 + 32);
    out.u64(event.created_at_ms);
    out.id(&event.public_key);
    out.id(&event.authority_event_id);
    out.finish()
}

fn decode_user_invite_key(key: &[u8]) -> Result<(EventId, EventId), String> {
    if key.len() != 64 {
        return Err("user_invite row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    let mut user_invite_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    user_invite_id.copy_from_slice(&key[32..]);
    Ok((workspace_id, user_invite_id))
}

#[cfg(test)]
mod tests {
    use crate::core::store::Store;

    use super::*;

    fn event() -> UserInviteEvent {
        UserInviteEvent {
            created_at_ms: 5,
            public_key: [1; 32],
            workspace_id: [2; 32],
            authority_event_id: [2; 32],
        }
    }

    // Invariant: user invite rows decode to projected shape.
    #[test]
    fn user_invite_rows_decode_to_projected_shape() {
        let row = user_invite_row([9; 32], &event());

        assert_eq!(row.table, USER_INVITES);
        assert_eq!(row.key, user_invite_key(&[2; 32], &[9; 32]));
        assert_eq!(
            decode_user_invite_row(&row.key, &row.value).expect("decode row"),
            UserInviteRow {
                workspace_id: [2; 32],
                user_invite_id: [9; 32],
                created_at_ms: 5,
                public_key: [1; 32],
                authority_event_id: [2; 32],
            }
        );
    }

    // Invariant: duplicate user invite row insert is idempotent.
    #[test]
    fn duplicate_user_invite_row_insert_is_idempotent() {
        let row = user_invite_row([9; 32], &event());
        let store = Store::open_memory_with_schemas(SCHEMAS).expect("open store");

        assert_eq!(
            store
                .insert_table_rows(vec![row.clone()])
                .expect("insert row"),
            1
        );
        assert_eq!(
            store
                .insert_table_rows(vec![row])
                .expect("insert duplicate"),
            0
        );
    }
}

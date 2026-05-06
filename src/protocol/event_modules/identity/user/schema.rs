//! Schema and rows for projected users.
//!
//! User rows are keyed by `workspace_id || user_id`. The workspace id is
//! derived from the signer user-invite dependency during projection.

use crate::core::store::{Schema, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::{Reader, Writer};

use super::codec;
use super::types::{UserEvent, UserRow, USERNAME_BYTES};

pub const USERS: TableName = TableName::new("identity.users");

pub const SCHEMAS: &[Schema] = &[Schema::durable_row_table("identity.users.v1", USERS)];

pub fn user_key(workspace_id: &EventId, user_id: &EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(workspace_id);
    key.extend_from_slice(user_id);
    key
}

pub fn user_row(
    workspace_id: EventId,
    user_id: EventId,
    user_invite_id: EventId,
    event: &UserEvent,
) -> Result<TableRow, String> {
    Ok(TableRow {
        table: USERS,
        key: user_key(&workspace_id, &user_id),
        value: encode_user_value(user_invite_id, event)?,
    })
}

pub fn decode_user_row(key: &[u8], value: &[u8]) -> Result<UserRow, String> {
    let (workspace_id, user_id) = decode_user_key(key)?;
    let mut reader = Reader::new(value, "user row");
    let created_at_ms = reader.u64()?;
    let public_key = reader.id()?;
    let user_invite_id = reader.id()?;
    let username = codec::decode_username(reader.slice(USERNAME_BYTES)?)?;
    reader.finish()?;
    Ok(UserRow {
        workspace_id,
        user_id,
        user_invite_id,
        created_at_ms,
        public_key,
        username,
    })
}

fn encode_user_value(user_invite_id: EventId, event: &UserEvent) -> Result<Vec<u8>, String> {
    let username = codec::encode_username(&event.username)?;
    let mut out = Writer::with_capacity(8 + 32 + 32 + USERNAME_BYTES);
    out.u64(event.created_at_ms);
    out.id(&event.public_key);
    out.id(&user_invite_id);
    out.raw(&username);
    Ok(out.finish())
}

fn decode_user_key(key: &[u8]) -> Result<(EventId, EventId), String> {
    if key.len() != 64 {
        return Err("user row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    let mut user_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    user_id.copy_from_slice(&key[32..]);
    Ok((workspace_id, user_id))
}

#[cfg(test)]
mod tests {
    use crate::core::store::Store;

    use super::*;

    fn event() -> UserEvent {
        UserEvent {
            created_at_ms: 6,
            workspace_id: [2; 32],
            public_key: [1; 32],
            username: "alice".to_string(),
        }
    }

    // Invariant: user rows decode to projected shape.
    #[test]
    fn user_rows_decode_to_projected_shape() {
        let row = user_row([2; 32], [9; 32], [5; 32], &event()).expect("user row");

        assert_eq!(row.table, USERS);
        assert_eq!(row.key, user_key(&[2; 32], &[9; 32]));
        assert_eq!(
            decode_user_row(&row.key, &row.value).expect("decode row"),
            UserRow {
                workspace_id: [2; 32],
                user_id: [9; 32],
                user_invite_id: [5; 32],
                created_at_ms: 6,
                public_key: [1; 32],
                username: "alice".to_string(),
            }
        );
    }

    // Invariant: duplicate user row insert is idempotent.
    #[test]
    fn duplicate_user_row_insert_is_idempotent() {
        let row = user_row([2; 32], [9; 32], [5; 32], &event()).expect("user row");
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

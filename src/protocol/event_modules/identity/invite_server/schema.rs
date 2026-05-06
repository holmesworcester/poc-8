//! Schema and rows for projected invite-server invites.
//!
//! Rows are keyed by `workspace_id || invite_server_id` and store the published
//! invite public key plus the authority event that signed it. This table is a
//! durable identity fact; it does not store private invite secrets or transport
//! listener state.

use crate::core::store::{Schema, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::{Reader, Writer};

use super::types::{InviteServerEvent, InviteServerRow};

pub const INVITE_SERVERS: TableName = TableName::new("identity.invite_servers");

pub const SCHEMAS: &[Schema] = &[Schema::durable_row_table(
    "identity.invite_servers.v1",
    INVITE_SERVERS,
)];

pub fn invite_server_key(workspace_id: &EventId, invite_server_id: &EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(workspace_id);
    key.extend_from_slice(invite_server_id);
    key
}

pub fn invite_server_row(invite_server_id: EventId, event: &InviteServerEvent) -> TableRow {
    TableRow {
        table: INVITE_SERVERS,
        key: invite_server_key(&event.workspace_id, &invite_server_id),
        value: encode_invite_server_value(event),
    }
}

pub fn decode_invite_server_row(key: &[u8], value: &[u8]) -> Result<InviteServerRow, String> {
    let (workspace_id, invite_server_id) = decode_invite_server_key(key)?;
    let mut reader = Reader::new(value, "invite_server row");
    let created_at_ms = reader.u64()?;
    let public_key = reader.id()?;
    let authority_event_id = reader.id()?;
    reader.finish()?;
    Ok(InviteServerRow {
        workspace_id,
        invite_server_id,
        created_at_ms,
        public_key,
        authority_event_id,
    })
}

fn encode_invite_server_value(event: &InviteServerEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(8 + 32 + 32);
    out.u64(event.created_at_ms);
    out.id(&event.public_key);
    out.id(&event.authority_event_id);
    out.finish()
}

fn decode_invite_server_key(key: &[u8]) -> Result<(EventId, EventId), String> {
    if key.len() != 64 {
        return Err("invite_server row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    let mut invite_server_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    invite_server_id.copy_from_slice(&key[32..]);
    Ok((workspace_id, invite_server_id))
}

#[cfg(test)]
mod tests {
    use crate::core::store::Store;

    use super::*;

    fn event() -> InviteServerEvent {
        InviteServerEvent {
            created_at_ms: 5,
            public_key: [1; 32],
            workspace_id: [2; 32],
            authority_event_id: [2; 32],
        }
    }

    #[test]
    fn invite_server_rows_decode_to_projected_shape() {
        let row = invite_server_row([9; 32], &event());

        assert_eq!(row.table, INVITE_SERVERS);
        assert_eq!(row.key, invite_server_key(&[2; 32], &[9; 32]));
        assert_eq!(
            decode_invite_server_row(&row.key, &row.value).expect("decode row"),
            InviteServerRow {
                workspace_id: [2; 32],
                invite_server_id: [9; 32],
                created_at_ms: 5,
                public_key: [1; 32],
                authority_event_id: [2; 32],
            }
        );
    }

    #[test]
    fn duplicate_invite_server_row_insert_is_idempotent() {
        let row = invite_server_row([9; 32], &event());
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

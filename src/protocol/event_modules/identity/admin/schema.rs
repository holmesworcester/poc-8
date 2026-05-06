//! Schema and row helpers for admin projection rows.
//!
//! `identity.admins` is keyed by `workspace_id || admin_id`, so the same admin
//! event id in another workspace cannot collide.

use crate::core::store::{Schema, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::{Reader, Writer};

use super::super::workspace::types::WorkspaceId;
use super::types::{AdminPublicKey, AdminRow};

pub const ADMINS: TableName = TableName::new("identity.admins");

pub const SCHEMAS: &[Schema] = &[Schema::durable_row_table("identity.admins.v1", ADMINS)];

pub fn admin_row(
    workspace_id: WorkspaceId,
    admin_id: EventId,
    created_at_ms: u64,
    public_key: AdminPublicKey,
    authority_event_id: EventId,
    user_event_id: EventId,
) -> TableRow {
    TableRow {
        table: ADMINS,
        key: admin_key(&workspace_id, &admin_id),
        value: encode_admin_value(created_at_ms, public_key, authority_event_id, user_event_id),
    }
}

pub fn admin_key(workspace_id: &WorkspaceId, admin_id: &EventId) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(workspace_id);
    out.extend_from_slice(admin_id);
    out
}

pub fn decode_admin_row(key: &[u8], value: &[u8]) -> Result<AdminRow, String> {
    if key.len() != 64 {
        return Err("admin row key is malformed".to_string());
    }
    let workspace_id = id_from_slice(&key[..32], "admin row workspace id")?;
    let admin_id = id_from_slice(&key[32..], "admin row admin id")?;

    let mut reader = Reader::new(value, "admin row");
    let row = AdminRow {
        workspace_id,
        admin_id,
        created_at_ms: reader.u64()?,
        public_key: reader.id()?,
        authority_event_id: reader.id()?,
        user_event_id: reader.id()?,
    };
    reader.finish()?;
    Ok(row)
}

fn encode_admin_value(
    created_at_ms: u64,
    public_key: AdminPublicKey,
    authority_event_id: EventId,
    user_event_id: EventId,
) -> Vec<u8> {
    let mut out = Writer::with_capacity(8 + (32 * 3));
    out.u64(created_at_ms);
    out.id(&public_key);
    out.id(&authority_event_id);
    out.id(&user_event_id);
    out.finish()
}

fn id_from_slice(bytes: &[u8], label: &'static str) -> Result<EventId, String> {
    if bytes.len() != 32 {
        return Err(format!("{label} is malformed"));
    }
    let mut out = [0; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use crate::core::store::Store;

    use super::*;

    // Invariant: admin rows decode to projected shape.
    #[test]
    fn admin_rows_decode_to_projected_shape() {
        let row = admin_row([1; 32], [2; 32], 9, [3; 32], [4; 32], [5; 32]);

        assert_eq!(row.table, ADMINS);
        assert_eq!(row.key, [[1; 32], [2; 32]].concat());

        let decoded = decode_admin_row(&row.key, &row.value).expect("decode row");
        assert_eq!(
            decoded,
            AdminRow {
                workspace_id: [1; 32],
                admin_id: [2; 32],
                created_at_ms: 9,
                public_key: [3; 32],
                authority_event_id: [4; 32],
                user_event_id: [5; 32],
            }
        );
    }

    // Invariant: duplicate admin row insert is idempotent.
    #[test]
    fn duplicate_admin_row_insert_is_idempotent() {
        let row = admin_row([1; 32], [2; 32], 9, [3; 32], [4; 32], [5; 32]);
        let store = Store::open_memory_with_schemas(SCHEMAS).expect("open store");

        assert_eq!(
            store
                .insert_table_rows(vec![row.clone()])
                .expect("insert admin row"),
            1
        );
        assert_eq!(
            store
                .insert_table_rows(vec![row])
                .expect("insert duplicate admin row"),
            0
        );
    }
}

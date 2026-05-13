//! Schema and row helpers for workspace projection rows.
//!
//! `identity.workspaces` is keyed by workspace id, which is the deterministic
//! event id of the workspace event. Values are fixed-width where possible and
//! reuse the workspace name slot from the canonical event.

use crate::core::store::{Schema, TableName, TableRow};
use crate::protocol::wire::{Reader, Writer};

use super::codec;
use super::types::{WorkspaceId, WorkspacePublicKey, WorkspaceRow, WORKSPACE_NAME_BYTES};

pub const WORKSPACES: TableName = TableName::new("identity.workspaces");

pub const SCHEMAS: &[Schema] = &[Schema::durable_row_table(
    "identity.workspaces.v2",
    WORKSPACES,
)];

const WORKSPACE_VALUE_BYTES: usize = 8 + 32 + 4 + WORKSPACE_NAME_BYTES;

pub fn workspace_row(
    workspace_id: WorkspaceId,
    created_at_ms: u64,
    public_key: WorkspacePublicKey,
    disappearing_ttl_minutes: u32,
    name: &str,
) -> Result<TableRow, String> {
    Ok(TableRow {
        table: WORKSPACES,
        key: workspace_id.to_vec(),
        value: encode_workspace_value(created_at_ms, public_key, disappearing_ttl_minutes, name)?,
    })
}

pub fn decode_workspace_row(key: &[u8], value: &[u8]) -> Result<WorkspaceRow, String> {
    if key.len() != 32 {
        return Err("workspace row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(key);

    let mut reader = Reader::new(value, "workspace row");
    let created_at_ms = reader.u64()?;
    let public_key = reader.id()?;
    let disappearing_ttl_minutes = reader.u32()?;
    let name = workspace_value_name(reader.slice(WORKSPACE_NAME_BYTES)?)?;
    reader.finish()?;

    Ok(WorkspaceRow {
        workspace_id,
        created_at_ms,
        public_key,
        disappearing_ttl_minutes,
        name,
    })
}

fn encode_workspace_value(
    created_at_ms: u64,
    public_key: WorkspacePublicKey,
    disappearing_ttl_minutes: u32,
    name: &str,
) -> Result<Vec<u8>, String> {
    let event = super::types::WorkspaceEvent {
        created_at_ms,
        public_key,
        disappearing_ttl_minutes,
        name: name.to_string(),
    };
    let encoded = codec::encode(&event)?;
    let mut reader = Reader::new(&encoded, "workspace value source");
    let tag = reader.u8()?;
    if tag != codec::TYPE_WORKSPACE {
        return Err("workspace value source has wrong type".to_string());
    }
    let value = reader.slice(WORKSPACE_VALUE_BYTES)?.to_vec();
    reader.finish()?;

    let mut out = Writer::with_capacity(WORKSPACE_VALUE_BYTES);
    out.raw(&value);
    Ok(out.finish())
}

fn workspace_value_name(bytes: &[u8]) -> Result<String, String> {
    let encoded = {
        let mut out = Writer::with_capacity(codec::WORKSPACE_WIRE_SIZE);
        out.u8(codec::TYPE_WORKSPACE);
        out.u64(0);
        out.id(&[0; 32]);
        out.u32(0);
        out.raw(bytes);
        out.finish()
    };
    codec::decode(&encoded).map(|event| event.name)
}

#[cfg(test)]
mod tests {
    use crate::core::store::Store;

    use super::*;

    #[test]
    fn workspace_rows_decode_to_projected_shape() {
        let row = workspace_row([1; 32], 9, [2; 32], 3, "Ops").expect("workspace row");
        assert_eq!(row.table, WORKSPACES);
        assert_eq!(row.key, [1; 32]);

        let decoded = decode_workspace_row(&row.key, &row.value).expect("decode row");
        assert_eq!(
            decoded,
            WorkspaceRow {
                workspace_id: [1; 32],
                created_at_ms: 9,
                public_key: [2; 32],
                disappearing_ttl_minutes: 3,
                name: "Ops".to_string(),
            }
        );
    }

    #[test]
    fn duplicate_workspace_row_insert_is_idempotent() {
        let row = workspace_row([3; 32], 10, [4; 32], 0, "Product").expect("workspace row");
        let store = Store::open_memory_with_schemas(SCHEMAS).expect("open store");

        assert_eq!(
            store
                .insert_table_rows(vec![row.clone()])
                .expect("insert workspace row"),
            1
        );
        assert_eq!(
            store
                .insert_table_rows(vec![row])
                .expect("insert duplicate workspace row"),
            0
        );
    }
}

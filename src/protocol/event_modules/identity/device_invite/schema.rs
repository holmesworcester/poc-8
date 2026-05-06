//! Schema and row helpers for device-invite projections.
//!
//! `identity.device_invites` is keyed by `workspace_id || device_invite_id` so
//! workspace scans remain local to this module-owned table.

use crate::core::store::{Schema, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::{Reader, Writer};

use super::types::{DeviceInviteEvent, DeviceInviteRow};

pub const DEVICE_INVITES: TableName = TableName::new("identity.device_invites");

pub const SCHEMAS: &[Schema] = &[Schema::durable_row_table(
    "identity.device_invites.v1",
    DEVICE_INVITES,
)];

pub fn device_invite_key(workspace_id: EventId, device_invite_id: EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&device_invite_id);
    key
}

pub fn device_invite_row(
    device_invite_id: EventId,
    event: &DeviceInviteEvent,
) -> Result<TableRow, String> {
    Ok(TableRow {
        table: DEVICE_INVITES,
        key: device_invite_key(event.workspace_id, device_invite_id),
        value: encode_device_invite_value(event),
    })
}

pub fn decode_device_invite_row(key: &[u8], value: &[u8]) -> Result<DeviceInviteRow, String> {
    if key.len() != 64 {
        return Err("device invite row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut device_invite_id = [0; 32];
    device_invite_id.copy_from_slice(&key[32..64]);

    let mut reader = Reader::new(value, "device invite row");
    let created_at_ms = reader.u64()?;
    let user_authority_event_id = reader.id()?;
    let user_invite_event_id = optional_event_id(reader.id()?);
    let public_key = reader.id()?;
    reader.finish()?;

    Ok(DeviceInviteRow {
        workspace_id,
        device_invite_id,
        created_at_ms,
        user_authority_event_id,
        user_invite_event_id,
        public_key,
    })
}

fn encode_device_invite_value(event: &DeviceInviteEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(8 + 32 + 32 + 32);
    out.u64(event.created_at_ms);
    out.id(&event.user_authority_event_id);
    out.id(&event.user_invite_event_id.unwrap_or([0; 32]));
    out.id(&event.public_key);
    out.finish()
}

fn optional_event_id(id: EventId) -> Option<EventId> {
    if id.iter().all(|byte| *byte == 0) {
        None
    } else {
        Some(id)
    }
}

#[cfg(test)]
mod tests {
    use crate::core::store::Store;

    use super::*;

    fn event() -> DeviceInviteEvent {
        DeviceInviteEvent {
            created_at_ms: 22,
            workspace_id: [1; 32],
            user_authority_event_id: [2; 32],
            user_invite_event_id: Some([5; 32]),
            public_key: [3; 32],
        }
    }

    // Invariant: device invite rows decode to projected shape.
    #[test]
    fn device_invite_rows_decode_to_projected_shape() {
        let row = device_invite_row([4; 32], &event()).expect("row");

        assert_eq!(row.table, DEVICE_INVITES);
        assert_eq!(row.key, device_invite_key([1; 32], [4; 32]));
        assert_eq!(
            decode_device_invite_row(&row.key, &row.value).expect("decode row"),
            DeviceInviteRow {
                workspace_id: [1; 32],
                device_invite_id: [4; 32],
                created_at_ms: 22,
                user_authority_event_id: [2; 32],
                user_invite_event_id: Some([5; 32]),
                public_key: [3; 32],
            }
        );
    }

    // Invariant: duplicate device invite row insert is idempotent.
    #[test]
    fn duplicate_device_invite_row_insert_is_idempotent() {
        let row = device_invite_row([4; 32], &event()).expect("row");
        let store = Store::open_memory_with_schemas(SCHEMAS).expect("open store");

        assert_eq!(
            store
                .insert_table_rows(vec![row.clone()])
                .expect("insert row"),
            1
        );
        assert_eq!(store.insert_table_rows(vec![row]).expect("insert row"), 0);
    }
}

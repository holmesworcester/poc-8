//! Schema for removal frontier rows.

use crate::core::store::{Schema, Store, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::{Reader, Writer};

use super::types::{RemovalFrontierEvent, RemovalFrontierRow, MAX_REMOVAL_FRONTIER_REFS};

pub const REMOVAL_FRONTIERS: TableName = TableName::new("encryption.removal_frontiers");

pub const SCHEMAS: &[Schema] = &[Schema::durable_row_table(
    "encryption.removal_frontiers.v1",
    REMOVAL_FRONTIERS,
)];

pub fn removal_frontier_row(
    removal_frontier_id: EventId,
    event: &RemovalFrontierEvent,
) -> Result<TableRow, String> {
    Ok(TableRow {
        table: REMOVAL_FRONTIERS,
        key: removal_frontier_key(event.workspace_id, removal_frontier_id),
        value: encode_value(event)?,
    })
}

pub fn removal_frontier_key(workspace_id: EventId, removal_frontier_id: EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&removal_frontier_id);
    key
}

pub fn get(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
) -> Result<Option<RemovalFrontierRow>, String> {
    let key = removal_frontier_key(workspace_id, removal_frontier_id);
    store
        .table_row(REMOVAL_FRONTIERS, &key)
        .map_err(|err| format!("load removal frontier: {err}"))?
        .map(|value| decode_removal_frontier_row(&key, &value))
        .transpose()
}

pub fn list_for_workspace(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<RemovalFrontierRow>, String> {
    store
        .table_rows_with_key_prefix(REMOVAL_FRONTIERS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load removal frontiers: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_removal_frontier_row(&key, &value))
        .collect()
}

pub fn decode_removal_frontier_row(key: &[u8], value: &[u8]) -> Result<RemovalFrontierRow, String> {
    if key.len() != 64 {
        return Err("removal frontier row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut removal_frontier_id = [0; 32];
    removal_frontier_id.copy_from_slice(&key[32..64]);

    let mut reader = Reader::new(value, "removal frontier row");
    let created_at_ms = reader.u64()?;
    let authority_admin_id = reader.id()?;
    let count = usize::from(reader.u8()?);
    if count > MAX_REMOVAL_FRONTIER_REFS {
        return Err("removal frontier row has too many refs".to_string());
    }
    let mut removal_event_ids = Vec::with_capacity(count);
    for idx in 0..MAX_REMOVAL_FRONTIER_REFS {
        let id = reader.id()?;
        if idx < count {
            removal_event_ids.push(id);
        } else if id.iter().any(|byte| *byte != 0) {
            return Err("removal frontier row unused ref slots must be empty".to_string());
        }
    }
    reader.finish()?;
    Ok(RemovalFrontierRow {
        workspace_id,
        removal_frontier_id,
        created_at_ms,
        authority_admin_id,
        removal_event_ids,
    })
}

fn encode_value(event: &RemovalFrontierEvent) -> Result<Vec<u8>, String> {
    if event.removal_event_ids.len() > MAX_REMOVAL_FRONTIER_REFS {
        return Err("removal frontier row has too many refs".to_string());
    }
    let mut out = Writer::with_capacity(8 + 32 + 1 + (32 * MAX_REMOVAL_FRONTIER_REFS));
    out.u64(event.created_at_ms);
    out.id(&event.authority_admin_id);
    out.u8(u8::try_from(event.removal_event_ids.len())
        .map_err(|_| "removal frontier row has too many refs".to_string())?);
    for id in &event.removal_event_ids {
        out.id(id);
    }
    for _ in event.removal_event_ids.len()..MAX_REMOVAL_FRONTIER_REFS {
        out.id(&[0; 32]);
    }
    Ok(out.finish())
}

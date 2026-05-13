//! Schema for the workspace `disappearing_messages_setting` history.
//!
//! Each admitted setting event projects one row keyed by
//! `(workspace_id, created_at_ms_be, setting_event_id)`. The "active"
//! setting for a workspace is the row with the highest `created_at_ms`
//! (ties broken by event id), found via a single bounded prefix scan in
//! `queries::active_for_workspace`.
//!
//! Storing each setting as its own row makes projection
//! order-independent: a late-arriving older setting just appears as an
//! earlier row in the prefix scan and never overwrites a newer one.

use crate::core::store::{Schema, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::{Reader, Writer};

use super::types::ActiveSettingRow;

pub const SETTINGS: TableName = TableName::new("encryption.disappearing_messages_settings");

/// Per-workspace + per-frontier table tracking the highest `floor_minute`
/// the local `disappearing_floor_dispatcher` worker has already chopped.
/// Local-only (never propagated): the value is deterministic given the
/// chain of admitted settings and the local clock state, so all peers
/// converge independently.
///
/// Keyed by `workspace_id || removal_frontier_id` (32 + 32 bytes).
/// Value: 8 BE bytes encoding `last_chopped_floor: u64`.
pub const WORKSPACE_CHOP_FLOOR: TableName = TableName::new("encryption.workspace_chop_floor");

pub const SCHEMAS: &[Schema] = &[
    Schema::durable_row_table(
        "encryption.disappearing_messages_settings.v1",
        SETTINGS,
    ),
    Schema::durable_row_table(
        "encryption.workspace_chop_floor.v1",
        WORKSPACE_CHOP_FLOOR,
    ),
];

const KEY_BYTES: usize = 32 + 8 + 32;
const VALUE_BYTES: usize = 4 + 8 + 8;

pub fn setting_row(
    workspace_id: EventId,
    setting_event_id: EventId,
    ttl_minutes: u32,
    effective_at_minute: u64,
    created_at_ms: u64,
    expires_at_or_before_minute: u64,
) -> TableRow {
    let mut key = Vec::with_capacity(KEY_BYTES);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&created_at_ms.to_be_bytes());
    key.extend_from_slice(&setting_event_id);
    let mut value = Writer::with_capacity(VALUE_BYTES);
    value.u32(ttl_minutes as usize);
    value.u64(effective_at_minute);
    value.u64(expires_at_or_before_minute);
    TableRow {
        table: SETTINGS,
        key,
        value: value.finish(),
    }
}

pub fn decode_active_setting_row(key: &[u8], value: &[u8]) -> Result<ActiveSettingRow, String> {
    if key.len() != KEY_BYTES {
        return Err("disappearing setting row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut created_at_be = [0; 8];
    created_at_be.copy_from_slice(&key[32..40]);
    let created_at_ms = u64::from_be_bytes(created_at_be);
    let mut setting_event_id = [0; 32];
    setting_event_id.copy_from_slice(&key[40..72]);
    let mut reader = Reader::new(value, "disappearing setting row");
    let ttl_minutes = reader.u32()?;
    let effective_at_minute = reader.u64()?;
    let expires_at_or_before_minute = reader.u64()?;
    reader.finish()?;
    Ok(ActiveSettingRow {
        workspace_id,
        setting_event_id,
        ttl_minutes,
        effective_at_minute,
        created_at_ms,
        expires_at_or_before_minute,
    })
}

pub const CHOP_FLOOR_KEY_BYTES: usize = 64;
pub const CHOP_FLOOR_VALUE_BYTES: usize = 8;

pub fn chop_floor_key(workspace_id: EventId, removal_frontier_id: EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(CHOP_FLOOR_KEY_BYTES);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&removal_frontier_id);
    key
}

/// Encode a chop-floor row for direct insertion. The dispatcher writes
/// these through the worker's own transaction (no schema-level upsert
/// helper): the row constructor stays pure, ownership of the persistence
/// step lives with the worker that advances the floor.
pub fn chop_floor_row(
    workspace_id: EventId,
    removal_frontier_id: EventId,
    last_chopped_floor: u64,
) -> TableRow {
    TableRow {
        table: WORKSPACE_CHOP_FLOOR,
        key: chop_floor_key(workspace_id, removal_frontier_id),
        value: last_chopped_floor.to_be_bytes().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_floor_value() {
        let row = setting_row([1; 32], [2; 32], 5, 100, 6_000_000, 77);
        let decoded = decode_active_setting_row(&row.key, &row.value).expect("decode");
        assert_eq!(decoded.expires_at_or_before_minute, 77);
        assert_eq!(decoded.ttl_minutes, 5);
        assert_eq!(decoded.effective_at_minute, 100);
    }

    #[test]
    fn setting_rows_for_same_workspace_sort_by_created_at_ms_then_event_id() {
        // Larger `created_at_ms` and then larger `event_id` are the
        // tiebreakers `queries::active_for_workspace` uses to select the
        // active setting. The schema test asserts the storage encoding
        // makes that prefix scan order match the conceptual ordering.
        let earlier = setting_row([1; 32], [2; 32], 5, 100, 6_000_000, 0);
        let tied_lower_id = setting_row([1; 32], [3; 32], 7, 200, 12_000_000, 0);
        let tied_higher_id = setting_row([1; 32], [9; 32], 7, 200, 12_000_000, 0);
        assert!(earlier.key < tied_lower_id.key);
        assert!(tied_lower_id.key < tied_higher_id.key);
        // All three share the workspace prefix so a `table_rows_with_key_prefix`
        // scan covers them together.
        assert_eq!(&earlier.key[..32], &[1; 32]);
        assert_eq!(&tied_higher_id.key[..32], &[1; 32]);
    }

    #[test]
    fn chop_floor_row_round_trips_key_and_value() {
        let row = chop_floor_row([1; 32], [2; 32], 12_345);
        assert_eq!(row.table, WORKSPACE_CHOP_FLOOR);
        assert_eq!(row.key.len(), CHOP_FLOOR_KEY_BYTES);
        assert_eq!(&row.key[..32], &[1; 32]);
        assert_eq!(&row.key[32..], &[2; 32]);
        assert_eq!(row.value, 12_345u64.to_be_bytes().to_vec());
    }
}

//! Schema for the workspace `disappearing_messages_setting` history.
//!
//! Each admitted setting event projects one row keyed by
//! `(workspace_id, created_at_ms_be, setting_event_id)`. The "active"
//! setting for a workspace is the row with the highest `created_at_ms`
//! (ties broken by event id), found via a single bounded prefix scan.
//!
//! Storing each setting as its own row makes projection
//! order-independent: a late-arriving older setting just appears as an
//! earlier row in the prefix scan and never overwrites a newer one.

use crate::core::store::{Schema, Store, TableName, TableRow};
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

/// Return the active (latest by `(created_at_ms, event_id)`) setting for a
/// workspace, or `None` if no setting has been admitted yet.
pub fn active_for_workspace(
    store: &Store,
    workspace_id: EventId,
) -> Result<Option<ActiveSettingRow>, String> {
    let rows = store
        .table_rows_with_key_prefix(SETTINGS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load disappearing settings: {err}"))?;
    let mut latest: Option<ActiveSettingRow> = None;
    for (key, value) in rows {
        let row = decode_active_setting_row(&key, &value)?;
        latest = match latest {
            None => Some(row),
            Some(prev) => Some(pick_later(prev, row)),
        };
    }
    Ok(latest)
}

fn pick_later(a: ActiveSettingRow, b: ActiveSettingRow) -> ActiveSettingRow {
    if (b.created_at_ms, b.setting_event_id) > (a.created_at_ms, a.setting_event_id) {
        b
    } else {
        a
    }
}

const CHOP_FLOOR_KEY_BYTES: usize = 64;
const CHOP_FLOOR_VALUE_BYTES: usize = 8;

fn chop_floor_key(workspace_id: EventId, removal_frontier_id: EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(CHOP_FLOOR_KEY_BYTES);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&removal_frontier_id);
    key
}

/// Encode a chop-floor row for direct insertion. Most callers should go
/// through `upsert_last_chopped_floor`; this helper is exported for the
/// dispatcher and tests that need to inspect the row shape.
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

/// Read the highest `floor_minute` already chopped for this workspace +
/// frontier. `None` means no chop has run yet (treated as 0 by the
/// dispatcher).
pub fn get_last_chopped_floor(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
) -> Result<Option<u64>, String> {
    let key = chop_floor_key(workspace_id, removal_frontier_id);
    let Some(value) = store
        .table_row(WORKSPACE_CHOP_FLOOR, &key)
        .map_err(|err| format!("load workspace chop floor: {err}"))?
    else {
        return Ok(None);
    };
    let bytes: [u8; CHOP_FLOOR_VALUE_BYTES] = value
        .as_slice()
        .try_into()
        .map_err(|_| "workspace chop floor row value must be 8 bytes".to_string())?;
    Ok(Some(u64::from_be_bytes(bytes)))
}

/// Persist a new last-chopped-floor for this workspace + frontier. Idempotent
/// in `floor_minute` because the dispatcher guards `floor > last_chopped`
/// before calling, but uses replace semantics so a same-value write is a
/// no-op rather than a duplicate-row error.
pub fn upsert_last_chopped_floor(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    last_chopped_floor: u64,
) -> Result<(), String> {
    store
        .write_transaction(|tx_store| {
            tx_store.replace_table_rows_in_tx(vec![chop_floor_row(
                workspace_id,
                removal_frontier_id,
                last_chopped_floor,
            )])
        })
        .map_err(|err| format!("upsert workspace chop floor: {err}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_returns_latest_under_lexicographic_tiebreak() {
        let store = Store::open_memory_with_schemas(SCHEMAS).expect("open store");
        let row_a = setting_row([1; 32], [2; 32], 5, 100, 6_000_000, 0);
        let row_b = setting_row([1; 32], [9; 32], 7, 200, 12_000_000, 0);
        let row_c = setting_row([1; 32], [3; 32], 3, 200, 12_000_000, 0);
        store
            .insert_table_rows(vec![row_a, row_b, row_c])
            .expect("insert");
        let active = active_for_workspace(&store, [1; 32])
            .expect("active")
            .expect("active row exists");
        assert_eq!(active.ttl_minutes, 7);
        assert_eq!(active.setting_event_id, [9; 32]);
        assert_eq!(active.created_at_ms, 12_000_000);
    }

    #[test]
    fn active_returns_none_when_no_settings_admitted() {
        let store = Store::open_memory_with_schemas(SCHEMAS).expect("open store");
        assert!(active_for_workspace(&store, [1; 32])
            .expect("active")
            .is_none());
    }

    #[test]
    fn active_is_workspace_scoped() {
        let store = Store::open_memory_with_schemas(SCHEMAS).expect("open store");
        store
            .insert_table_rows(vec![setting_row([1; 32], [2; 32], 5, 100, 6_000_000, 0)])
            .expect("insert");
        assert!(active_for_workspace(&store, [9; 32])
            .expect("active")
            .is_none());
    }

    #[test]
    fn round_trips_floor_value() {
        let row = setting_row([1; 32], [2; 32], 5, 100, 6_000_000, 77);
        let decoded = decode_active_setting_row(&row.key, &row.value).expect("decode");
        assert_eq!(decoded.expires_at_or_before_minute, 77);
        assert_eq!(decoded.ttl_minutes, 5);
        assert_eq!(decoded.effective_at_minute, 100);
    }

    #[test]
    fn chop_floor_round_trips_through_get_after_upsert() {
        let store = Store::open_memory_with_schemas(SCHEMAS).expect("open store");
        assert_eq!(
            get_last_chopped_floor(&store, [1; 32], [2; 32]).expect("get"),
            None,
            "no row yet means None"
        );
        upsert_last_chopped_floor(&store, [1; 32], [2; 32], 12_345)
            .expect("upsert initial floor");
        assert_eq!(
            get_last_chopped_floor(&store, [1; 32], [2; 32]).expect("get"),
            Some(12_345)
        );
    }

    #[test]
    fn chop_floor_upsert_overwrites_existing_row() {
        let store = Store::open_memory_with_schemas(SCHEMAS).expect("open store");
        upsert_last_chopped_floor(&store, [1; 32], [2; 32], 100).expect("first upsert");
        upsert_last_chopped_floor(&store, [1; 32], [2; 32], 250).expect("second upsert");
        assert_eq!(
            get_last_chopped_floor(&store, [1; 32], [2; 32]).expect("get"),
            Some(250),
            "second upsert must overwrite the first (caller enforces monotonicity)"
        );
    }

    #[test]
    fn chop_floor_is_keyed_by_workspace_and_frontier() {
        let store = Store::open_memory_with_schemas(SCHEMAS).expect("open store");
        upsert_last_chopped_floor(&store, [1; 32], [2; 32], 100).expect("ws1+f2");
        upsert_last_chopped_floor(&store, [1; 32], [3; 32], 200).expect("ws1+f3");
        upsert_last_chopped_floor(&store, [9; 32], [2; 32], 300).expect("ws9+f2");
        assert_eq!(
            get_last_chopped_floor(&store, [1; 32], [2; 32]).expect("get"),
            Some(100)
        );
        assert_eq!(
            get_last_chopped_floor(&store, [1; 32], [3; 32]).expect("get"),
            Some(200)
        );
        assert_eq!(
            get_last_chopped_floor(&store, [9; 32], [2; 32]).expect("get"),
            Some(300)
        );
        assert_eq!(
            get_last_chopped_floor(&store, [9; 32], [3; 32]).expect("get"),
            None
        );
    }
}

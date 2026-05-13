//! Read-only views over the disappearing-messages setting tables.
//!
//! The setting projection writes one row per admitted event, so the
//! "active" setting for a workspace is the row with the highest
//! `(created_at_ms, event_id)` tiebreaker. The chop-floor table records
//! per-workspace+frontier dispatcher progress and is the only durable
//! signal of how much subtree material has already been retired.

use crate::core::store::Store;
use crate::protocol::event_modules::types::EventId;

use super::schema::{
    self, decode_active_setting_row, CHOP_FLOOR_VALUE_BYTES, SETTINGS, WORKSPACE_CHOP_FLOOR,
};
use super::types::ActiveSettingRow;

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

/// Read the highest `floor_minute` already chopped for this workspace +
/// frontier. `None` means no chop has run yet (treated as 0 by the
/// dispatcher).
pub fn get_last_chopped_floor(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
) -> Result<Option<u64>, String> {
    let key = schema::chop_floor_key(workspace_id, removal_frontier_id);
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

// Read-only queries; mutation-driven coverage (active-row tiebreak, chop
// floor upsert/lookup, workspace scoping) lives in the worker tests in
// `src/workers/disappearing_floor_dispatcher.rs` and the projector unit
// tests under this module.

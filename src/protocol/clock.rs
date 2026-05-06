//! Store-local logical clock for deterministic CLI scenarios.
//!
//! This is not a protocol event and it is not synced. It is local operator/test
//! metadata used as a lower bound when CLI commands choose the next event
//! timestamp. Existing event timestamps still win, so setting the clock
//! backwards cannot make new shared events collide with old ones.

use crate::core::store::{Schema, Store, TableName, TableRow};
use crate::protocol::wire::{Reader, Writer};

pub const LOGICAL_CLOCK: TableName = TableName::new("protocol.logical_clock");
pub const SCHEMAS: &[Schema] = &[Schema::durable_row_table(
    "protocol.logical_clock.v1",
    LOGICAL_CLOCK,
)];

const CLOCK_KEY: &[u8] = b"now";

pub fn logical_time(store: &Store) -> Result<Option<u64>, String> {
    store
        .table_row(LOGICAL_CLOCK, CLOCK_KEY)
        .map_err(|err| format!("load logical clock: {err}"))?
        .map(|value| decode_value(&value))
        .transpose()
}

pub fn set_logical_time(store: &Store, timestamp: u64) -> Result<u64, String> {
    store
        .write_transaction(|store| store.replace_table_rows_in_tx(vec![clock_row(timestamp)]))
        .map_err(|err| format!("set logical clock: {err}"))?;
    Ok(timestamp)
}

pub fn advance_logical_time(store: &Store, delta: u64) -> Result<u64, String> {
    let current = logical_time(store)?.unwrap_or(0);
    let next = current
        .checked_add(delta)
        .ok_or_else(|| "logical clock advance overflows u64".to_string())?;
    set_logical_time(store, next)
}

pub fn clear_logical_time(store: &Store) -> Result<(), String> {
    store
        .delete_table_rows(LOGICAL_CLOCK, vec![CLOCK_KEY.to_vec()])
        .map_err(|err| format!("clear logical clock: {err}"))?;
    Ok(())
}

pub fn next_timestamp(store: &Store, observed_max_timestamp: u64) -> Result<u64, String> {
    let from_events = observed_max_timestamp.saturating_add(1);
    Ok(from_events.max(logical_time(store)?.unwrap_or(0)))
}

pub fn max_timestamp_for_next(store: &Store, observed_max_timestamp: u64) -> Result<u64, String> {
    next_timestamp(store, observed_max_timestamp).map(|timestamp| timestamp.saturating_sub(1))
}

fn clock_row(timestamp: u64) -> TableRow {
    let mut out = Writer::with_capacity(8);
    out.u64(timestamp);
    TableRow {
        table: LOGICAL_CLOCK,
        key: CLOCK_KEY.to_vec(),
        value: out.finish(),
    }
}

fn decode_value(value: &[u8]) -> Result<u64, String> {
    let mut reader = Reader::new(value, "logical clock row");
    let timestamp = reader.u64()?;
    reader.finish()?;
    Ok(timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logical_clock_is_a_lower_bound_for_next_timestamp() {
        let store = Store::open_memory_with_schemas(SCHEMAS).expect("store");

        assert_eq!(next_timestamp(&store, 7).expect("next"), 8);

        set_logical_time(&store, 100).expect("set");
        assert_eq!(next_timestamp(&store, 7).expect("next"), 100);
        assert_eq!(next_timestamp(&store, 125).expect("next"), 126);
    }

    #[test]
    fn advance_and_clear_are_store_local() {
        let store = Store::open_memory_with_schemas(SCHEMAS).expect("store");

        assert_eq!(advance_logical_time(&store, 5).expect("advance"), 5);
        assert_eq!(advance_logical_time(&store, 7).expect("advance"), 12);
        assert_eq!(logical_time(&store).expect("clock"), Some(12));

        clear_logical_time(&store).expect("clear");
        assert_eq!(logical_time(&store).expect("clock"), None);
    }
}

//! Content-event projection rows.
//!
//! Rows are keyed by `workspace_id || content_event_id` so tests and future
//! workers can inspect content by workspace without decoding the common event
//! store or relying on global counts.

use crate::core::store::{Schema, Store, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::{Reader, Writer};

use super::types::ContentEvent;

pub const CONTENT_EVENTS: TableName = TableName::new("content.events");

pub const SCHEMAS: &[Schema] = &[Schema::durable_row_table(
    "content.events.v1",
    CONTENT_EVENTS,
)];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentEventRow {
    pub workspace_id: EventId,
    pub event_id: EventId,
    pub timestamp: u64,
    pub payload_bytes: usize,
}

pub fn content_event_row(event_id: EventId, event: &ContentEvent) -> TableRow {
    TableRow {
        table: CONTENT_EVENTS,
        key: content_event_key(event.workspace_id, event_id),
        value: encode_content_event_value(event.timestamp, event.payload.len()),
    }
}

pub fn count_for_workspace(store: &Store, workspace_id: EventId) -> Result<usize, String> {
    store
        .table_rows_with_key_prefix(CONTENT_EVENTS, &workspace_id, usize::MAX)
        .map(|rows| rows.len())
        .map_err(|err| format!("count content events: {err}"))
}

pub fn payload_bytes_for_workspace(store: &Store, workspace_id: EventId) -> Result<usize, String> {
    store
        .table_rows_with_key_prefix(CONTENT_EVENTS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load content events: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_content_event_row(&key, &value).map(|row| row.payload_bytes))
        .sum()
}

pub fn max_timestamp_for_workspace(store: &Store, workspace_id: EventId) -> Result<u64, String> {
    store
        .table_rows_with_key_prefix(CONTENT_EVENTS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load content events: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_content_event_row(&key, &value).map(|row| row.timestamp))
        .try_fold(0, |max, timestamp| {
            timestamp.map(|timestamp| max.max(timestamp))
        })
}

pub fn decode_content_event_row(key: &[u8], value: &[u8]) -> Result<ContentEventRow, String> {
    if key.len() != 64 {
        return Err("content event row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut event_id = [0; 32];
    event_id.copy_from_slice(&key[32..64]);

    let mut reader = Reader::new(value, "content event row");
    let timestamp = reader.u64()?;
    let payload_bytes = reader.u64()? as usize;
    reader.finish()?;

    Ok(ContentEventRow {
        workspace_id,
        event_id,
        timestamp,
        payload_bytes,
    })
}

fn content_event_key(workspace_id: EventId, event_id: EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&event_id);
    key
}

fn encode_content_event_value(timestamp: u64, payload_bytes: usize) -> Vec<u8> {
    let mut out = Writer::with_capacity(16);
    out.u64(timestamp);
    out.u64(payload_bytes as u64);
    out.finish()
}

#[cfg(test)]
mod tests {
    use crate::core::store::Store;

    use super::*;

    // Invariant: content rows are keyed and counted by workspace.
    #[test]
    fn content_rows_are_keyed_and_counted_by_workspace() {
        let store = Store::open_memory_with_schemas(SCHEMAS).expect("open store");
        let row_a = content_event_row(
            [2; 32],
            &ContentEvent {
                workspace_id: [1; 32],
                timestamp: 9,
                payload: vec![0; 3],
            },
        );
        let row_b = content_event_row(
            [4; 32],
            &ContentEvent {
                workspace_id: [3; 32],
                timestamp: 10,
                payload: vec![0; 5],
            },
        );
        store
            .insert_table_rows(vec![row_a.clone(), row_b])
            .expect("insert content rows");

        assert_eq!(count_for_workspace(&store, [1; 32]).expect("count"), 1);
        assert_eq!(
            payload_bytes_for_workspace(&store, [1; 32]).expect("bytes"),
            3
        );
        assert_eq!(
            max_timestamp_for_workspace(&store, [1; 32]).expect("max timestamp"),
            9
        );
        assert_eq!(
            decode_content_event_row(&row_a.key, &row_a.value).expect("decode row"),
            ContentEventRow {
                workspace_id: [1; 32],
                event_id: [2; 32],
                timestamp: 9,
                payload_bytes: 3,
            }
        );
    }
}

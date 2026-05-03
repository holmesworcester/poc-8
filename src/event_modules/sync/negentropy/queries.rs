use crate::store::{AppliedEventEntry, EventId, Store, TableRow, TableRowDeletion};

use super::tables;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexedEntry {
    pub apply_seq: u64,
    pub event_id: EventId,
}

pub fn cursor(store: &Store) -> Result<u64, String> {
    let Some(bytes) = store
        .table_row(tables::CURSOR, tables::CURSOR_KEY)
        .map_err(|err| format!("load sync index cursor: {err}"))?
    else {
        return Ok(0);
    };
    if bytes.len() != 8 {
        return Err("sync index cursor must be 8 bytes".to_string());
    }
    let mut value = [0; 8];
    value.copy_from_slice(&bytes);
    Ok(u64::from_be_bytes(value))
}

pub fn cursor_update(apply_seq: u64) -> (TableRowDeletion, TableRow) {
    (
        TableRowDeletion {
            table: tables::CURSOR,
            key: tables::CURSOR_KEY.to_vec(),
        },
        TableRow {
            table: tables::CURSOR,
            key: tables::CURSOR_KEY.to_vec(),
            value: apply_seq.to_be_bytes().to_vec(),
        },
    )
}

pub fn index_rows(entries: &[AppliedEventEntry]) -> Vec<TableRow> {
    entries.iter().map(index_row).collect()
}

pub fn indexed_entries(store: &Store) -> Result<Vec<IndexedEntry>, String> {
    let rows = store
        .table_rows(tables::INDEX)
        .map_err(|err| format!("load sync negentropy index: {err}"))?;
    let mut entries = Vec::with_capacity(rows.len());
    for (key, _) in rows {
        if key.len() != 40 {
            return Err("sync negentropy index key must be 40 bytes".to_string());
        }
        let mut seq = [0; 8];
        seq.copy_from_slice(&key[..8]);
        let mut event_id = [0; 32];
        event_id.copy_from_slice(&key[8..40]);
        entries.push(IndexedEntry {
            apply_seq: u64::from_be_bytes(seq),
            event_id,
        });
    }
    Ok(entries)
}

fn index_row(entry: &AppliedEventEntry) -> TableRow {
    let mut key = Vec::with_capacity(40);
    key.extend_from_slice(&entry.apply_seq.to_be_bytes());
    key.extend_from_slice(&entry.event_id);
    TableRow {
        table: tables::INDEX,
        key,
        value: vec![entry.partition],
    }
}

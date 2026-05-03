use crate::store::Store;

use super::tables;
use super::types::{self, QueuedSyncWork};

pub fn next_work(store: &Store) -> Result<Option<QueuedSyncWork>, String> {
    let Some((key, value)) = store
        .table_rows(tables::WORK)
        .map_err(|err| format!("load sync work: {err}"))?
        .into_iter()
        .next()
    else {
        return Ok(None);
    };
    types::decode(key, &value).map(Some)
}

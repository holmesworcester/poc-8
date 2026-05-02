use crate::store::{EventRecord, Store};

pub fn insert_many(store: &Store, records: Vec<EventRecord>) -> rusqlite::Result<usize> {
    store.insert_events(records)
}

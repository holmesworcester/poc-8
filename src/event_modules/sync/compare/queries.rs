use negentropy::{Id, NegentropyStorageVector};

use crate::store::{EventId, Store};

pub trait ReadContext {
    fn storage(&self) -> Result<NegentropyStorageVector, String>;
    fn has_event(&self, event_id: &EventId) -> Result<bool, String>;
    fn event_byte(&self, id: &EventId) -> Result<Option<Vec<u8>>, String>;
}

impl ReadContext for Store {
    fn storage(&self) -> Result<NegentropyStorageVector, String> {
        storage(self)
    }

    fn has_event(&self, event_id: &EventId) -> Result<bool, String> {
        has_event(self, event_id)
    }

    fn event_byte(&self, id: &EventId) -> Result<Option<Vec<u8>>, String> {
        event_byte(self, id)
    }
}

pub fn storage(store: &Store) -> Result<NegentropyStorageVector, String> {
    let mut storage = NegentropyStorageVector::new();
    for entry in super::super::negentropy::queries::indexed_entries(store)? {
        storage
            .insert(entry.apply_seq, Id::from_byte_array(entry.event_id))
            .map_err(|err| format!("insert sync index item: {err:?}"))?;
    }
    storage
        .seal()
        .map_err(|err| format!("seal sync index: {err:?}"))?;
    Ok(storage)
}

pub fn has_event(store: &Store, event_id: &EventId) -> Result<bool, String> {
    store
        .has_shared_event(event_id)
        .map_err(|err| format!("check event presence: {err}"))
}

pub fn event_byte(store: &Store, id: &EventId) -> Result<Option<Vec<u8>>, String> {
    store
        .shared_event_bytes(id)
        .map_err(|err| format!("load event bytes: {err}"))
}

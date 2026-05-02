use crate::event_modules::content;
use crate::store::{EventId, Store};

use super::codec::{BucketSummary, BUCKETS};

pub fn summary(store: &Store) -> Result<[BucketSummary; BUCKETS], String> {
    let mut summary = [BucketSummary::default(); BUCKETS];
    for header in store
        .headers()
        .map_err(|err| format!("load event headers: {err}"))?
    {
        let bucket = &mut summary[usize::from(header.bucket)];
        bucket.count += 1;
        xor_into(&mut bucket.fingerprint, &fingerprint_id(&header.event_id));
    }
    Ok(summary)
}

pub fn ids_in_bucket(store: &Store, bucket: u8) -> Result<Vec<EventId>, String> {
    store
        .ids_in_bucket(bucket)
        .map_err(|err| format!("load bucket ids: {err}"))
}

pub fn has_event(store: &Store, event_id: &EventId) -> Result<bool, String> {
    store
        .has_event(event_id)
        .map_err(|err| format!("check event presence: {err}"))
}

pub fn event_bytes(store: &Store, ids: &[EventId]) -> Result<Vec<Vec<u8>>, String> {
    let mut events = Vec::with_capacity(ids.len());
    for id in ids {
        if let Some(bytes) = store
            .event_bytes(id)
            .map_err(|err| format!("load event bytes: {err}"))?
        {
            events.push(bytes);
        }
    }
    Ok(events)
}

pub fn insert_events(store: &Store, events: Vec<Vec<u8>>) -> Result<usize, String> {
    let mut records = Vec::with_capacity(events.len());
    for bytes in events {
        records.push(content::codec::record_from_bytes(bytes)?);
    }
    store
        .insert_events(records)
        .map_err(|err| format!("insert received events: {err}"))
}

fn fingerprint_id(id: &EventId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"sync-event-id:");
    hasher.update(id);
    *hasher.finalize().as_bytes()
}

fn xor_into(target: &mut [u8; 32], value: &[u8; 32]) {
    for (left, right) in target.iter_mut().zip(value.iter()) {
        *left ^= *right;
    }
}

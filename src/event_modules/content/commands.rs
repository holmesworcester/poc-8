use crate::store::Store;

use super::codec::{self, ContentEvent};
use super::projector;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateReport {
    pub inserted_events: usize,
    pub first_timestamp: u64,
    pub last_timestamp: u64,
}

pub fn generate(
    store: &Store,
    num_events: usize,
    event_size: usize,
) -> Result<GenerateReport, String> {
    let start = store
        .max_timestamp()
        .map_err(|err| format!("load max timestamp: {err}"))?
        .saturating_add(1);
    let mut records = Vec::with_capacity(num_events);

    for offset in 0..num_events {
        let timestamp = start + offset as u64;
        let payload = payload(timestamp, event_size);
        let bytes = codec::encode(&ContentEvent { timestamp, payload });
        let record = codec::record_from_bytes(bytes)?;
        records.push(record);
    }

    let inserted_events =
        projector::insert_many(store, records).map_err(|err| format!("insert events: {err}"))?;

    Ok(GenerateReport {
        inserted_events,
        first_timestamp: start,
        last_timestamp: start + num_events as u64 - 1,
    })
}

fn payload(timestamp: u64, size: usize) -> Vec<u8> {
    let mut seed = blake3::Hasher::new();
    seed.update(b"content-payload:");
    seed.update(&timestamp.to_be_bytes());
    let mut state = *seed.finalize().as_bytes();
    let mut out = Vec::with_capacity(size);

    while out.len() < size {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&state);
        state = *hasher.finalize().as_bytes();
        let remaining = size - out.len();
        out.extend_from_slice(&state[..remaining.min(state.len())]);
    }

    out
}

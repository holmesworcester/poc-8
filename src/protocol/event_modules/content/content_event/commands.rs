//! Commands for generating content events.
//!
//! Generation is deterministic from `(start_timestamp, count, size)`, which
//! lets CLI tests compare counts and throughput without relying on random test
//! fixtures. The command proposes shared events only; storing and projection are
//! handled by the common worker.

use crate::core::crypto::{self, Ed25519PrivateKey};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::CommandOutput;

use super::codec;
use super::types::ContentEvent;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateReport {
    pub first_timestamp: u64,
    pub last_timestamp: u64,
}

pub fn generate(
    workspace_id: EventId,
    signer_endpoint_shared_id: EventId,
    signer_private_key: Ed25519PrivateKey,
    start_timestamp: u64,
    num_events: usize,
    event_size: usize,
) -> Result<CommandOutput<GenerateReport>, String> {
    let mut records = Vec::with_capacity(num_events);

    for offset in 0..num_events {
        let timestamp = start_timestamp + offset as u64;
        let payload = payload(timestamp, event_size);
        let bytes = codec::encode(&ContentEvent {
            workspace_id,
            timestamp,
            payload,
        });
        let signed = codec::sign(signer_endpoint_shared_id, &signer_private_key, bytes);
        let record = codec::signed_record_from_bytes(codec::encode_signed(&signed))?;
        records.push(record);
    }

    Ok(CommandOutput::with_events(
        GenerateReport {
            first_timestamp: start_timestamp,
            last_timestamp: start_timestamp + num_events as u64 - 1,
        },
        records,
    ))
}

fn payload(timestamp: u64, size: usize) -> Vec<u8> {
    // Derive pseudo-random-looking bytes from the timestamp so large payload
    // tests move nontrivial data while remaining reproducible.
    let mut seed = Vec::with_capacity("content-payload:".len() + std::mem::size_of::<u64>());
    seed.extend_from_slice(b"content-payload:");
    seed.extend_from_slice(&timestamp.to_be_bytes());
    let mut state = crypto::hash(&seed);
    let mut out = Vec::with_capacity(size);

    while out.len() < size {
        state = crypto::hash(&state);
        let remaining = size - out.len();
        out.extend_from_slice(&state[..remaining.min(state.len())]);
    }

    out
}

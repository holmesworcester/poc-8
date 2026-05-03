use crate::store::{EventId, EventRecord, TableRow, TableRowDeletion};
use crate::wire::{Reader, Writer};

use super::tables;

const START: u8 = 1;
const INBOUND_FRAME: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncWork {
    Start {
        connection_id: EventId,
        required_index_seq: u64,
    },
    InboundFrame {
        connection_id: EventId,
        required_index_seq: u64,
        frame_bytes: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedSyncWork {
    pub key: Vec<u8>,
    pub work: SyncWork,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncJobOutput {
    pub rows: Vec<TableRow>,
    pub deleted_rows: Vec<TableRowDeletion>,
    pub events: Vec<EventRecord>,
    pub received_event_bytes: Vec<Vec<u8>>,
    pub sent_events: usize,
    pub received_events: usize,
}

pub fn encode(work: SyncWork) -> TableRow {
    let mut key = Vec::with_capacity(65);
    let mut value = Writer::new();
    match work {
        SyncWork::Start {
            connection_id,
            required_index_seq,
        } => {
            key.push(START);
            key.extend_from_slice(&connection_id);
            value.u8(START);
            value.id(&connection_id);
            value.u64(required_index_seq);
        }
        SyncWork::InboundFrame {
            connection_id,
            required_index_seq,
            frame_bytes,
        } => {
            key.push(INBOUND_FRAME);
            key.extend_from_slice(&connection_id);
            key.extend_from_slice(&crate::store::event_id(&frame_bytes));
            value.u8(INBOUND_FRAME);
            value.id(&connection_id);
            value.u64(required_index_seq);
            value.sized_bytes(&frame_bytes);
        }
    }
    TableRow {
        table: tables::WORK,
        key,
        value: value.finish(),
    }
}

pub fn decode(key: Vec<u8>, value: &[u8]) -> Result<QueuedSyncWork, String> {
    let mut reader = Reader::new(value, "sync work");
    let tag = reader.u8()?;
    let connection_id = reader.id()?;
    let required_index_seq = reader.u64()?;
    validate_key(&key, tag, &connection_id)?;
    let work = match tag {
        START => SyncWork::Start {
            connection_id,
            required_index_seq,
        },
        INBOUND_FRAME => SyncWork::InboundFrame {
            connection_id,
            required_index_seq,
            frame_bytes: reader.sized_bytes()?,
        },
        other => return Err(format!("unknown sync work kind {other}")),
    };
    reader.finish()?;
    Ok(QueuedSyncWork { key, work })
}

impl SyncWork {
    pub fn required_index_seq(&self) -> u64 {
        match self {
            Self::Start {
                required_index_seq, ..
            }
            | Self::InboundFrame {
                required_index_seq, ..
            } => *required_index_seq,
        }
    }
}

fn validate_key(key: &[u8], tag: u8, connection_id: &EventId) -> Result<(), String> {
    let expected_len = match tag {
        START => 33,
        INBOUND_FRAME => 65,
        other => return Err(format!("unknown sync work key kind {other}")),
    };
    if key.len() != expected_len {
        return Err(format!("sync work key must be {expected_len} bytes"));
    }
    if key[0] != tag || &key[1..33] != connection_id {
        return Err("sync work key does not match payload".to_string());
    }
    Ok(())
}

use crate::store::{EventId, TableRow, TableRowDeletion, WorkRecord};
use crate::wire::{Reader, Writer};

pub const LANE: &str = "sync";
pub const START: &str = "start";
pub const INBOUND_FRAME: &str = "inbound_frame";

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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncJobOutput {
    pub rows: Vec<TableRow>,
    pub deleted_rows: Vec<TableRowDeletion>,
    pub work: Vec<WorkRecord>,
    pub received_event_bytes: Vec<Vec<u8>>,
    pub sent_events: usize,
    pub received_events: usize,
}

pub fn start_record(connection_id: EventId, required_index_seq: u64) -> WorkRecord {
    let mut payload = Writer::new();
    payload.id(&connection_id);
    payload.u64(required_index_seq);
    WorkRecord {
        lane: LANE,
        kind: START,
        dedupe_key: connection_id.to_vec(),
        payload: payload.finish(),
    }
}

pub fn inbound_frame_record(
    connection_id: EventId,
    required_index_seq: u64,
    frame_bytes: Vec<u8>,
) -> WorkRecord {
    let mut dedupe_key = Vec::with_capacity(64);
    dedupe_key.extend_from_slice(&connection_id);
    dedupe_key.extend_from_slice(&crate::store::event_id(&frame_bytes));

    let mut payload = Writer::new();
    payload.id(&connection_id);
    payload.u64(required_index_seq);
    payload.sized_bytes(&frame_bytes);
    WorkRecord {
        lane: LANE,
        kind: INBOUND_FRAME,
        dedupe_key,
        payload: payload.finish(),
    }
}

pub fn decode(kind: &str, payload: &[u8]) -> Result<SyncWork, String> {
    let mut reader = Reader::new(payload, "sync work");
    let connection_id = reader.id()?;
    let required_index_seq = reader.u64()?;
    let work = match kind {
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
    Ok(work)
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

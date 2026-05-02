use crate::store::EventId;
use crate::wire::{Reader, Writer};

pub const BUCKETS: usize = 256;

const MAGIC: &[u8; 9] = b"TOPOSYNC1";
const TAG_COMPARE: u8 = 1;
const TAG_HAVE_ID: u8 = 2;
const TAG_NEED_ID: u8 = 3;
const TAG_DATA: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BucketSummary {
    pub count: u64,
    pub fingerprint: [u8; 32],
}

impl Default for BucketSummary {
    fn default() -> Self {
        Self {
            count: 0,
            fingerprint: [0; 32],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub more: bool,
    pub items: Vec<SyncItem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncItem {
    Compare {
        connection_id: EventId,
        summary: [BucketSummary; BUCKETS],
    },
    HaveId {
        connection_id: EventId,
        bucket: u8,
        id: EventId,
    },
    NeedId {
        connection_id: EventId,
        id: EventId,
    },
    Data {
        connection_id: EventId,
        items: Vec<Vec<u8>>,
    },
}

pub fn encode(frame: &Frame) -> Vec<u8> {
    let mut out = Writer::new();
    out.raw(MAGIC);
    out.u8(u8::from(frame.more));
    out.u32(frame.items.len());
    for item in &frame.items {
        match item {
            SyncItem::Compare {
                connection_id,
                summary,
            } => {
                out.u8(TAG_COMPARE);
                out.id(connection_id);
                for bucket in summary {
                    out.u64(bucket.count);
                    out.id(&bucket.fingerprint);
                }
            }
            SyncItem::HaveId {
                connection_id,
                bucket,
                id,
            } => {
                out.u8(TAG_HAVE_ID);
                out.id(connection_id);
                out.u8(*bucket);
                out.id(id);
            }
            SyncItem::NeedId { connection_id, id } => {
                out.u8(TAG_NEED_ID);
                out.id(connection_id);
                out.id(id);
            }
            SyncItem::Data {
                connection_id,
                items,
            } => {
                out.u8(TAG_DATA);
                out.id(connection_id);
                out.u32(items.len());
                for item in items {
                    out.sized_bytes(item);
                }
            }
        }
    }
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<Frame, String> {
    if !bytes.starts_with(MAGIC) {
        return Err("not a sync frame".to_string());
    }
    let mut reader = Reader::new(&bytes[MAGIC.len()..], "sync frame");
    let more = match reader.u8()? {
        0 => false,
        1 => true,
        other => return Err(format!("invalid sync frame continuation flag {other}")),
    };
    let item_count = reader.u32()? as usize;
    let mut items = Vec::with_capacity(item_count);
    for _ in 0..item_count {
        let item = match reader.u8()? {
            TAG_COMPARE => {
                let connection_id = reader.id()?;
                let mut summary = [BucketSummary::default(); BUCKETS];
                for bucket in &mut summary {
                    bucket.count = reader.u64()?;
                    bucket.fingerprint = reader.id()?;
                }
                SyncItem::Compare {
                    connection_id,
                    summary,
                }
            }
            TAG_HAVE_ID => SyncItem::HaveId {
                connection_id: reader.id()?,
                bucket: reader.u8()?,
                id: reader.id()?,
            },
            TAG_NEED_ID => SyncItem::NeedId {
                connection_id: reader.id()?,
                id: reader.id()?,
            },
            TAG_DATA => {
                let connection_id = reader.id()?;
                let count = reader.u32()? as usize;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(reader.sized_bytes()?);
                }
                SyncItem::Data {
                    connection_id,
                    items,
                }
            }
            other => return Err(format!("unknown sync item tag {other}")),
        };
        items.push(item);
    }
    reader.finish()?;
    Ok(Frame { more, items })
}

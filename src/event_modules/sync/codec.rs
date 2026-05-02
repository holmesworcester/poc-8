use crate::store::EventId;

pub const BUCKETS: usize = 256;

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
pub enum Message {
    Hello,
    HelloAck,
    Summary([BucketSummary; BUCKETS]),
    Have { bucket: u8, ids: Vec<EventId> },
    Need { ids: Vec<EventId> },
    Events { events: Vec<Vec<u8>> },
    Done,
}

pub fn encode(message: &Message) -> Vec<u8> {
    let mut out = Vec::new();
    match message {
        Message::Hello => out.push(1),
        Message::HelloAck => out.push(2),
        Message::Summary(summary) => {
            out.push(3);
            for bucket in summary {
                out.extend_from_slice(&bucket.count.to_be_bytes());
                out.extend_from_slice(&bucket.fingerprint);
            }
        }
        Message::Have { bucket, ids } => {
            out.push(4);
            out.push(*bucket);
            put_ids(&mut out, ids);
        }
        Message::Need { ids } => {
            out.push(5);
            put_ids(&mut out, ids);
        }
        Message::Events { events } => {
            out.push(6);
            put_u32(&mut out, events.len());
            for event in events {
                put_u32(&mut out, event.len());
                out.extend_from_slice(event);
            }
        }
        Message::Done => out.push(7),
    }
    out
}

pub fn decode(bytes: &[u8]) -> Result<Message, String> {
    let Some((&tag, rest)) = bytes.split_first() else {
        return Err("empty message".to_string());
    };
    let mut cursor = Cursor { rest };
    let message = match tag {
        1 => Message::Hello,
        2 => Message::HelloAck,
        3 => {
            let mut summary = [BucketSummary::default(); BUCKETS];
            for bucket in &mut summary {
                bucket.count = cursor.u64()?;
                bucket.fingerprint = cursor.id()?;
            }
            Message::Summary(summary)
        }
        4 => {
            let bucket = cursor.u8()?;
            Message::Have {
                bucket,
                ids: cursor.ids()?,
            }
        }
        5 => Message::Need { ids: cursor.ids()? },
        6 => {
            let count = cursor.u32()? as usize;
            let mut events = Vec::with_capacity(count);
            for _ in 0..count {
                let len = cursor.u32()? as usize;
                events.push(cursor.bytes(len)?);
            }
            Message::Events { events }
        }
        7 => Message::Done,
        other => return Err(format!("unknown sync message tag {other}")),
    };
    cursor.finish()?;
    Ok(message)
}

fn put_ids(out: &mut Vec<u8>, ids: &[EventId]) {
    put_u32(out, ids.len());
    for id in ids {
        out.extend_from_slice(id);
    }
}

fn put_u32(out: &mut Vec<u8>, value: usize) {
    let value = u32::try_from(value).expect("value too large for sync codec");
    out.extend_from_slice(&value.to_be_bytes());
}

struct Cursor<'a> {
    rest: &'a [u8],
}

impl Cursor<'_> {
    fn u8(&mut self) -> Result<u8, String> {
        if self.rest.is_empty() {
            return Err("truncated sync message".to_string());
        }
        let value = self.rest[0];
        self.rest = &self.rest[1..];
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32, String> {
        if self.rest.len() < 4 {
            return Err("truncated sync message".to_string());
        }
        let mut bytes = [0; 4];
        bytes.copy_from_slice(&self.rest[..4]);
        self.rest = &self.rest[4..];
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, String> {
        if self.rest.len() < 8 {
            return Err("truncated sync message".to_string());
        }
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&self.rest[..8]);
        self.rest = &self.rest[8..];
        Ok(u64::from_be_bytes(bytes))
    }

    fn id(&mut self) -> Result<EventId, String> {
        if self.rest.len() < 32 {
            return Err("truncated sync message".to_string());
        }
        let mut id = [0; 32];
        id.copy_from_slice(&self.rest[..32]);
        self.rest = &self.rest[32..];
        Ok(id)
    }

    fn ids(&mut self) -> Result<Vec<EventId>, String> {
        let count = self.u32()? as usize;
        let mut ids = Vec::with_capacity(count);
        for _ in 0..count {
            ids.push(self.id()?);
        }
        Ok(ids)
    }

    fn bytes(&mut self, len: usize) -> Result<Vec<u8>, String> {
        if self.rest.len() < len {
            return Err("truncated sync message".to_string());
        }
        let (head, tail) = self.rest.split_at(len);
        self.rest = tail;
        Ok(head.to_vec())
    }

    fn finish(&self) -> Result<(), String> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err("trailing sync message bytes".to_string())
        }
    }
}

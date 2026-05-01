use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub type ConnectionId = [u8; 32];
pub type EventId = [u8; 32];

const FRAME_MAGIC: &[u8; 8] = b"TOPONET1";
const FRAME_HEADER_BYTES: usize = 4 + FRAME_MAGIC.len() + 32 + 32 + 4;
const REFILL_ROW_LIMIT: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkError {
    MissingEvent {
        connection_id: ConnectionId,
        event_id: EventId,
    },
    Store(String),
    Transport(String),
}

pub type NetworkResult<T> = Result<T, NetworkError>;

pub trait Outbox {
    fn pending_connections(&self) -> NetworkResult<Vec<ConnectionId>>;

    fn list_outbox_for_connection(
        &self,
        connection_id: &ConnectionId,
        limit: usize,
    ) -> NetworkResult<Vec<EventId>>;

    fn event_bytes(
        &self,
        connection_id: &ConnectionId,
        event_id: &EventId,
    ) -> NetworkResult<Option<Vec<u8>>>;

    fn delete_outbox_rows(
        &mut self,
        connection_id: &ConnectionId,
        event_ids: &[EventId],
    ) -> NetworkResult<()>;
}

pub trait Transport {
    fn send(&mut self, connection_id: &ConnectionId, frame: &OutboundFrame) -> NetworkResult<()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundFrame {
    bytes: Vec<u8>,
}

impl OutboundFrame {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

pub fn frame_len_for_event_bytes(event_bytes_len: usize) -> usize {
    FRAME_HEADER_BYTES + event_bytes_len
}

pub fn wrap_frame(
    connection_id: &ConnectionId,
    event_id: &EventId,
    event_bytes: &[u8],
) -> OutboundFrame {
    let body_len = FRAME_MAGIC.len() + connection_id.len() + event_id.len() + 4 + event_bytes.len();
    let mut bytes = Vec::with_capacity(4 + body_len);
    bytes.extend_from_slice(&(body_len as u32).to_be_bytes());
    bytes.extend_from_slice(FRAME_MAGIC);
    bytes.extend_from_slice(connection_id);
    bytes.extend_from_slice(event_id);
    bytes.extend_from_slice(&(event_bytes.len() as u32).to_be_bytes());
    bytes.extend_from_slice(event_bytes);
    OutboundFrame { bytes }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QueuedFrame {
    event_id: EventId,
    frame: OutboundFrame,
}

#[derive(Debug, Clone)]
pub struct ConnectionSender {
    connection_id: ConnectionId,
    max_hot_bytes: usize,
    hot_bytes: usize,
    hot_queue: VecDeque<QueuedFrame>,
    present: BTreeSet<EventId>,
}

impl ConnectionSender {
    pub fn new(connection_id: ConnectionId, max_hot_bytes: usize) -> Self {
        Self {
            connection_id,
            max_hot_bytes,
            hot_bytes: 0,
            hot_queue: VecDeque::new(),
            present: BTreeSet::new(),
        }
    }

    pub fn connection_id(&self) -> &ConnectionId {
        &self.connection_id
    }

    pub fn hot_queue_len(&self) -> usize {
        self.hot_queue.len()
    }

    pub fn hot_queue_bytes(&self) -> usize {
        self.hot_bytes
    }

    pub fn present_len(&self) -> usize {
        self.present.len()
    }

    pub fn refill<O: Outbox>(&mut self, outbox: &O) -> NetworkResult<usize> {
        let pending = outbox.list_outbox_for_connection(&self.connection_id, REFILL_ROW_LIMIT)?;
        let mut loaded = 0;
        let mut seen = BTreeSet::new();

        for event_id in pending {
            if !seen.insert(event_id) || self.present.contains(&event_id) {
                continue;
            }

            let event_bytes = outbox.event_bytes(&self.connection_id, &event_id)?.ok_or(
                NetworkError::MissingEvent {
                    connection_id: self.connection_id,
                    event_id,
                },
            )?;
            let frame = wrap_frame(&self.connection_id, &event_id, &event_bytes);

            if self.hot_bytes + frame.len() > self.max_hot_bytes {
                break;
            }

            self.hot_bytes += frame.len();
            self.present.insert(event_id);
            self.hot_queue.push_back(QueuedFrame { event_id, frame });
            loaded += 1;
        }

        Ok(loaded)
    }

    pub fn send_one<O: Outbox, T: Transport>(
        &mut self,
        outbox: &mut O,
        transport: &mut T,
    ) -> NetworkResult<Option<EventId>> {
        if self.hot_queue.is_empty() {
            self.refill(outbox)?;
        }

        let Some(queued) = self.hot_queue.pop_front() else {
            return Ok(None);
        };

        self.hot_bytes -= queued.frame.len();
        self.present.remove(&queued.event_id);

        transport.send(&self.connection_id, &queued.frame)?;
        outbox.delete_outbox_rows(&self.connection_id, &[queued.event_id])?;

        Ok(Some(queued.event_id))
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TickReport {
    pub sent: Vec<(ConnectionId, EventId)>,
    pub errors: Vec<(ConnectionId, NetworkError)>,
}

pub struct Network<T> {
    transport: T,
    max_hot_bytes_per_connection: usize,
    senders: BTreeMap<ConnectionId, ConnectionSender>,
}

impl<T> Network<T> {
    pub fn new(transport: T, max_hot_bytes_per_connection: usize) -> Self {
        Self {
            transport,
            max_hot_bytes_per_connection,
            senders: BTreeMap::new(),
        }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn sender(&self, connection_id: &ConnectionId) -> Option<&ConnectionSender> {
        self.senders.get(connection_id)
    }

    pub fn sender_mut(&mut self, connection_id: &ConnectionId) -> &mut ConnectionSender {
        self.senders.entry(*connection_id).or_insert_with(|| {
            ConnectionSender::new(*connection_id, self.max_hot_bytes_per_connection)
        })
    }
}

impl<T: Transport> Network<T> {
    pub fn tick<O: Outbox>(&mut self, outbox: &mut O) -> NetworkResult<TickReport> {
        let mut connections = outbox.pending_connections()?;
        connections.sort();
        connections.dedup();

        let mut report = TickReport::default();
        for connection_id in connections {
            let sender = self.senders.entry(connection_id).or_insert_with(|| {
                ConnectionSender::new(connection_id, self.max_hot_bytes_per_connection)
            });

            match sender.send_one(outbox, &mut self.transport) {
                Ok(Some(event_id)) => report.sent.push((connection_id, event_id)),
                Ok(None) => {}
                Err(err) => report.errors.push((connection_id, err)),
            }
        }

        Ok(report)
    }
}

#[derive(Debug, Default, Clone)]
pub struct MemoryTransport {
    accepted: BTreeMap<ConnectionId, Vec<Vec<u8>>>,
    failing: BTreeSet<ConnectionId>,
}

impl MemoryTransport {
    pub fn fail_connection(&mut self, connection_id: ConnectionId) {
        self.failing.insert(connection_id);
    }

    pub fn allow_connection(&mut self, connection_id: &ConnectionId) {
        self.failing.remove(connection_id);
    }

    pub fn frames_for(&self, connection_id: &ConnectionId) -> &[Vec<u8>] {
        self.accepted
            .get(connection_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }
}

impl Transport for MemoryTransport {
    fn send(&mut self, connection_id: &ConnectionId, frame: &OutboundFrame) -> NetworkResult<()> {
        if self.failing.contains(connection_id) {
            return Err(NetworkError::Transport("connection send failed".to_owned()));
        }

        self.accepted
            .entry(*connection_id)
            .or_default()
            .push(frame.bytes().to_vec());
        Ok(())
    }
}

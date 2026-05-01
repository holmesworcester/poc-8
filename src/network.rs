use rusqlite::{params, Connection, OptionalExtension};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

pub type ConnectionId = [u8; 32];
pub type EventId = [u8; 32];

const FRAME_MAGIC: &[u8; 8] = b"TOPONET1";
const FRAME_HEADER_BYTES: usize = 4 + FRAME_MAGIC.len() + 32 + 32 + 4;
const FRAME_BODY_HEADER_BYTES: usize = FRAME_MAGIC.len() + 32 + 32 + 4;
const MAX_FRAME_BODY_BYTES: usize = 64 * 1024 * 1024;
const REFILL_ROW_LIMIT: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkError {
    MissingEvent {
        connection_id: ConnectionId,
        event_id: EventId,
    },
    Store(String),
    Protocol(String),
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

pub struct SqliteOutbox<'a> {
    conn: &'a Connection,
    connection_filter: Option<ConnectionId>,
}

impl<'a> SqliteOutbox<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self {
            conn,
            connection_filter: None,
        }
    }

    pub fn for_connection(conn: &'a Connection, connection_id: ConnectionId) -> Self {
        Self {
            conn,
            connection_filter: Some(connection_id),
        }
    }
}

impl Outbox for SqliteOutbox<'_> {
    fn pending_connections(&self) -> NetworkResult<Vec<ConnectionId>> {
        let rows = if let Some(connection_id) = self.connection_filter {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT DISTINCT connection_id
                     FROM outbox
                     WHERE connection_id = ?1
                     ORDER BY connection_id",
                )
                .map_err(|err| store_error("prepare pending connections", err))?;
            let mapped = stmt
                .query_map(params![connection_id.to_vec()], |row| {
                    row.get::<_, Vec<u8>>(0)
                })
                .map_err(|err| store_error("query pending connections", err))?;
            mapped
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|err| store_error("read pending connection", err))?
        } else {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT DISTINCT connection_id
                     FROM outbox
                     ORDER BY connection_id",
                )
                .map_err(|err| store_error("prepare pending connections", err))?;
            let mapped = stmt
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .map_err(|err| store_error("query pending connections", err))?;
            mapped
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|err| store_error("read pending connection", err))?
        };

        rows.into_iter()
            .map(|row| blob_to_id(row, "connection_id"))
            .collect()
    }

    fn list_outbox_for_connection(
        &self,
        connection_id: &ConnectionId,
        limit: usize,
    ) -> NetworkResult<Vec<EventId>> {
        if self
            .connection_filter
            .is_some_and(|filter| filter != *connection_id)
        {
            return Ok(Vec::new());
        }

        let mut stmt = self
            .conn
            .prepare(
                "SELECT event_id
                 FROM outbox
                 WHERE connection_id = ?1
                 ORDER BY queued_at_ms, event_id
                 LIMIT ?2",
            )
            .map_err(|err| store_error("prepare outbox rows", err))?;
        let rows = stmt
            .query_map(params![connection_id.to_vec(), limit as i64], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .map_err(|err| store_error("query outbox rows", err))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|err| store_error("read outbox row", err))?;

        rows.into_iter()
            .map(|row| blob_to_id(row, "event_id"))
            .collect()
    }

    fn event_bytes(
        &self,
        _connection_id: &ConnectionId,
        event_id: &EventId,
    ) -> NetworkResult<Option<Vec<u8>>> {
        self.conn
            .query_row(
                "SELECT canonical_bytes FROM events WHERE event_id = ?1",
                params![event_id.to_vec()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| store_error("load event bytes", err))
    }

    fn delete_outbox_rows(
        &mut self,
        connection_id: &ConnectionId,
        event_ids: &[EventId],
    ) -> NetworkResult<()> {
        for event_id in event_ids {
            self.conn
                .execute(
                    "DELETE FROM outbox WHERE connection_id = ?1 AND event_id = ?2",
                    params![connection_id.to_vec(), event_id.to_vec()],
                )
                .map_err(|err| store_error("delete outbox row", err))?;
        }
        Ok(())
    }
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
pub struct InboundFrame {
    pub connection_id: ConnectionId,
    pub event_id: EventId,
    pub event_bytes: Vec<u8>,
}

pub fn read_frame(reader: &mut impl Read) -> NetworkResult<InboundFrame> {
    let mut len = [0u8; 4];
    reader
        .read_exact(&mut len)
        .map_err(|err| NetworkError::Transport(format!("read frame length: {err}")))?;
    let body_len = u32::from_be_bytes(len) as usize;
    if body_len > MAX_FRAME_BODY_BYTES {
        return Err(NetworkError::Protocol(format!(
            "frame body too large: {body_len} bytes"
        )));
    }

    let mut body = vec![0u8; body_len];
    reader
        .read_exact(&mut body)
        .map_err(|err| NetworkError::Transport(format!("read frame body: {err}")))?;

    let mut bytes = Vec::with_capacity(4 + body_len);
    bytes.extend_from_slice(&len);
    bytes.extend_from_slice(&body);
    parse_frame(&bytes)
}

pub fn parse_frame(bytes: &[u8]) -> NetworkResult<InboundFrame> {
    if bytes.len() < 4 {
        return Err(NetworkError::Protocol("truncated frame length".to_string()));
    }

    let body_len = u32::from_be_bytes(array_4(&bytes[..4])?) as usize;
    if body_len > MAX_FRAME_BODY_BYTES {
        return Err(NetworkError::Protocol(format!(
            "frame body too large: {body_len} bytes"
        )));
    }
    if bytes.len() != 4 + body_len {
        return Err(NetworkError::Protocol(format!(
            "frame length mismatch: header={body_len} actual={}",
            bytes.len().saturating_sub(4)
        )));
    }
    if body_len < FRAME_BODY_HEADER_BYTES {
        return Err(NetworkError::Protocol("truncated frame body".to_string()));
    }

    let body = &bytes[4..];
    if &body[..FRAME_MAGIC.len()] != FRAME_MAGIC {
        return Err(NetworkError::Protocol("bad frame magic".to_string()));
    }

    let mut offset = FRAME_MAGIC.len();
    let connection_id = array_32(&body[offset..offset + 32])?;
    offset += 32;
    let event_id = array_32(&body[offset..offset + 32])?;
    offset += 32;
    let event_len = u32::from_be_bytes(array_4(&body[offset..offset + 4])?) as usize;
    offset += 4;

    if body.len() != offset + event_len {
        return Err(NetworkError::Protocol(format!(
            "event length mismatch: header={event_len} actual={}",
            body.len().saturating_sub(offset)
        )));
    }

    Ok(InboundFrame {
        connection_id,
        event_id,
        event_bytes: body[offset..].to_vec(),
    })
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

            if self.hot_bytes + frame.len() > self.max_hot_bytes && !self.hot_queue.is_empty() {
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

#[derive(Debug, Clone)]
pub struct TcpTransport {
    endpoints: BTreeMap<ConnectionId, SocketAddr>,
    connect_timeout: Duration,
    write_timeout: Duration,
}

impl Default for TcpTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpTransport {
    pub fn new() -> Self {
        Self::with_timeouts(Duration::from_secs(3), Duration::from_secs(10))
    }

    pub fn with_timeouts(connect_timeout: Duration, write_timeout: Duration) -> Self {
        Self {
            endpoints: BTreeMap::new(),
            connect_timeout,
            write_timeout,
        }
    }

    pub fn upsert_endpoint(&mut self, connection_id: ConnectionId, addr: SocketAddr) {
        self.endpoints.insert(connection_id, addr);
    }

    pub fn remove_endpoint(&mut self, connection_id: &ConnectionId) {
        self.endpoints.remove(connection_id);
    }
}

impl Transport for TcpTransport {
    fn send(&mut self, connection_id: &ConnectionId, frame: &OutboundFrame) -> NetworkResult<()> {
        let addr = self.endpoints.get(connection_id).ok_or_else(|| {
            NetworkError::Transport("missing endpoint for connection".to_string())
        })?;
        let mut stream = TcpStream::connect_timeout(addr, self.connect_timeout)
            .map_err(|err| NetworkError::Transport(format!("connect {addr}: {err}")))?;
        stream
            .set_nodelay(true)
            .map_err(|err| NetworkError::Transport(format!("set TCP_NODELAY: {err}")))?;
        stream
            .set_write_timeout(Some(self.write_timeout))
            .map_err(|err| NetworkError::Transport(format!("set write timeout: {err}")))?;
        stream
            .write_all(frame.bytes())
            .map_err(|err| NetworkError::Transport(format!("write frame: {err}")))?;
        stream
            .flush()
            .map_err(|err| NetworkError::Transport(format!("flush frame: {err}")))?;
        Ok(())
    }
}

fn store_error(context: &str, err: rusqlite::Error) -> NetworkError {
    NetworkError::Store(format!("{context}: {err}"))
}

fn blob_to_id(blob: Vec<u8>, column: &str) -> NetworkResult<[u8; 32]> {
    if blob.len() != 32 {
        return Err(NetworkError::Store(format!(
            "{column} must be 32 bytes, got {}",
            blob.len()
        )));
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&blob);
    Ok(id)
}

fn array_4(bytes: &[u8]) -> NetworkResult<[u8; 4]> {
    if bytes.len() != 4 {
        return Err(NetworkError::Protocol("expected 4 bytes".to_string()));
    }
    let mut out = [0u8; 4];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn array_32(bytes: &[u8]) -> NetworkResult<[u8; 32]> {
    if bytes.len() != 32 {
        return Err(NetworkError::Protocol("expected 32 bytes".to_string()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

//! Worker-owned queue schemas and row codecs.
//!
//! A table belongs here when a worker claims, drains, consumes, retries,
//! unblocks, or schedules work from it. Domain schemas should keep projected
//! semantic facts; this file keeps operational worker queues visible in one
//! place.
//!
//! All tables here are memory tables. They are restart-local work queues, not
//! durable semantic history. A worker either recreates needed work from durable
//! facts or accepts eventual-consistency retry through the peer protocol.
//!
//! Naming is caller-facing: `in` is work entering a worker, `out` is work a
//! worker prepared for another boundary, and event-module names are used only
//! where the queue belongs to the shared event pipeline.

use std::net::SocketAddr;
use std::str::FromStr;

use crate::core::store::{Schema, Store, TableName, TableRow};
use crate::protocol::event_modules::connection::types::ConnectionId;
use crate::protocol::event_modules::types::{
    EventId, EventIndexEntry, EventRecord, ReceiveAuthorization, ReceiveMetadata,
};
use crate::protocol::wire::{Reader, Writer};

pub const CANONICAL_IN: TableName = TableName::new("canonical.in");
pub const EVENT_RECEIVE_CONTEXT: TableName = TableName::new("event_modules.event_receive_context");
pub const RECENTLY_VALID_EVENTS: TableName = TableName::new("event_modules.recently_valid_events");
pub const APPLIED_SHARED_EVENTS: TableName = TableName::new("event_modules.applied_shared_events");
pub const SYNC_IN_EVENTS: TableName = TableName::new("sync.in");
pub const TRANSIT_OUT: TableName = TableName::new("transit.out");

pub const SCHEMAS: &[Schema] = &[
    Schema::memory_row_table("canonical.in.v1", CANONICAL_IN),
    Schema::memory_row_table(
        "event_modules.event_receive_context.v1",
        EVENT_RECEIVE_CONTEXT,
    ),
    Schema::memory_row_table(
        "event_modules.recently_valid_events.v1",
        RECENTLY_VALID_EVENTS,
    ),
    Schema::memory_row_table(
        "event_modules.applied_shared_events.v1",
        APPLIED_SHARED_EVENTS,
    ),
    Schema::memory_row_table("sync.in.v1", SYNC_IN_EVENTS),
    Schema::memory_row_table("transit.out.v1", TRANSIT_OUT),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalIn {
    pub key: Vec<u8>,
    /// Canonical event bytes recovered from a command or transit envelope.
    ///
    /// Admission asks the protocol registry to decode these bytes only after the
    /// row has been claimed, so provenance can travel as queue metadata instead
    /// of being smuggled into the event body.
    pub canonical_bytes: Vec<u8>,
    /// Direct receive context for already-classified local connection events.
    pub receive: Option<ReceiveMetadata>,
    /// Transit unwrap context for bytes that still need protocol admission
    /// classification.
    pub provenance: Option<TransitProvenance>,
}

type DecodedCanonicalIn = (Vec<u8>, Option<ReceiveMetadata>, Option<TransitProvenance>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitProvenance {
    /// Socket address that delivered the outer frame.
    pub origin: SocketAddr,
    /// Local endpoint key used to unwrap the frame.
    pub local_endpoint: EventId,
    /// Remote endpoint proven by the outer frame.
    pub sender_endpoint: EventId,
    /// Whether projection may remember `origin` as a usable route.
    pub remember_route: bool,
    /// Which transit envelope type produced the inner canonical bytes.
    pub unwrapped_with: TransitUnwrap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitUnwrap {
    /// Bootstrap envelope addressed directly to the local endpoint key.
    Bootstrap,
    /// Established connection envelope addressed through a connection id.
    Connection { connection_id: ConnectionId },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecentlyValidEvent {
    pub key: Vec<u8>,
    pub event_id: EventId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedSharedEvent {
    pub key: Vec<u8>,
    pub entry: EventIndexEntry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncInEvent {
    pub connection_id: ConnectionId,
    pub event_id: EventId,
    pub event_bytes: Vec<u8>,
}

impl SyncInEvent {
    pub fn key(&self) -> Vec<u8> {
        sync_in_event_key(self.connection_id, self.event_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitOutKey {
    pub connection_id: ConnectionId,
    pub event_id: EventId,
}

impl TransitOutKey {
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&self.connection_id);
        bytes.extend_from_slice(&self.event_id);
        bytes
    }
}

pub fn canonical_in_row(event: EventRecord, receive: Option<ReceiveMetadata>) -> TableRow {
    let value = encode_canonical_in(&event.canonical_bytes, receive, None);
    TableRow {
        table: CANONICAL_IN,
        key: canonical_in_key(&value),
        value,
    }
}

pub fn transit_canonical_in_row(
    canonical_bytes: Vec<u8>,
    provenance: TransitProvenance,
) -> TableRow {
    let value = encode_canonical_in(&canonical_bytes, None, Some(provenance));
    TableRow {
        table: CANONICAL_IN,
        key: canonical_in_key(&value),
        value,
    }
}

pub fn claim_canonical_in(store: &Store, limit: usize) -> rusqlite::Result<Vec<CanonicalIn>> {
    store
        .table_rows_with_key_prefix(CANONICAL_IN, &[], limit)?
        .into_iter()
        .map(|(key, value)| {
            let (canonical_bytes, receive, provenance) =
                decode_canonical_in(&value).map_err(table_error)?;
            Ok(CanonicalIn {
                key,
                canonical_bytes,
                receive,
                provenance,
            })
        })
        .collect()
}

pub fn event_receive_context_row(event_id: EventId, receive: ReceiveMetadata) -> TableRow {
    let mut writer = Writer::new();
    encode_receive(&mut writer, Some(receive));
    TableRow {
        table: EVENT_RECEIVE_CONTEXT,
        key: event_id.to_vec(),
        value: writer.finish(),
    }
}

pub fn event_receive_context(
    store: &Store,
    event_id: &EventId,
) -> rusqlite::Result<Option<ReceiveMetadata>> {
    let Some(value) = store.table_row(EVENT_RECEIVE_CONTEXT, event_id)? else {
        return Ok(None);
    };
    let mut reader = Reader::new(&value, "event receive context row");
    let receive = decode_receive(&mut reader).map_err(table_error)?;
    reader.finish().map_err(table_error)?;
    Ok(receive)
}

pub fn delete_event_receive_context_in_tx(
    store: &Store,
    event_id: &EventId,
) -> rusqlite::Result<usize> {
    store.delete_table_rows_in_tx(EVENT_RECEIVE_CONTEXT, vec![event_id.to_vec()])
}

pub fn recently_valid_event_row(event_id: EventId) -> TableRow {
    TableRow {
        table: RECENTLY_VALID_EVENTS,
        key: event_id.to_vec(),
        value: event_id.to_vec(),
    }
}

pub fn claim_recently_valid_events(
    store: &Store,
    limit: usize,
) -> rusqlite::Result<Vec<RecentlyValidEvent>> {
    store
        .table_rows_with_key_prefix(RECENTLY_VALID_EVENTS, &[], limit)?
        .into_iter()
        .map(|(key, value)| {
            let event_id = vec_to_id(value)?;
            Ok(RecentlyValidEvent { key, event_id })
        })
        .collect()
}

pub fn applied_shared_event_row(entry: EventIndexEntry) -> TableRow {
    TableRow {
        table: APPLIED_SHARED_EVENTS,
        key: timestamp_key(entry.timestamp, &entry.event_id),
        value: encode_workspace_index_value(entry.workspace_id),
    }
}

pub fn claim_applied_shared_events(
    store: &Store,
    limit: usize,
) -> rusqlite::Result<Vec<AppliedSharedEvent>> {
    store
        .table_rows_with_key_prefix(APPLIED_SHARED_EVENTS, &[], limit)?
        .into_iter()
        .map(|(key, value)| {
            let (timestamp, event_id) = split_timestamp_key(&key)?;
            let workspace_id = decode_workspace_index_value(&value)?;
            Ok(AppliedSharedEvent {
                key,
                entry: EventIndexEntry {
                    event_id,
                    timestamp,
                    workspace_id,
                },
            })
        })
        .collect()
}

pub fn sync_in_event_row(
    connection_id: ConnectionId,
    event_id: EventId,
    event_bytes: Vec<u8>,
) -> TableRow {
    TableRow {
        table: SYNC_IN_EVENTS,
        key: sync_in_event_key(connection_id, event_id),
        value: event_bytes,
    }
}

pub fn sync_in_event_prefix(connection_id: ConnectionId) -> Vec<u8> {
    connection_id.to_vec()
}

pub fn claim_sync_in_events(store: &Store, limit: usize) -> rusqlite::Result<Vec<SyncInEvent>> {
    store
        .table_rows_with_key_prefix(SYNC_IN_EVENTS, &[], limit)?
        .into_iter()
        .map(|(key, value)| decode_sync_in_event(key, value).map_err(table_error))
        .collect()
}

pub fn claim_sync_in_events_for_connection(
    store: &Store,
    connection_id: ConnectionId,
    limit: usize,
) -> rusqlite::Result<Vec<SyncInEvent>> {
    store
        .table_rows_with_key_prefix(SYNC_IN_EVENTS, &sync_in_event_prefix(connection_id), limit)?
        .into_iter()
        .map(|(key, value)| decode_sync_in_event(key, value).map_err(table_error))
        .collect()
}

pub fn decode_sync_in_event(key: Vec<u8>, event_bytes: Vec<u8>) -> Result<SyncInEvent, String> {
    if key.len() != 64 {
        return Err("sync in event key must be 64 bytes".to_string());
    }
    let mut connection_id = [0; 32];
    connection_id.copy_from_slice(&key[..32]);
    let mut event_id = [0; 32];
    event_id.copy_from_slice(&key[32..]);
    Ok(SyncInEvent {
        connection_id,
        event_id,
        event_bytes,
    })
}

pub fn transit_out_row(connection_id: ConnectionId, event_id: EventId) -> TableRow {
    let key = TransitOutKey {
        connection_id,
        event_id,
    }
    .to_bytes();
    TableRow {
        table: TRANSIT_OUT,
        key,
        value: Vec::new(),
    }
}

pub fn transit_out_prefix(connection_id: ConnectionId) -> Vec<u8> {
    connection_id.to_vec()
}

pub fn decode_transit_out_key(bytes: &[u8]) -> Result<TransitOutKey, String> {
    if bytes.len() != 64 {
        return Err("out key must be 64 bytes".to_string());
    }
    let mut connection_id = [0; 32];
    connection_id.copy_from_slice(&bytes[..32]);
    let mut event_id = [0; 32];
    event_id.copy_from_slice(&bytes[32..]);
    Ok(TransitOutKey {
        connection_id,
        event_id,
    })
}

fn canonical_in_key(value: &[u8]) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"topo:event-in:v1:");
    hasher.update(value);
    hasher.finalize().as_bytes().to_vec()
}

fn encode_canonical_in(
    canonical_bytes: &[u8],
    receive: Option<ReceiveMetadata>,
    provenance: Option<TransitProvenance>,
) -> Vec<u8> {
    let mut writer = Writer::new();
    writer.sized_bytes(canonical_bytes);
    encode_receive(&mut writer, receive);
    encode_transit_provenance(&mut writer, provenance);
    writer.finish()
}

fn decode_canonical_in(bytes: &[u8]) -> Result<DecodedCanonicalIn, String> {
    let mut reader = Reader::new(bytes, "canonical in row");
    let canonical_bytes = reader.sized_bytes()?;
    let receive = decode_receive(&mut reader)?;
    let provenance = decode_transit_provenance(&mut reader)?;
    reader.finish()?;
    Ok((canonical_bytes, receive, provenance))
}

fn encode_receive(writer: &mut Writer, receive: Option<ReceiveMetadata>) {
    let Some(receive) = receive else {
        writer.u8(0);
        return;
    };
    writer.u8(1);
    writer.sized_bytes(receive.origin().to_string().as_bytes());
    writer.id(&receive.local_endpoint());
    writer.id(&receive.remote_endpoint());
    writer.u8(u8::from(receive.remember_route()));
    match receive.authorization() {
        ReceiveAuthorization::BootstrapInvite => writer.u8(0),
        ReceiveAuthorization::EndpointReceive => writer.u8(1),
    }
}

fn decode_receive(reader: &mut Reader<'_>) -> Result<Option<ReceiveMetadata>, String> {
    match reader.u8()? {
        0 => Ok(None),
        1 => {
            let origin = String::from_utf8(reader.sized_bytes()?)
                .map_err(|err| format!("canonical in receive origin is not utf8: {err}"))
                .and_then(|addr| {
                    SocketAddr::from_str(&addr)
                        .map_err(|err| format!("canonical in receive origin is invalid: {err}"))
                })?;
            let local_endpoint = reader.id()?;
            let remote_endpoint = reader.id()?;
            let remember_route = match reader.u8()? {
                0 => false,
                1 => true,
                other => return Err(format!("unknown canonical in remember-route flag {other}")),
            };
            match reader.u8()? {
                0 => Ok(Some(ReceiveMetadata::bootstrap_invite(
                    origin,
                    local_endpoint,
                    remote_endpoint,
                    remember_route,
                ))),
                1 => Ok(Some(ReceiveMetadata::endpoint_receive(
                    origin,
                    local_endpoint,
                    remote_endpoint,
                    remember_route,
                ))),
                other => Err(format!(
                    "unknown canonical in receive authorization {other}"
                )),
            }
        }
        other => Err(format!("unknown canonical in receive flag {other}")),
    }
}

fn encode_transit_provenance(writer: &mut Writer, provenance: Option<TransitProvenance>) {
    let Some(provenance) = provenance else {
        writer.u8(0);
        return;
    };
    writer.u8(1);
    writer.sized_bytes(provenance.origin.to_string().as_bytes());
    writer.id(&provenance.local_endpoint);
    writer.id(&provenance.sender_endpoint);
    writer.u8(u8::from(provenance.remember_route));
    match provenance.unwrapped_with {
        TransitUnwrap::Bootstrap => writer.u8(0),
        TransitUnwrap::Connection { connection_id } => {
            writer.u8(1);
            writer.id(&connection_id);
        }
    }
}

fn decode_transit_provenance(reader: &mut Reader<'_>) -> Result<Option<TransitProvenance>, String> {
    match reader.u8()? {
        0 => Ok(None),
        1 => {
            let origin = String::from_utf8(reader.sized_bytes()?)
                .map_err(|err| format!("canonical in transit origin is not utf8: {err}"))
                .and_then(|addr| {
                    SocketAddr::from_str(&addr)
                        .map_err(|err| format!("canonical in transit origin is invalid: {err}"))
                })?;
            let local_endpoint = reader.id()?;
            let sender_endpoint = reader.id()?;
            let remember_route = match reader.u8()? {
                0 => false,
                1 => true,
                other => {
                    return Err(format!(
                        "unknown canonical in transit remember flag {other}"
                    ))
                }
            };
            let unwrapped_with = match reader.u8()? {
                0 => TransitUnwrap::Bootstrap,
                1 => TransitUnwrap::Connection {
                    connection_id: reader.id()?,
                },
                other => return Err(format!("unknown canonical in transit unwrap tag {other}")),
            };
            Ok(Some(TransitProvenance {
                origin,
                local_endpoint,
                sender_endpoint,
                remember_route,
                unwrapped_with,
            }))
        }
        other => Err(format!(
            "unknown canonical in transit provenance flag {other}"
        )),
    }
}

fn sync_in_event_key(connection_id: ConnectionId, event_id: EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&connection_id);
    key.extend_from_slice(&event_id);
    key
}

fn timestamp_key(timestamp: u64, event_id: &EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(40);
    key.extend_from_slice(&timestamp.to_be_bytes());
    key.extend_from_slice(event_id);
    key
}

fn split_timestamp_key(key: &[u8]) -> rusqlite::Result<(u64, EventId)> {
    if key.len() != 40 {
        return Err(table_error(format!(
            "timestamp key should be 40 bytes, got {}",
            key.len()
        )));
    }
    let timestamp = u64::from_be_bytes(key[..8].try_into().expect("slice length checked"));
    Ok((timestamp, vec_to_id(key[8..].to_vec())?))
}

fn encode_workspace_index_value(workspace_id: Option<EventId>) -> Vec<u8> {
    let mut out = Vec::with_capacity(33);
    match workspace_id {
        Some(workspace_id) => {
            out.push(1);
            out.extend_from_slice(&workspace_id);
        }
        None => {
            out.push(0);
            out.extend_from_slice(&[0; 32]);
        }
    }
    out
}

fn decode_workspace_index_value(value: &[u8]) -> rusqlite::Result<Option<EventId>> {
    if value.len() != 33 {
        return Err(table_error(format!(
            "workspace index value should be 33 bytes, got {}",
            value.len()
        )));
    }
    let mut offset = 0;
    read_optional_id(value, &mut offset)
}

fn read_optional_id(bytes: &[u8], offset: &mut usize) -> rusqlite::Result<Option<EventId>> {
    let present = read_u8(bytes, offset)?;
    let id = read_id(bytes, offset)?;
    match present {
        0 => Ok(None),
        1 => Ok(Some(id)),
        _ => Err(table_error(format!("invalid optional id flag {present}"))),
    }
}

fn read_id(bytes: &[u8], offset: &mut usize) -> rusqlite::Result<EventId> {
    let end = offset
        .checked_add(32)
        .ok_or_else(|| table_error("row id offset overflow".to_string()))?;
    let raw = bytes
        .get(*offset..end)
        .ok_or_else(|| table_error("row id is truncated".to_string()))?;
    *offset = end;
    vec_to_id(raw.to_vec())
}

fn read_u8(bytes: &[u8], offset: &mut usize) -> rusqlite::Result<u8> {
    let byte = *bytes
        .get(*offset)
        .ok_or_else(|| table_error("row u8 is truncated".to_string()))?;
    *offset += 1;
    Ok(byte)
}

fn vec_to_id(bytes: Vec<u8>) -> rusqlite::Result<EventId> {
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        table_error(format!("expected 32-byte event id, got {}", bytes.len()))
    })
}

fn table_error(err: String) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(err)
}

#[cfg(test)]
mod tests {
    use crate::protocol::Protocol;

    use super::*;

    // Invariant: transit out rows are memory restart work.
    #[test]
    fn transit_out_rows_are_memory_restart_work() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let path = tmp.path().join("connection-out.db");
        {
            let store = Protocol::open_store(&path).expect("open first store");
            store
                .insert_table_rows(vec![transit_out_row([1; 32], [2; 32])])
                .expect("insert temp out row");
            assert_eq!(
                store.table_row_count(TRANSIT_OUT).expect("count temp out"),
                1
            );
        }

        let store = Protocol::open_store(&path).expect("reopen store");
        assert_eq!(
            store
                .table_row_count(TRANSIT_OUT)
                .expect("count temp out after reopen"),
            0
        );
    }
}

//! Opaque byte queues used by the TCP pump.
//!
//! Core owns the mechanics of queueing bytes by route because the TCP code
//! needs a place to stage frames before and after socket writes. These queues
//! are memory-local operational state, not durable protocol truth. The only
//! interpretation here is the route key needed to claim a bounded batch for one
//! remote address without scanning every pending row.
//!
//! The queue key is intentionally deterministic: the same route and same bytes
//! map to the same row. That gives the boundary a cheap idempotence property
//! while callers are still free to retry after crashes. If this file starts
//! parsing the payload, naming protocol concepts, or deciding when a row should
//! be produced, it has crossed out of core and into an event module.

use std::net::SocketAddr;
use std::str::FromStr;

use crate::core::store::{Schema, Store, TableName, TableRow};

pub const OUTBOUND_TABLE: TableName = TableName::new("core.network.outbound");
pub const INBOUND_TABLE: TableName = TableName::new("core.network.inbound");

/// Store declarations for the two core-owned byte queues.
///
/// Network queues are core IO state, so their schemas live here rather than in
/// the protocol registry. They still use the same generic row-table shape as
/// module-owned tables, but they are restart-local because higher layers can
/// regenerate meaningful sends and resend missing inbound facts.
pub const SCHEMAS: &[Schema] = &[
    Schema::memory_row_table("core.network.outbound.v1", OUTBOUND_TABLE),
    Schema::memory_row_table("core.network.inbound.v1", INBOUND_TABLE),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkTarget {
    addr: SocketAddr,
}

impl NetworkTarget {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    pub fn addr(self) -> SocketAddr {
        self.addr
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkSource {
    addr: SocketAddr,
}

impl NetworkSource {
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    pub fn addr(self) -> SocketAddr {
        self.addr
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundNetworkRow {
    pub key: Vec<u8>,
    pub target: NetworkTarget,
    pub bytes: Vec<u8>,
}

impl OutboundNetworkRow {
    pub fn new(target: NetworkTarget, bytes: Vec<u8>) -> Self {
        Self {
            key: queue_key(b"outbound", target.addr(), &bytes),
            target,
            bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundNetworkRow {
    pub key: Vec<u8>,
    pub source: NetworkSource,
    pub bytes: Vec<u8>,
}

impl InboundNetworkRow {
    pub fn new(source: NetworkSource, bytes: Vec<u8>) -> Self {
        Self {
            key: queue_key(b"inbound", source.addr(), &bytes),
            source,
            bytes,
        }
    }
}

/// Build deterministic queued rows for a target and a set of opaque frames.
pub fn outbound_rows(target: NetworkTarget, frames: Vec<Vec<u8>>) -> Vec<OutboundNetworkRow> {
    frames
        .into_iter()
        .map(|bytes| OutboundNetworkRow::new(target, bytes))
        .collect()
}

/// Insert outbound rows idempotently.
///
/// The store handles the transaction; this helper only converts typed queue
/// rows to generic `TableRow`s. Deletion is a separate, explicit step so callers
/// can commit their own "sent" bookkeeping at the right boundary.
pub fn enqueue_outbound(store: &Store, rows: &[OutboundNetworkRow]) -> Result<usize, String> {
    store
        .insert_table_rows(rows.iter().map(outbound_table_row).collect())
        .map_err(|err| format!("enqueue outbound network rows: {err}"))
}

/// Claim at most `limit` outbound rows for one concrete target.
///
/// The target prefix in the row key is the performance property that matters:
/// a slow route does not require a full-table scan and does not block other
/// routes from being claimed by their own callers.
pub fn claim_outbound_for_target(
    store: &Store,
    target: NetworkTarget,
    limit: usize,
) -> Result<Vec<OutboundNetworkRow>, String> {
    store
        .table_rows_with_key_prefix(OUTBOUND_TABLE, &target_prefix(target.addr()), limit)
        .map_err(|err| format!("claim outbound network rows: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_outbound(key, &value))
        .collect()
}

/// Remove outbound rows that have been successfully handed off by the caller.
pub fn delete_outbound(store: &Store, rows: &[OutboundNetworkRow]) -> Result<(), String> {
    store
        .delete_table_rows(
            OUTBOUND_TABLE,
            rows.iter().map(|row| row.key.clone()).collect(),
        )
        .map(|_| ())
        .map_err(|err| format!("delete outbound network rows: {err}"))
}

/// Insert inbound rows idempotently.
pub fn enqueue_inbound(store: &Store, rows: &[InboundNetworkRow]) -> Result<usize, String> {
    store
        .insert_table_rows(rows.iter().map(inbound_table_row).collect())
        .map_err(|err| format!("enqueue inbound network rows: {err}"))
}

/// Remove inbound rows after the caller has accepted responsibility for them.
pub fn delete_inbound(store: &Store, rows: &[InboundNetworkRow]) -> Result<(), String> {
    store
        .delete_table_rows(
            INBOUND_TABLE,
            rows.iter().map(|row| row.key.clone()).collect(),
        )
        .map(|_| ())
        .map_err(|err| format!("delete inbound network rows: {err}"))
}

/// Claim at most `limit` inbound byte rows, ordered by the deterministic queue key.
pub fn claim_inbound(store: &Store, limit: usize) -> Result<Vec<InboundNetworkRow>, String> {
    store
        .table_rows_with_key_prefix(INBOUND_TABLE, &[], limit)
        .map_err(|err| format!("claim inbound network rows: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_inbound(key, &value))
        .collect()
}

/// Remove inbound rows inside a caller-owned transaction after admission.
pub fn delete_inbound_in_tx(store: &Store, rows: &[InboundNetworkRow]) -> rusqlite::Result<usize> {
    store.delete_table_rows_in_tx(
        INBOUND_TABLE,
        rows.iter().map(|row| row.key.clone()).collect(),
    )
}

fn outbound_table_row(row: &OutboundNetworkRow) -> TableRow {
    TableRow {
        table: OUTBOUND_TABLE,
        key: row.key.clone(),
        value: row.bytes.clone(),
    }
}

fn inbound_table_row(row: &InboundNetworkRow) -> TableRow {
    TableRow {
        table: INBOUND_TABLE,
        key: row.key.clone(),
        value: row.bytes.clone(),
    }
}

fn decode_outbound(key: Vec<u8>, value: &[u8]) -> Result<OutboundNetworkRow, String> {
    let addr = decode_addr_from_key(&key)?;
    Ok(OutboundNetworkRow {
        key,
        target: NetworkTarget::new(addr),
        bytes: value.to_vec(),
    })
}

fn decode_inbound(key: Vec<u8>, value: &[u8]) -> Result<InboundNetworkRow, String> {
    let addr = decode_addr_from_key(&key)?;
    Ok(InboundNetworkRow {
        key,
        source: NetworkSource::new(addr),
        bytes: value.to_vec(),
    })
}

fn target_prefix(addr: SocketAddr) -> Vec<u8> {
    let addr = addr.to_string();
    let addr = addr.as_bytes();
    let mut out = Vec::with_capacity(4 + addr.len());
    out.extend_from_slice(&(addr.len() as u32).to_be_bytes());
    out.extend_from_slice(addr);
    out
}

fn decode_addr_from_key(key: &[u8]) -> Result<SocketAddr, String> {
    let mut offset = 0;
    let addr_len = read_u32(key, &mut offset)? as usize;
    let addr_end = offset
        .checked_add(addr_len)
        .ok_or_else(|| "network row address length overflow".to_string())?;
    let addr_bytes = key
        .get(offset..addr_end)
        .ok_or_else(|| "network row address is truncated".to_string())?;
    if key.len() != addr_end + 32 {
        return Err("network row key has invalid length".to_string());
    }
    std::str::from_utf8(addr_bytes)
        .map_err(|_| "network row address is not utf8".to_string())
        .and_then(|addr| {
            SocketAddr::from_str(addr).map_err(|_| "network row address is invalid".to_string())
        })
}

fn read_u32(value: &[u8], offset: &mut usize) -> Result<u32, String> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| "network row length overflow".to_string())?;
    let bytes: [u8; 4] = value
        .get(*offset..end)
        .ok_or_else(|| "network row length is truncated".to_string())?
        .try_into()
        .expect("slice length checked");
    *offset = end;
    Ok(u32::from_be_bytes(bytes))
}

fn queue_key(kind: &[u8], addr: SocketAddr, bytes: &[u8]) -> Vec<u8> {
    // Include direction, route, length, and bytes in the digest. The route is
    // also present as a plain prefix for efficient claims; the digest makes the
    // rest of the key compact and stable.
    let mut key = target_prefix(addr);
    let mut hasher = blake3::Hasher::new();
    hasher.update(kind);
    hasher.update(addr.to_string().as_bytes());
    hasher.update(&(bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    key.extend_from_slice(hasher.finalize().as_bytes());
    key
}

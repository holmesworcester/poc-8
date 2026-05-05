//! Compare-driven sync commands.
//!
//! This is the POC's range-negentropy reconciliation engine. A peer asks "does
//! this timestamp range have the same count and fingerprint?" If not, the
//! responder answers with child compares until a timestamp leaf can advertise
//! concrete ids. Missing ids become need ids; received need ids queue durable
//! event ids to the connection outbox. The command emits event records and ids
//! only: transit wrapping and TCP framing are outside sync.

use crate::protocol::event_modules::types::{EventId, EventIndexEntry};

use super::super::have_id::{self, types::HaveIdEvent};
use super::super::need_id::{self, types::NeedIdEvent};
use super::types::{CompareEvent, RangeSummary, TimestampRange};

const MAX_HAVE_IDS_PER_RANGE: usize = 64;

pub trait ReadContext {
    // The caller must provide a connection-scoped view. These methods talk in
    // generic ranges and ids because the negentropy algorithm is generic, but the
    // implementation is responsible for hiding any event outside the connection's
    // mutual workspace set.
    /// Summarize every shared event whose timestamp is inside the range.
    fn summary(&self, range: TimestampRange) -> Result<RangeSummary, String>;
    /// Enumerate ids in one timestamp range when summaries differ.
    fn ids_in_range(&self, range: TimestampRange) -> Result<Vec<EventIndexEntry>, String>;
    /// Return the first and last local timestamp present in a range.
    fn timestamp_bounds(&self, range: TimestampRange) -> Result<Option<(u64, u64)>, String>;
    /// Check whether an advertised id is already present locally.
    fn has_event(&self, event_id: &EventId) -> Result<bool, String>;
    /// Check whether a locally present id may be served to this connection.
    fn can_send_event(&self, event_id: &EventId) -> Result<bool, String>;
    /// Enumerate present transitive dependencies for root ids in a leaf range.
    fn dependency_closure_entries(
        &self,
        roots: &[EventIndexEntry],
    ) -> Result<Vec<EventIndexEntry>, String>;
    /// Suppress ids already advertised to this connection in the current worker.
    fn fresh_have_entries(
        &self,
        connection_id: EventId,
        entries: Vec<EventIndexEntry>,
    ) -> Result<Vec<EventIndexEntry>, String>;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub sent_events: usize,
    pub events: Vec<crate::protocol::event_modules::types::EventRecord>,
    pub send_event_ids: Vec<EventId>,
}

pub fn start(
    context: &impl ReadContext,
    connection_id: EventId,
    range: TimestampRange,
) -> Result<SyncReport, String> {
    // Manual start sends only one compare over the caller-selected range. The
    // rest of the exchange is driven by projected inbound compare rows.
    let mut report = SyncReport::default();
    report
        .events
        .push(super::codec::outbound_record(CompareEvent {
            connection_id,
            range,
            summary: context.summary(range)?,
            response_requested: true,
        })?);
    Ok(report)
}

pub fn handle_inbound_event(
    context: &impl ReadContext,
    expected_connection_id: EventId,
    bytes: &[u8],
) -> Result<SyncReport, String> {
    let mut report = SyncReport::default();
    if super::codec::is_event(bytes) {
        let event = super::codec::decode(bytes)?;
        ensure_connection(event.connection_id, expected_connection_id)?;
        let local = context.summary(event.range)?;
        if local != event.summary {
            let events = compare_response(
                context,
                event.connection_id,
                event.range,
                local,
                event.summary,
                event.response_requested,
            )?;
            report.events.extend(events);
        }
        return Ok(report);
    }
    if have_id::codec::is_event(bytes) {
        let event = have_id::codec::decode(bytes)?;
        ensure_connection(event.connection_id, expected_connection_id)?;
        if !context.has_event(&event.id)? {
            report
                .events
                .push(need_id::codec::outbound_record(NeedIdEvent {
                    connection_id: event.connection_id,
                    id: event.id,
                })?);
        }
        return Ok(report);
    }
    if need_id::codec::is_event(bytes) {
        let event = need_id::codec::decode(bytes)?;
        ensure_connection(event.connection_id, expected_connection_id)?;
        // Need-id is intentionally not treated as proof that we should send the
        // event. Peers can guess ids, replay ids, or request ids from stale
        // summaries. The scoped ReadContext is the authorization check.
        if context.can_send_event(&event.id)? {
            report.send_event_ids.push(event.id);
            report.sent_events = 1;
        }
        return Ok(report);
    }
    Err("not an inbound sync event".to_string())
}

fn ensure_connection(
    connection_id: EventId,
    expected_connection_id: EventId,
) -> Result<(), String> {
    if connection_id != expected_connection_id {
        return Err("sync event used a different connection id".to_string());
    }
    Ok(())
}

fn compare_response(
    context: &impl ReadContext,
    connection_id: EventId,
    range: TimestampRange,
    local: RangeSummary,
    remote: RangeSummary,
    response_requested: bool,
) -> Result<Vec<crate::protocol::event_modules::types::EventRecord>, String> {
    let mut records = Vec::new();
    if local.count == 0 {
        if response_requested {
            records.push(super::codec::outbound_record(CompareEvent {
                connection_id,
                range,
                summary: local,
                response_requested: false,
            })?);
        }
        return Ok(records);
    }

    if local.count <= MAX_HAVE_IDS_PER_RANGE as u64 {
        let entries = context.ids_in_range(range)?;
        let dep_entries = context
            .fresh_have_entries(connection_id, context.dependency_closure_entries(&entries)?)?;
        let entries = context.fresh_have_entries(connection_id, entries)?;
        for entry in dep_entries.into_iter().chain(entries.into_iter()) {
            records.push(have_id::codec::outbound_record(HaveIdEvent {
                connection_id,
                timestamp: entry.timestamp,
                id: entry.event_id,
            })?);
        }
        if response_requested && remote.count > 0 {
            records.push(super::codec::outbound_record(CompareEvent {
                connection_id,
                range,
                summary: local,
                response_requested: false,
            })?);
        }
        return Ok(records);
    }

    let (min_timestamp, max_timestamp) = context
        .timestamp_bounds(range)?
        .ok_or_else(|| "non-empty range summary had no timestamp bounds".to_string())?;
    if min_timestamp == max_timestamp {
        let entries = context.ids_in_range(range)?;
        let dep_entries = context
            .fresh_have_entries(connection_id, context.dependency_closure_entries(&entries)?)?;
        let entries = context.fresh_have_entries(connection_id, entries)?;
        for entry in dep_entries.into_iter().chain(entries.into_iter()) {
            records.push(have_id::codec::outbound_record(HaveIdEvent {
                connection_id,
                timestamp: entry.timestamp,
                id: entry.event_id,
            })?);
        }
        if response_requested && remote.count > 0 {
            records.push(super::codec::outbound_record(CompareEvent {
                connection_id,
                range,
                summary: local,
                response_requested: false,
            })?);
        }
        return Ok(records);
    }

    if range.start < min_timestamp {
        let empty_left = TimestampRange {
            start: range.start,
            end: min_timestamp - 1,
        };
        records.push(super::codec::outbound_record(CompareEvent {
            connection_id,
            range: empty_left,
            summary: RangeSummary::default(),
            response_requested: true,
        })?);
    }
    if max_timestamp < range.end {
        let empty_right = TimestampRange {
            start: max_timestamp + 1,
            end: range.end,
        };
        records.push(super::codec::outbound_record(CompareEvent {
            connection_id,
            range: empty_right,
            summary: RangeSummary::default(),
            response_requested: true,
        })?);
    }

    let local_range = TimestampRange {
        start: min_timestamp,
        end: max_timestamp,
    };
    if let Some((left, right)) = local_range.split() {
        for child in [left, right] {
            records.push(super::codec::outbound_record(CompareEvent {
                connection_id,
                range: child,
                summary: context.summary(child)?,
                response_requested: true,
            })?);
        }
        return Ok(records);
    }
    Ok(records)
}

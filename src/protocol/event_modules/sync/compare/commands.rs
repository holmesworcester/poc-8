//! Compare-driven sync commands.
//!
//! This is the POC's range-negentropy reconciliation engine. A peer asks "does
//! this timestamp range have the same count and fingerprint?" If not, the
//! responder answers with child compares until a timestamp leaf can advertise
//! concrete ids. Missing ids become need ids; received need ids queue durable
//! event ids to transit out. The command emits event records and ids
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
    /// Return ids that should be advertised in the current response.
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
    start_with_summary(context.summary(range)?, connection_id, range)
}

pub fn start_with_summary(
    summary: RangeSummary,
    connection_id: EventId,
    range: TimestampRange,
) -> Result<SyncReport, String> {
    // Start sends one compare over the caller-selected range. The
    // rest of the exchange is driven by projected inbound compare rows.
    let mut report = SyncReport::default();
    report
        .events
        .push(super::codec::outbound_record(CompareEvent {
            connection_id,
            range,
            summary,
            response_requested: true,
        })?);
    report.sent_events = 1;
    Ok(report)
}

pub fn handle_inbound_event(
    context: &impl ReadContext,
    expected_connection_id: EventId,
    response_connection_id: EventId,
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
                response_connection_id,
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
                    connection_id: response_connection_id,
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

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashSet, VecDeque};

    use crate::protocol::event_modules::types::EventIndexEntry;

    use super::*;

    const CONNECTION_ID: EventId = [7; 32];
    const WORKSPACE_ID: EventId = [9; 32];

    #[derive(Clone)]
    struct SetContext {
        entries: Vec<EventIndexEntry>,
        ids: HashSet<EventId>,
    }

    impl SetContext {
        fn new(mut entries: Vec<EventIndexEntry>) -> Self {
            entries.sort_by_key(|entry| (entry.timestamp, entry.event_id));
            let ids = entries.iter().map(|entry| entry.event_id).collect();
            Self { entries, ids }
        }

        fn entries_in_range(&self, range: TimestampRange) -> Vec<EventIndexEntry> {
            self.entries
                .iter()
                .filter(|entry| range.start <= entry.timestamp && entry.timestamp <= range.end)
                .cloned()
                .collect()
        }
    }

    impl ReadContext for SetContext {
        fn summary(&self, range: TimestampRange) -> Result<RangeSummary, String> {
            Ok(summary_of(&self.entries_in_range(range)))
        }

        fn ids_in_range(&self, range: TimestampRange) -> Result<Vec<EventIndexEntry>, String> {
            Ok(self.entries_in_range(range))
        }

        fn timestamp_bounds(&self, range: TimestampRange) -> Result<Option<(u64, u64)>, String> {
            let entries = self.entries_in_range(range);
            let Some(first) = entries.first() else {
                return Ok(None);
            };
            let last = entries.last().unwrap_or(first);
            Ok(Some((first.timestamp, last.timestamp)))
        }

        fn has_event(&self, event_id: &EventId) -> Result<bool, String> {
            Ok(self.ids.contains(event_id))
        }

        fn can_send_event(&self, event_id: &EventId) -> Result<bool, String> {
            Ok(self.ids.contains(event_id))
        }

        fn dependency_closure_entries(
            &self,
            _roots: &[EventIndexEntry],
        ) -> Result<Vec<EventIndexEntry>, String> {
            Ok(Vec::new())
        }

        fn fresh_have_entries(
            &self,
            _connection_id: EventId,
            entries: Vec<EventIndexEntry>,
        ) -> Result<Vec<EventIndexEntry>, String> {
            Ok(entries)
        }
    }

    #[derive(Clone, Copy)]
    enum Recipient {
        Left,
        Right,
    }

    #[test]
    fn large_scattered_differences_reconcile_with_bounded_idempotent_exchange() {
        let common_count = 65_536u64;
        let diff_count = 768u64;
        let stride = u64::MAX / (common_count + diff_count + 8);
        let mut left_entries = Vec::with_capacity((common_count + diff_count) as usize);
        let mut right_entries = Vec::with_capacity((common_count + diff_count) as usize);
        let mut left_unique = BTreeSet::new();
        let mut right_unique = BTreeSet::new();

        for idx in 0..common_count {
            let entry = EventIndexEntry {
                event_id: test_id(b"common", idx),
                timestamp: 1 + idx.saturating_mul(stride),
                workspace_id: Some(WORKSPACE_ID),
            };
            left_entries.push(entry.clone());
            right_entries.push(entry);
        }

        for idx in 0..diff_count {
            // A prime stride scatters differences throughout the large common
            // set instead of clustering them into one easy range.
            let slot = (idx * 7_919) % common_count;
            let base_timestamp = 1 + slot.saturating_mul(stride);
            let left_id = test_id(b"left-only", idx);
            let right_id = test_id(b"right-only", idx);
            left_unique.insert(left_id);
            right_unique.insert(right_id);
            left_entries.push(EventIndexEntry {
                event_id: left_id,
                timestamp: base_timestamp
                    .saturating_add(stride / 3)
                    .max(base_timestamp),
                workspace_id: Some(WORKSPACE_ID),
            });
            right_entries.push(EventIndexEntry {
                event_id: right_id,
                timestamp: base_timestamp
                    .saturating_add((2 * stride) / 3)
                    .max(base_timestamp.saturating_add(1)),
                workspace_id: Some(WORKSPACE_ID),
            });
        }

        let result = run_exchange(
            SetContext::new(left_entries),
            SetContext::new(right_entries),
        );

        assert_eq!(result.delivered_to_left, right_unique);
        assert_eq!(result.delivered_to_right, left_unique);
        assert!(
            result.processed_protocol_events < 150_000,
            "scattered sync exchange produced too many protocol events: {}",
            result.processed_protocol_events
        );
    }

    #[test]
    fn mostly_disjoint_large_sets_reconcile_with_bounded_exchange() {
        let count = 32_768u64;
        let stride = u64::MAX / (count + 8);
        let mut left_entries = Vec::with_capacity(count as usize);
        let mut right_entries = Vec::with_capacity(count as usize);
        let mut left_unique = BTreeSet::new();
        let mut right_unique = BTreeSet::new();

        for idx in 0..count {
            let left_id = test_id(b"disjoint-left", idx);
            let right_id = test_id(b"disjoint-right", idx);
            left_unique.insert(left_id);
            right_unique.insert(right_id);
            left_entries.push(EventIndexEntry {
                event_id: left_id,
                timestamp: 1 + idx.saturating_mul(stride),
                workspace_id: Some(WORKSPACE_ID),
            });
            right_entries.push(EventIndexEntry {
                event_id: right_id,
                timestamp: 1 + idx.saturating_mul(stride),
                workspace_id: Some(WORKSPACE_ID),
            });
        }

        let result = run_exchange(
            SetContext::new(left_entries),
            SetContext::new(right_entries),
        );

        assert_eq!(result.delivered_to_left, right_unique);
        assert_eq!(result.delivered_to_right, left_unique);
        assert!(
            result.processed_protocol_events < 250_000,
            "mostly-disjoint sync exchange produced too many protocol events: {}",
            result.processed_protocol_events
        );
    }

    struct ExchangeResult {
        delivered_to_left: BTreeSet<EventId>,
        delivered_to_right: BTreeSet<EventId>,
        processed_protocol_events: usize,
    }

    fn run_exchange(left: SetContext, right: SetContext) -> ExchangeResult {
        let mut delivered_to_left = BTreeSet::new();
        let mut delivered_to_right = BTreeSet::new();
        let mut queue = VecDeque::new();
        let mut processed_protocol_events = 0usize;

        for event in start(&left, CONNECTION_ID, TimestampRange::ROOT)
            .expect("start sync")
            .events
        {
            queue.push_back((Recipient::Right, event));
        }

        while let Some((recipient, event)) = queue.pop_front() {
            processed_protocol_events += 1;
            let (context, response_recipient, delivered) = match recipient {
                Recipient::Left => (&left, Recipient::Right, &mut delivered_to_right),
                Recipient::Right => (&right, Recipient::Left, &mut delivered_to_left),
            };
            let report = handle_inbound_event(
                context,
                CONNECTION_ID,
                CONNECTION_ID,
                &event.canonical_bytes,
            )
            .expect("handle sync event");
            delivered.extend(report.send_event_ids);
            for response in report.events {
                queue.push_back((response_recipient, response));
            }
            assert!(
                processed_protocol_events < 300_000,
                "sync exchange did not converge within the protocol event budget"
            );
        }

        ExchangeResult {
            delivered_to_left,
            delivered_to_right,
            processed_protocol_events,
        }
    }

    fn summary_of(entries: &[EventIndexEntry]) -> RangeSummary {
        let mut summary = RangeSummary {
            count: entries.len() as u64,
            fingerprint: [0; 32],
        };
        for entry in entries {
            xor_into(&mut summary.fingerprint, &fingerprint_id(&entry.event_id));
        }
        summary
    }

    fn test_id(domain: &[u8], idx: u64) -> EventId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        hasher.update(&idx.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    fn fingerprint_id(id: &EventId) -> EventId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"test-sync-event-id:");
        hasher.update(id);
        *hasher.finalize().as_bytes()
    }

    fn xor_into(target: &mut EventId, value: &EventId) {
        for (left, right) in target.iter_mut().zip(value.iter()) {
            *left ^= *right;
        }
    }
}

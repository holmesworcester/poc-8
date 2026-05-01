use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub type ConnectionId = String;
pub type EventId = String;
pub type Timestamp = u64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelConfig {
    pub inbound_capacity: usize,
    pub parse_handoff_capacity: usize,
    pub context_handoff_capacity: usize,
    pub apply_handoff_capacity: usize,
    pub unblock_handoff_capacity: usize,
    pub sender_hot_capacity_events: usize,
    pub max_drive_steps: usize,
}

impl Default for KernelConfig {
    fn default() -> Self {
        Self {
            inbound_capacity: 32,
            parse_handoff_capacity: 8,
            context_handoff_capacity: 8,
            apply_handoff_capacity: 8,
            unblock_handoff_capacity: 8,
            sender_hot_capacity_events: 8,
            max_drive_steps: 10_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Operator {
    Inbound,
    Parse,
    Context,
    Apply,
    Unblock,
    Send,
}

impl Operator {
    pub const ALL: [Operator; 6] = [
        Operator::Inbound,
        Operator::Parse,
        Operator::Context,
        Operator::Apply,
        Operator::Unblock,
        Operator::Send,
    ];

    fn label(self) -> &'static str {
        match self {
            Operator::Inbound => "inbound",
            Operator::Parse => "parse",
            Operator::Context => "context",
            Operator::Apply => "apply",
            Operator::Unblock => "unblock",
            Operator::Send => "send",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capability {
    pub from: Operator,
    pub to: Operator,
    pub time: Timestamp,
}

impl Capability {
    fn new(from: Operator, to: Operator, time: Timestamp) -> Self {
        Self { from, to, time }
    }

    fn trace_label(&self) -> String {
        format!(
            "capability {}->{} @t{}",
            self.from.label(),
            self.to.label(),
            self.time
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventStatus {
    Ready,
    Blocked,
    Applied,
    Rejected,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventRecord {
    pub event_id: EventId,
    pub deps: Vec<EventId>,
    pub origin_connection: ConnectionId,
    pub send_to: Option<ConnectionId>,
    pub body: String,
    pub canonical: String,
    pub time: Timestamp,
    pub status: EventStatus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentFrame {
    pub connection_id: ConnectionId,
    pub event_id: EventId,
    pub canonical: String,
    pub time: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frontiers {
    pub inbound: Timestamp,
    pub parse: Timestamp,
    pub context: Timestamp,
    pub apply: Timestamp,
    pub unblock: Timestamp,
    pub send: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmitError {
    InboundFull,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DriveError {
    StepLimitExceeded { limit: usize },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    MissingField(&'static str),
    MalformedField(String),
    EmptyEventId,
}

pub fn encode_event(event_id: &str, deps: &[&str], send_to: Option<&str>, body: &str) -> String {
    format!(
        "id={};deps={};send={};body={}",
        event_id,
        deps.join(","),
        send_to.unwrap_or(""),
        body
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct InboundFrame {
    connection_id: ConnectionId,
    bytes: String,
    time: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CanonicalEnvelope {
    connection_id: ConnectionId,
    canonical: String,
    time: Timestamp,
    capability: Capability,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EventWork {
    event_id: EventId,
    time: Timestamp,
    capability: Capability,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct UnblockWake {
    applied_event_id: EventId,
    time: Timestamp,
    capability: Capability,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SendItem {
    connection_id: ConnectionId,
    event_id: EventId,
    time: Timestamp,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct OutboxRow {
    connection_id: ConnectionId,
    event_id: EventId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BoundedQueue<T> {
    capacity: usize,
    rows: VecDeque<T>,
}

impl<T> BoundedQueue<T> {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            rows: VecDeque::new(),
        }
    }

    fn is_full(&self) -> bool {
        self.rows.len() >= self.capacity
    }

    fn len(&self) -> usize {
        self.rows.len()
    }

    fn capacity_left(&self) -> usize {
        self.capacity.saturating_sub(self.rows.len())
    }

    fn push_back(&mut self, row: T) -> Result<(), T> {
        if self.is_full() {
            Err(row)
        } else {
            self.rows.push_back(row);
            Ok(())
        }
    }

    fn pop_front(&mut self) -> Option<T> {
        self.rows.pop_front()
    }

    fn front(&self) -> Option<&T> {
        self.rows.front()
    }

    fn iter(&self) -> impl Iterator<Item = &T> {
        self.rows.iter()
    }
}

pub struct Kernel {
    config: KernelConfig,
    next_time: Timestamp,
    inbound_rx: BoundedQueue<InboundFrame>,
    parse_handoff: BoundedQueue<CanonicalEnvelope>,
    context_handoff: BoundedQueue<EventWork>,
    apply_handoff: BoundedQueue<EventWork>,
    unblock_handoff: BoundedQueue<UnblockWake>,
    events: BTreeMap<EventId, EventRecord>,
    blocked_by_event: BTreeMap<EventId, BTreeSet<EventId>>,
    outbox: BTreeSet<OutboxRow>,
    sender_hot: BTreeMap<ConnectionId, BoundedQueue<SendItem>>,
    connection_writable: BTreeMap<ConnectionId, bool>,
    sent_frames: Vec<SentFrame>,
    trace: Vec<String>,
}

impl Kernel {
    pub fn new(config: KernelConfig) -> Self {
        Self {
            inbound_rx: BoundedQueue::new(config.inbound_capacity),
            parse_handoff: BoundedQueue::new(config.parse_handoff_capacity),
            context_handoff: BoundedQueue::new(config.context_handoff_capacity),
            apply_handoff: BoundedQueue::new(config.apply_handoff_capacity),
            unblock_handoff: BoundedQueue::new(config.unblock_handoff_capacity),
            config,
            next_time: 0,
            events: BTreeMap::new(),
            blocked_by_event: BTreeMap::new(),
            outbox: BTreeSet::new(),
            sender_hot: BTreeMap::new(),
            connection_writable: BTreeMap::new(),
            sent_frames: Vec::new(),
            trace: Vec::new(),
        }
    }

    pub fn admit_frame(
        &mut self,
        connection_id: impl Into<ConnectionId>,
        canonical_event_bytes: impl Into<String>,
    ) -> Result<Timestamp, AdmitError> {
        let time = self.next_time;
        let frame = InboundFrame {
            connection_id: connection_id.into(),
            bytes: canonical_event_bytes.into(),
            time,
        };
        if self.inbound_rx.push_back(frame).is_err() {
            return Err(AdmitError::InboundFull);
        }
        self.next_time += 1;
        self.trace
            .push(format!("source accepted inbound frame @t{}", time));
        Ok(time)
    }

    pub fn drive_until_idle(&mut self) -> Result<usize, DriveError> {
        let mut steps = 0;

        loop {
            let mut made_progress = false;
            for operator in Operator::ALL {
                if self.step_operator(operator) {
                    made_progress = true;
                    steps += 1;
                    if steps > self.config.max_drive_steps {
                        return Err(DriveError::StepLimitExceeded {
                            limit: self.config.max_drive_steps,
                        });
                    }
                }
            }

            if !made_progress {
                return Ok(steps);
            }
        }
    }

    pub fn step_operator(&mut self, operator: Operator) -> bool {
        match operator {
            Operator::Inbound => self.step_inbound(),
            Operator::Parse => self.step_parse(),
            Operator::Context => self.step_context(),
            Operator::Apply => self.step_apply(),
            Operator::Unblock => self.step_unblock(),
            Operator::Send => self.step_send(),
        }
    }

    pub fn set_connection_writable(
        &mut self,
        connection_id: impl Into<ConnectionId>,
        writable: bool,
    ) {
        self.connection_writable
            .insert(connection_id.into(), writable);
    }

    pub fn event_status(&self, event_id: &str) -> Option<EventStatus> {
        self.events.get(event_id).map(|record| record.status)
    }

    pub fn event(&self, event_id: &str) -> Option<&EventRecord> {
        self.events.get(event_id)
    }

    pub fn blocked_edges(&self) -> Vec<(EventId, EventId)> {
        let mut edges = Vec::new();
        for (blocked_by_event_id, blocked_events) in &self.blocked_by_event {
            for event_id in blocked_events {
                edges.push((blocked_by_event_id.clone(), event_id.clone()));
            }
        }
        edges
    }

    pub fn outbox_rows(&self) -> Vec<(ConnectionId, EventId)> {
        self.outbox
            .iter()
            .map(|row| (row.connection_id.clone(), row.event_id.clone()))
            .collect()
    }

    pub fn sent_frames(&self) -> &[SentFrame] {
        &self.sent_frames
    }

    pub fn trace(&self) -> &[String] {
        &self.trace
    }

    pub fn queue_len(&self, operator_boundary: Operator) -> usize {
        match operator_boundary {
            Operator::Inbound => self.inbound_rx.len(),
            Operator::Parse => self.parse_handoff.len(),
            Operator::Context => self.context_handoff.len(),
            Operator::Apply => self.apply_handoff.len(),
            Operator::Unblock => self.unblock_handoff.len(),
            Operator::Send => self.sender_hot.values().map(BoundedQueue::len).sum(),
        }
    }

    pub fn sender_hot_len(&self, connection_id: &str) -> usize {
        self.sender_hot
            .get(connection_id)
            .map(BoundedQueue::len)
            .unwrap_or_default()
    }

    pub fn frontiers(&self) -> Frontiers {
        let inbound_min = self.inbound_rx.iter().map(|row| row.time).min();
        let parse_min = self.parse_handoff.iter().map(|row| row.time).min();
        let context_min = self.context_handoff.iter().map(|row| row.time).min();
        let apply_min = self.apply_handoff.iter().map(|row| row.time).min();
        let unblock_min = self.unblock_handoff.iter().map(|row| row.time).min();
        let blocked_min = self
            .events
            .values()
            .filter(|record| record.status == EventStatus::Blocked)
            .map(|record| record.time)
            .min();
        let send_min = self
            .outbox
            .iter()
            .filter_map(|row| self.events.get(&row.event_id).map(|record| record.time))
            .chain(
                self.sender_hot
                    .values()
                    .flat_map(|queue| queue.iter().map(|row| row.time)),
            )
            .min();

        Frontiers {
            inbound: self.or_upper(inbound_min),
            parse: self.or_upper(min_option(inbound_min, parse_min)),
            context: self.or_upper(min_options([
                inbound_min,
                parse_min,
                context_min,
                blocked_min,
            ])),
            apply: self.or_upper(min_options([
                inbound_min,
                parse_min,
                context_min,
                apply_min,
                blocked_min,
            ])),
            unblock: self.or_upper(unblock_min),
            send: self.or_upper(send_min),
        }
    }

    fn step_inbound(&mut self) -> bool {
        if self.parse_handoff.is_full() {
            return false;
        }

        let Some(frame) = self.inbound_rx.pop_front() else {
            return false;
        };

        let capability = Capability::new(Operator::Inbound, Operator::Parse, frame.time);
        let trace_capability = capability.trace_label();
        let envelope = CanonicalEnvelope {
            connection_id: frame.connection_id,
            canonical: frame.bytes,
            time: frame.time,
            capability,
        };
        self.parse_handoff
            .push_back(envelope)
            .expect("capacity checked before inbound handoff");
        self.trace.push(format!(
            "inbound emitted canonical bytes with {}",
            trace_capability
        ));
        true
    }

    fn step_parse(&mut self) -> bool {
        if self.context_handoff.is_full() {
            return false;
        }

        let Some(envelope) = self.parse_handoff.pop_front() else {
            return false;
        };

        let parsed =
            match parse_canonical(&envelope.canonical, &envelope.connection_id, envelope.time) {
                Ok(parsed) => parsed,
                Err(err) => {
                    self.trace.push(format!(
                        "parse rejected bytes @t{}: {:?}",
                        envelope.time, err
                    ));
                    return true;
                }
            };

        if self.events.contains_key(&parsed.event_id) {
            self.trace.push(format!(
                "parse suppressed duplicate event {} @t{}",
                parsed.event_id, envelope.time
            ));
            return true;
        }

        let event_id = parsed.event_id.clone();
        let time = parsed.time;
        self.events.insert(event_id.clone(), parsed);
        let capability = Capability::new(Operator::Parse, Operator::Context, time);
        let trace_capability = capability.trace_label();
        self.context_handoff
            .push_back(EventWork {
                event_id: event_id.clone(),
                time,
                capability,
            })
            .expect("capacity checked before parse handoff");
        self.trace.push(format!(
            "parse admitted event {} with {}; upstream was {}",
            event_id,
            trace_capability,
            envelope.capability.trace_label()
        ));
        true
    }

    fn step_context(&mut self) -> bool {
        let Some(work) = self.context_handoff.front().cloned() else {
            return false;
        };

        let missing = self.missing_deps(&work.event_id);
        if missing.is_empty() && self.apply_handoff.is_full() {
            return false;
        }

        let work = self
            .context_handoff
            .pop_front()
            .expect("front item was just checked");

        if self.event_status(&work.event_id) != Some(EventStatus::Ready) {
            self.trace.push(format!(
                "context skipped event {} because it is {:?}",
                work.event_id,
                self.event_status(&work.event_id)
            ));
            return true;
        }

        if !missing.is_empty() {
            if let Some(record) = self.events.get_mut(&work.event_id) {
                record.status = EventStatus::Blocked;
            }
            for missing_dep in &missing {
                self.blocked_by_event
                    .entry(missing_dep.clone())
                    .or_default()
                    .insert(work.event_id.clone());
            }
            self.trace.push(format!(
                "context blocked event {} @t{} on missing deps [{}]",
                work.event_id,
                work.time,
                missing.join(",")
            ));
            return true;
        }

        let capability = Capability::new(Operator::Context, Operator::Apply, work.time);
        let trace_capability = capability.trace_label();
        self.apply_handoff
            .push_back(EventWork {
                event_id: work.event_id.clone(),
                time: work.time,
                capability,
            })
            .expect("capacity checked before context handoff");
        self.trace.push(format!(
            "context emitted event {} with {}; upstream was {}",
            work.event_id,
            trace_capability,
            work.capability.trace_label()
        ));
        true
    }

    fn step_apply(&mut self) -> bool {
        if self.unblock_handoff.is_full() {
            return false;
        }

        let Some(work) = self.apply_handoff.pop_front() else {
            return false;
        };

        if self.event_status(&work.event_id) == Some(EventStatus::Applied) {
            self.trace.push(format!(
                "apply skipped already-applied event {}",
                work.event_id
            ));
            return true;
        }

        let Some(record) = self.events.get_mut(&work.event_id) else {
            self.trace
                .push(format!("apply rejected unknown event {}", work.event_id));
            return true;
        };

        record.status = EventStatus::Applied;
        let applied_event_id = record.event_id.clone();
        let send_to = record.send_to.clone();
        let time = record.time;

        if let Some(connection_id) = send_to {
            self.outbox.insert(OutboxRow {
                connection_id: connection_id.clone(),
                event_id: applied_event_id.clone(),
            });
            self.connection_writable
                .entry(connection_id)
                .or_insert(true);
        }

        let capability = Capability::new(Operator::Apply, Operator::Unblock, time);
        let trace_capability = capability.trace_label();
        self.unblock_handoff
            .push_back(UnblockWake {
                applied_event_id: applied_event_id.clone(),
                time,
                capability,
            })
            .expect("capacity checked before apply handoff");
        self.trace.push(format!(
            "apply committed event {} and emitted {}; upstream was {}",
            applied_event_id,
            trace_capability,
            work.capability.trace_label()
        ));
        true
    }

    fn step_unblock(&mut self) -> bool {
        let Some(wake) = self.unblock_handoff.front().cloned() else {
            return false;
        };

        let dependents = self
            .blocked_by_event
            .get(&wake.applied_event_id)
            .cloned()
            .unwrap_or_default();
        let ready_after_removal = dependents
            .iter()
            .filter(|event_id| !self.has_other_blockers(event_id, &wake.applied_event_id))
            .count();

        if ready_after_removal > self.context_handoff.capacity_left() {
            return false;
        }

        let wake = self
            .unblock_handoff
            .pop_front()
            .expect("front wake was just checked");
        let dependents = self
            .blocked_by_event
            .remove(&wake.applied_event_id)
            .unwrap_or_default();

        let mut released = Vec::new();
        for event_id in dependents {
            if self.has_any_blockers(&event_id) {
                continue;
            }

            let Some(record) = self.events.get_mut(&event_id) else {
                continue;
            };
            record.status = EventStatus::Ready;
            let time = record.time;
            let capability = Capability::new(Operator::Unblock, Operator::Context, time);
            self.context_handoff
                .push_back(EventWork {
                    event_id: event_id.clone(),
                    time,
                    capability,
                })
                .expect("capacity checked before unblock handoff");
            released.push(event_id);
        }

        self.trace.push(format!(
            "unblock consumed {}; released [{}]",
            wake.capability.trace_label(),
            released.into_iter().collect::<Vec<_>>().join(",")
        ));
        true
    }

    fn step_send(&mut self) -> bool {
        let connection_ids = self.send_connection_ids();
        for connection_id in connection_ids {
            let refilled = self.refill_sender_hot(&connection_id);
            let writable = self
                .connection_writable
                .get(&connection_id)
                .copied()
                .unwrap_or(true);

            if !writable {
                if refilled {
                    self.trace.push(format!(
                        "send refilled hot queue for {} but socket is not writable",
                        connection_id
                    ));
                }
                return refilled;
            }

            if let Some(sent) = self.pop_hot_send(&connection_id) {
                self.outbox.remove(&OutboxRow {
                    connection_id: connection_id.clone(),
                    event_id: sent.event_id.clone(),
                });
                let canonical = self
                    .events
                    .get(&sent.event_id)
                    .map(|record| record.canonical.clone())
                    .unwrap_or_default();
                self.sent_frames.push(SentFrame {
                    connection_id: connection_id.clone(),
                    event_id: sent.event_id.clone(),
                    canonical,
                    time: sent.time,
                });
                self.trace.push(format!(
                    "send wrote event {} on {} and deleted its outbox row",
                    sent.event_id, connection_id
                ));
                return true;
            }

            if refilled {
                return true;
            }
        }

        false
    }

    fn missing_deps(&self, event_id: &str) -> Vec<EventId> {
        let Some(record) = self.events.get(event_id) else {
            return vec![event_id.to_string()];
        };

        record
            .deps
            .iter()
            .filter(|dep| self.event_status(dep) != Some(EventStatus::Applied))
            .cloned()
            .collect()
    }

    fn has_any_blockers(&self, event_id: &str) -> bool {
        self.blocked_by_event
            .values()
            .any(|blocked_events| blocked_events.contains(event_id))
    }

    fn has_other_blockers(&self, event_id: &str, removed_blocker: &str) -> bool {
        self.blocked_by_event
            .iter()
            .any(|(blocked_by_event_id, blocked_events)| {
                blocked_by_event_id != removed_blocker && blocked_events.contains(event_id)
            })
    }

    fn refill_sender_hot(&mut self, connection_id: &str) -> bool {
        let hot_capacity = self.config.sender_hot_capacity_events;
        let candidates: Vec<SendItem> = self
            .outbox
            .iter()
            .filter(|row| row.connection_id == connection_id)
            .filter(|row| !self.hot_contains(connection_id, &row.event_id))
            .filter_map(|row| {
                self.events.get(&row.event_id).map(|record| SendItem {
                    connection_id: row.connection_id.clone(),
                    event_id: row.event_id.clone(),
                    time: record.time,
                })
            })
            .collect();

        let hot = self
            .sender_hot
            .entry(connection_id.to_string())
            .or_insert_with(|| BoundedQueue::new(hot_capacity));
        let mut refilled = false;
        for item in candidates {
            if hot.is_full() {
                break;
            }
            hot.push_back(item)
                .expect("sender hot queue capacity checked before refill");
            refilled = true;
        }
        refilled
    }

    fn hot_contains(&self, connection_id: &str, event_id: &str) -> bool {
        self.sender_hot
            .get(connection_id)
            .map(|queue| queue.iter().any(|item| item.event_id == event_id))
            .unwrap_or(false)
    }

    fn pop_hot_send(&mut self, connection_id: &str) -> Option<SendItem> {
        self.sender_hot
            .get_mut(connection_id)
            .and_then(BoundedQueue::pop_front)
    }

    fn send_connection_ids(&self) -> Vec<ConnectionId> {
        let mut ids = BTreeSet::new();
        for row in &self.outbox {
            ids.insert(row.connection_id.clone());
        }
        for (connection_id, queue) in &self.sender_hot {
            if queue.len() > 0 {
                ids.insert(connection_id.clone());
            }
        }
        ids.into_iter().collect()
    }

    fn or_upper(&self, time: Option<Timestamp>) -> Timestamp {
        time.unwrap_or(self.next_time)
    }
}

fn parse_canonical(
    canonical: &str,
    origin_connection: &str,
    time: Timestamp,
) -> Result<EventRecord, ParseError> {
    let mut fields = BTreeMap::new();
    for part in canonical.split(';') {
        let Some((key, value)) = part.split_once('=') else {
            return Err(ParseError::MalformedField(part.to_string()));
        };
        fields.insert(key, value);
    }

    let event_id = fields
        .get("id")
        .ok_or(ParseError::MissingField("id"))?
        .to_string();
    if event_id.is_empty() {
        return Err(ParseError::EmptyEventId);
    }

    let deps = fields
        .get("deps")
        .ok_or(ParseError::MissingField("deps"))?
        .split(',')
        .filter(|dep| !dep.is_empty())
        .map(ToString::to_string)
        .collect();
    let send = fields.get("send").ok_or(ParseError::MissingField("send"))?;
    let send_to = if send.is_empty() {
        None
    } else {
        Some(send.to_string())
    };
    let body = fields
        .get("body")
        .ok_or(ParseError::MissingField("body"))?
        .to_string();

    Ok(EventRecord {
        event_id,
        deps,
        origin_connection: origin_connection.to_string(),
        send_to,
        body,
        canonical: canonical.to_string(),
        time,
        status: EventStatus::Ready,
    })
}

fn min_option(left: Option<Timestamp>, right: Option<Timestamp>) -> Option<Timestamp> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn min_options<const N: usize>(times: [Option<Timestamp>; N]) -> Option<Timestamp> {
    times.into_iter().flatten().min()
}

use std::collections::{BTreeMap, BTreeSet};

use topo::network::{
    frame_len_for_event_bytes, wrap_frame, ConnectionId, ConnectionSender, EventId,
    MemoryTransport, Network, NetworkError, NetworkResult, Outbox,
};

#[derive(Default)]
struct ToyOutbox {
    rows: BTreeMap<(ConnectionId, EventId), u64>,
    events: BTreeMap<EventId, Vec<u8>>,
}

impl ToyOutbox {
    fn add_event(&mut self, event_id: EventId, bytes: impl Into<Vec<u8>>) {
        self.events.insert(event_id, bytes.into());
    }

    fn enqueue(&mut self, connection_id: ConnectionId, event_id: EventId, queued_at_ms: u64) {
        self.rows
            .entry((connection_id, event_id))
            .or_insert(queued_at_ms);
    }

    fn pending_for_connection(&self, connection_id: &ConnectionId) -> Vec<EventId> {
        let mut rows: Vec<(u64, EventId)> = self
            .rows
            .iter()
            .filter_map(|((conn, event), queued_at_ms)| {
                (conn == connection_id).then_some((*queued_at_ms, *event))
            })
            .collect();
        rows.sort();
        rows.into_iter().map(|(_, event)| event).collect()
    }
}

impl Outbox for ToyOutbox {
    fn pending_connections(&self) -> NetworkResult<Vec<ConnectionId>> {
        let connections: BTreeSet<ConnectionId> = self
            .rows
            .keys()
            .map(|(connection_id, _)| *connection_id)
            .collect();
        Ok(connections.into_iter().collect())
    }

    fn list_outbox_for_connection(
        &self,
        connection_id: &ConnectionId,
        limit: usize,
    ) -> NetworkResult<Vec<EventId>> {
        Ok(self
            .pending_for_connection(connection_id)
            .into_iter()
            .take(limit)
            .collect())
    }

    fn event_bytes(
        &self,
        _connection_id: &ConnectionId,
        event_id: &EventId,
    ) -> NetworkResult<Option<Vec<u8>>> {
        Ok(self.events.get(event_id).cloned())
    }

    fn delete_outbox_rows(
        &mut self,
        connection_id: &ConnectionId,
        event_ids: &[EventId],
    ) -> NetworkResult<()> {
        for event_id in event_ids {
            self.rows.remove(&(*connection_id, *event_id));
        }
        Ok(())
    }
}

fn id(byte: u8) -> [u8; 32] {
    [byte; 32]
}

#[test]
fn outbox_deduped_rows_produce_one_send() {
    let conn = id(0xC1);
    let event = id(0xE1);
    let bytes = b"toy-event".to_vec();
    let mut outbox = ToyOutbox::default();
    outbox.add_event(event, bytes.clone());
    outbox.enqueue(conn, event, 10);
    outbox.enqueue(conn, event, 11);

    let mut network = Network::new(MemoryTransport::default(), 1024);
    let report = network.tick(&mut outbox).unwrap();

    assert!(report.errors.is_empty());
    assert_eq!(report.sent, vec![(conn, event)]);
    assert_eq!(network.transport().frames_for(&conn).len(), 1);
    assert_eq!(
        network.transport().frames_for(&conn)[0].as_slice(),
        wrap_frame(&conn, &event, &bytes).bytes()
    );
    assert!(outbox.pending_for_connection(&conn).is_empty());
}

#[test]
fn send_failure_leaves_outbox_pending() {
    let conn = id(0xC2);
    let event = id(0xE2);
    let mut outbox = ToyOutbox::default();
    outbox.add_event(event, b"retry-me");
    outbox.enqueue(conn, event, 1);

    let mut transport = MemoryTransport::default();
    transport.fail_connection(conn);
    let mut network = Network::new(transport, 1024);
    let report = network.tick(&mut outbox).unwrap();

    assert!(report.sent.is_empty());
    assert_eq!(report.errors.len(), 1);
    assert!(matches!(
        &report.errors[0].1,
        NetworkError::Transport(message) if message == "connection send failed"
    ));
    assert_eq!(outbox.pending_for_connection(&conn), vec![event]);
    assert!(network.transport().frames_for(&conn).is_empty());
    assert_eq!(network.sender(&conn).unwrap().hot_queue_len(), 0);
    assert_eq!(network.sender(&conn).unwrap().present_len(), 0);
}

#[test]
fn independent_connections_drain_separately() {
    let conn_a = id(0xA0);
    let conn_b = id(0xB0);
    let event_a = id(0xA1);
    let event_b = id(0xB1);
    let mut outbox = ToyOutbox::default();
    outbox.add_event(event_a, b"a-payload");
    outbox.add_event(event_b, b"b-payload");
    outbox.enqueue(conn_a, event_a, 1);
    outbox.enqueue(conn_b, event_b, 1);

    let mut transport = MemoryTransport::default();
    transport.fail_connection(conn_b);
    let mut network = Network::new(transport, 1024);
    let report = network.tick(&mut outbox).unwrap();

    assert_eq!(report.sent, vec![(conn_a, event_a)]);
    assert_eq!(report.errors.len(), 1);
    assert_eq!(report.errors[0].0, conn_b);
    assert_eq!(network.transport().frames_for(&conn_a).len(), 1);
    assert!(network.transport().frames_for(&conn_b).is_empty());
    assert!(outbox.pending_for_connection(&conn_a).is_empty());
    assert_eq!(outbox.pending_for_connection(&conn_b), vec![event_b]);
}

#[test]
fn bounded_hot_queue_respects_byte_limit() {
    let conn = id(0xC4);
    let first = id(0xE4);
    let second = id(0xE5);
    let payload = vec![7; 12];
    let max_hot_bytes = frame_len_for_event_bytes(payload.len());
    let mut outbox = ToyOutbox::default();
    outbox.add_event(first, payload.clone());
    outbox.add_event(second, payload);
    outbox.enqueue(conn, first, 1);
    outbox.enqueue(conn, second, 2);

    let mut sender = ConnectionSender::new(conn, max_hot_bytes);
    let loaded = sender.refill(&outbox).unwrap();

    assert_eq!(loaded, 1);
    assert_eq!(sender.hot_queue_len(), 1);
    assert_eq!(sender.present_len(), 1);
    assert!(sender.hot_queue_bytes() <= max_hot_bytes);
    assert_eq!(outbox.pending_for_connection(&conn), vec![first, second]);
}

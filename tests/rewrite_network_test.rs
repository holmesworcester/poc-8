use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use topo::network::{
    frame_len_for_event_bytes, parse_frame, read_frame, wrap_frame, Network, NetworkError, Outbox,
    SqliteOutbox, TcpTransport,
};
use topo::{event_modules, pipeline};

fn id(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn applied_message_with_outbox(
    connection_id: [u8; 32],
    payload: &[u8],
) -> (rusqlite::Connection, [u8; 32], Vec<u8>) {
    let conn = pipeline::open_memory().unwrap();
    let workspace_id = id(0xA1);
    let workspace = event_modules::encode_workspace(workspace_id, "net");
    let workspace_event_id = pipeline::event_id(&workspace);
    pipeline::ingest_local(&conn, &workspace, 10).unwrap();
    pipeline::project_ready(&conn, workspace_event_id, 11).unwrap();

    let body = String::from_utf8(payload.to_vec()).unwrap();
    let message = event_modules::encode_message(
        workspace_id,
        workspace_event_id,
        [0; 32],
        connection_id,
        &body,
    );
    let message_id = pipeline::event_id(&message);
    pipeline::ingest_local(&conn, &message, 12).unwrap();
    pipeline::project_ready(&conn, message_id, 13).unwrap();
    (conn, message_id, message)
}

#[test]
fn framed_event_round_trips_through_parser() {
    let connection_id = id(0xC1);
    let event_id = id(0xE1);
    let event_bytes = b"canonical event bytes";
    let frame = wrap_frame(&connection_id, &event_id, event_bytes);

    assert_eq!(frame.len(), frame_len_for_event_bytes(event_bytes.len()));
    let parsed = parse_frame(frame.bytes()).unwrap();
    assert_eq!(parsed.connection_id, connection_id);
    assert_eq!(parsed.event_id, event_id);
    assert_eq!(parsed.event_bytes, event_bytes);
}

#[test]
fn tcp_transport_sends_sqlite_outbox_frame_and_deletes_row() {
    let connection_id = id(0xC2);
    let (conn, event_id, event_bytes) = applied_message_with_outbox(connection_id, b"over tcp");
    assert_eq!(pipeline::pending_outbox_count(&conn).unwrap(), 1);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let receiver = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        read_frame(&mut stream).unwrap()
    });

    let mut transport = TcpTransport::new();
    transport.upsert_endpoint(connection_id, addr);
    let mut network = Network::new(transport, 1024 * 1024);
    let mut outbox = SqliteOutbox::new(&conn);
    let report = network.tick(&mut outbox).unwrap();

    assert!(report.errors.is_empty());
    assert_eq!(report.sent, vec![(connection_id, event_id)]);
    assert_eq!(pipeline::pending_outbox_count(&conn).unwrap(), 0);

    let frame = receiver.join().unwrap();
    assert_eq!(frame.connection_id, connection_id);
    assert_eq!(frame.event_id, event_id);
    assert_eq!(frame.event_bytes, event_bytes);
}

#[test]
fn tcp_send_failure_leaves_sqlite_outbox_pending() {
    let connection_id = id(0xC3);
    let (conn, event_id, _) = applied_message_with_outbox(connection_id, b"retry");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let mut transport =
        TcpTransport::with_timeouts(Duration::from_millis(50), Duration::from_millis(50));
    transport.upsert_endpoint(connection_id, addr);
    let mut network = Network::new(transport, 1024 * 1024);
    let mut outbox = SqliteOutbox::new(&conn);
    let report = network.tick(&mut outbox).unwrap();

    assert!(report.sent.is_empty());
    assert_eq!(report.errors.len(), 1);
    assert_eq!(report.errors[0].0, connection_id);
    assert!(matches!(report.errors[0].1, NetworkError::Transport(_)));
    assert_eq!(pipeline::pending_outbox_count(&conn).unwrap(), 1);
    assert_eq!(
        network.sender(&connection_id).unwrap().hot_queue_len(),
        0,
        "failed sends leave the frame in durable outbox, not hot memory"
    );

    let pending = {
        let outbox = SqliteOutbox::for_connection(&conn, connection_id);
        outbox
            .list_outbox_for_connection(&connection_id, 10)
            .unwrap()
    };
    assert_eq!(pending, vec![event_id]);
}

#[test]
fn oversized_frame_still_sends_when_hot_limit_is_smaller_than_the_frame() {
    let connection_id = id(0xC4);
    let payload = vec![b'x'; 4096];
    let (conn, event_id, _) = applied_message_with_outbox(connection_id, &payload);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let receiver = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        read_frame(&mut stream).unwrap()
    });

    let mut transport = TcpTransport::new();
    transport.upsert_endpoint(connection_id, addr);
    let mut network = Network::new(transport, 16);
    let mut outbox = SqliteOutbox::for_connection(&conn, connection_id);
    let report = network.tick(&mut outbox).unwrap();

    assert!(report.errors.is_empty());
    assert_eq!(report.sent, vec![(connection_id, event_id)]);
    let received = receiver.join().unwrap();
    assert_eq!(received.event_id, event_id);
    assert_eq!(pipeline::pending_outbox_count(&conn).unwrap(), 0);
}

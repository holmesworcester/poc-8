#[path = "cli_harness/mod.rs"]
mod cli_harness;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use cli_harness::*;

#[test]
fn connect_handshake_does_not_create_durable_events() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let port = free_port();

    let listener = start_listener(&bob, port, 1);
    let connected = connect_with_retry(&alice, port);
    assert!(connected.contains("connected:"));
    let server_out = wait_success(listener, "connect listener");
    assert!(
        server_out.contains("accepted_connections: 1"),
        "listener output:\n{server_out}"
    );
    assert!(
        server_out.contains("received_events: 0"),
        "listener output:\n{server_out}"
    );

    assert_eq!(count(&alice), 0, "connect must not store local sync items");
    assert_eq!(count(&bob), 0, "connect must not store remote sync items");
    assert_eq!(connection_count(&alice), 1);
    assert_eq!(connection_count(&bob), 1);
    assert_eq!(connection_event_count(&alice), 2);
    assert_eq!(connection_event_count(&bob), 2);
}

#[test]
fn connect_requires_matching_bootstrap_token() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let port = free_port();

    let listener = start_listener(&bob, port, 1);
    let connected = connect_with_token_after_listener(&alice, port, "wrong-token");
    assert!(
        !connected.status.success(),
        "connect unexpectedly succeeded:\n{}",
        stdout(&connected)
    );
    let server = listener.wait_with_output().expect("wait for listener");
    assert!(
        !server.status.success(),
        "listener unexpectedly accepted bad bootstrap:\n{}",
        stdout(&server)
    );

    assert_eq!(count(&alice), 0);
    assert_eq!(count(&bob), 0);
    assert_eq!(connection_count(&alice), 0);
    assert_eq!(connection_count(&bob), 0);
}

#[test]
fn connect_rejects_ack_with_invalid_connection_id() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_frame(&mut stream);
        let ack = invalid_connection_ack(&request);
        write_frame(&mut stream, &ack);
    });

    let connected = connect_with_token(&alice, port, BOOTSTRAP_TOKEN);
    server.join().unwrap();
    assert!(
        !connected.status.success(),
        "connect unexpectedly accepted invalid ack:\n{}",
        stdout(&connected)
    );
    assert!(
        stderr(&connected).contains("invalid connection id"),
        "stderr:\n{}",
        stderr(&connected)
    );
    assert_eq!(count(&alice), 0);
    assert_eq!(connection_count(&alice), 0);
}

fn invalid_connection_ack(request: &[u8]) -> Vec<u8> {
    const MAGIC: &[u8; 10] = b"TOPOCONN1\0";
    assert!(request.starts_with(MAGIC));
    assert_eq!(request[MAGIC.len()], 1);

    let from_offset = MAGIC.len() + 1;
    let requester_endpoint = &request[from_offset..from_offset + 32];
    let request_id = *blake3::hash(request).as_bytes();
    let responder_endpoint = [7u8; 32];
    let invalid_connection_id = [9u8; 32];

    let mut ack = Vec::with_capacity(MAGIC.len() + 1 + 32 * 4);
    ack.extend_from_slice(MAGIC);
    ack.push(2);
    ack.extend_from_slice(&responder_endpoint);
    ack.extend_from_slice(requester_endpoint);
    ack.extend_from_slice(&request_id);
    ack.extend_from_slice(&invalid_connection_id);
    ack
}

fn read_frame(stream: &mut std::net::TcpStream) -> Vec<u8> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).unwrap();
    let len = u32::from_be_bytes(len) as usize;
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes).unwrap();
    bytes
}

fn write_frame(stream: &mut std::net::TcpStream, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap();
    stream.write_all(&len.to_be_bytes()).unwrap();
    stream.write_all(bytes).unwrap();
    stream.flush().unwrap();
}

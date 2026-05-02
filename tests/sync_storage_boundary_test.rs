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
    let bob_invite = invite(&bob, port);

    let listener = start_listener(&bob, port, 1);
    let connected = connect_with_retry(&alice, &bob_invite);
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
fn connect_requires_matching_invite_private_key() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let port = free_port();
    let bob_invite = invite(&bob, port);
    let wrong_invite = replace_invite_private_key(&bob_invite, &"00".repeat(32));

    let listener = start_listener(&bob, port, 1);
    let connected = connect_with_invite_after_listener(&alice, &wrong_invite);
    assert!(
        !connected.status.success(),
        "connect unexpectedly succeeded:\n{}",
        stdout(&connected)
    );
    let server = listener.wait_with_output().expect("wait for listener");
    assert!(
        !server.status.success(),
        "listener unexpectedly accepted bad invite private key:\n{}",
        stdout(&server)
    );

    assert_eq!(count(&alice), 0);
    assert_eq!(count(&bob), 0);
    assert_eq!(connection_count(&alice), 0);
    assert_eq!(connection_count(&bob), 0);
}

#[test]
fn connect_rejects_plaintext_or_malformed_response() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _request = read_frame(&mut stream);
        write_frame(&mut stream, b"not a transit envelope");
    });

    let bad_server_invite =
        rewrite_invite_address(&invite(&alice, free_port()), &format!("127.0.0.1:{port}"));
    let connected = connect_with_invite(&alice, &bad_server_invite);
    server.join().unwrap();
    assert!(
        !connected.status.success(),
        "connect unexpectedly accepted invalid ack:\n{}",
        stdout(&connected)
    );
    assert!(
        stderr(&connected).contains("not a transit envelope"),
        "stderr:\n{}",
        stderr(&connected)
    );
    assert_eq!(count(&alice), 0);
    assert_eq!(connection_count(&alice), 0);
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

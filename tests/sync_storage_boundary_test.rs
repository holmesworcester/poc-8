#[path = "cli_harness/mod.rs"]
mod cli_harness;

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
}

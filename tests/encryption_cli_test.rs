//! Black-box CLI tests for encryption key availability.
//!
//! Setup goes through the real `topo` binary: workspace creation, invite
//! listening, invite acceptance, transport connection learning, sync, key
//! publication, wrap creation, and derivation.

mod cli_harness;

use std::io::{BufRead, BufReader, Read};
use std::process::Child;
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use cli_harness::*;

#[test]
fn cli_key_wrap_derives_access_only_for_wrapped_recipient() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let carol = temp_db(&tmp, "carol.db");
    let workspace_id = create_workspace(&alice, "Keys", "alice", "alice-laptop");
    let bob_join_port = free_port();
    let carol_join_port = free_port();

    join_workspace(
        &alice,
        &bob,
        &workspace_id,
        bob_join_port,
        "bob",
        "bob-phone",
    );
    join_workspace(
        &alice,
        &carol,
        &workspace_id,
        carol_join_port,
        "carol",
        "carol-tablet",
    );

    let bob_recipient = assert_success(topo(&["--db", &bob, "key-recipient", &workspace_id]));
    let bob_recipient_id = line_value(&bob_recipient, "recipient_key_id");
    assert_success(topo(&["--db", &carol, "key-recipient", &workspace_id]));
    sync_once(&bob, &alice, bob_join_port);

    let alice_to_bob = free_port();
    let alice_to_carol = free_port();
    connect_pair(&alice, &bob, alice_to_bob);
    connect_pair(&alice, &carol, alice_to_carol);

    let frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");
    assert_eq!(
        line_value(
            &assert_success(topo(&[
                "--db",
                &alice,
                "key-access",
                &workspace_id,
                &removal_frontier_id,
            ])),
            "access",
        ),
        "yes"
    );

    sync_two_routes(&alice, &bob, alice_to_bob, &carol, alice_to_carol);
    assert_eq!(
        line_value(
            &assert_success(topo(&[
                "--db",
                &bob,
                "key-access",
                &workspace_id,
                &removal_frontier_id,
            ])),
            "access",
        ),
        "no"
    );
    assert_eq!(
        line_value(
            &assert_success(topo(&[
                "--db",
                &carol,
                "key-access",
                &workspace_id,
                &removal_frontier_id,
            ])),
            "access",
        ),
        "no"
    );

    let wrapped = assert_success(topo(&[
        "--db",
        &alice,
        "key-wrap",
        &workspace_id,
        &removal_frontier_id,
        &bob_recipient_id,
    ]));
    assert_eq!(line_value(&wrapped, "recipient_key_id"), bob_recipient_id);

    sync_two_routes(&alice, &bob, alice_to_bob, &carol, alice_to_carol);

    let bob_derive = assert_success(topo(&["--db", &bob, "key-derive"]));
    assert_eq!(line_value(&bob_derive, "derived_key_secrets"), "1");
    assert_eq!(
        line_value(
            &assert_success(topo(&[
                "--db",
                &bob,
                "key-access",
                &workspace_id,
                &removal_frontier_id,
            ])),
            "access",
        ),
        "yes"
    );

    let carol_derive = assert_success(topo(&["--db", &carol, "key-derive"]));
    assert_eq!(line_value(&carol_derive, "derived_key_secrets"), "0");
    assert_eq!(
        line_value(
            &assert_success(topo(&[
                "--db",
                &carol,
                "key-access",
                &workspace_id,
                &removal_frontier_id,
            ])),
            "access",
        ),
        "no"
    );
}

#[test]
fn cli_invite_server_syncs_but_cannot_be_a_key_recipient() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let server = temp_db(&tmp, "invite-server.db");
    let bob = temp_db(&tmp, "bob.db");
    let workspace_id = create_workspace(&alice, "Helper FS", "alice", "alice-laptop");
    let server_join_port = free_port();
    let bob_join_port = free_port();

    join_invite_server(&alice, &server, &workspace_id, server_join_port, "relay");
    let server_identity = assert_success(topo(&["--db", &server, "identity"]));
    assert!(
        server_identity.contains("endpoint_role=invite-server"),
        "{server_identity}"
    );

    let denied = topo(&["--db", &server, "key-recipient", &workspace_id]);
    assert!(
        !denied.status.success(),
        "invite-server recipient key should be invalid\nstdout={}\nstderr={}",
        stdout(&denied),
        stderr(&denied)
    );
    assert!(
        stderr(&denied).contains("local endpoint role cannot receive key wraps"),
        "{}",
        stderr(&denied)
    );

    join_workspace(
        &alice,
        &bob,
        &workspace_id,
        bob_join_port,
        "bob",
        "bob-phone",
    );
    let bob_recipient = assert_success(topo(&["--db", &bob, "key-recipient", &workspace_id]));
    let bob_recipient_id = line_value(&bob_recipient, "recipient_key_id");
    sync_once(&bob, &alice, bob_join_port);

    let alice_to_bob = free_port();
    let alice_to_server = free_port();
    connect_pair(&alice, &bob, alice_to_bob);
    connect_pair(&alice, &server, alice_to_server);

    let frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");
    assert_success(topo(&[
        "--db",
        &alice,
        "key-wrap",
        &workspace_id,
        &removal_frontier_id,
        &bob_recipient_id,
    ]));

    sync_two_routes(&alice, &bob, alice_to_bob, &server, alice_to_server);

    let bob_derive = assert_success(topo(&["--db", &bob, "key-derive"]));
    assert_eq!(line_value(&bob_derive, "derived_key_secrets"), "1");
    let server_derive = assert_success(topo(&["--db", &server, "key-derive"]));
    assert_eq!(line_value(&server_derive, "derived_key_secrets"), "0");
    assert_eq!(
        line_value(
            &assert_success(topo(&[
                "--db",
                &server,
                "key-access",
                &workspace_id,
                &removal_frontier_id,
            ])),
            "access",
        ),
        "no"
    );
}

#[test]
fn cli_rotates_recipient_keys_and_tombstones_history_path_nodes() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&alice, "Fs Keys", "alice", "alice-laptop");

    let first_recipient = assert_success(topo(&["--db", &alice, "key-recipient", &workspace_id]));
    let first_recipient_id = line_value(&first_recipient, "recipient_key_id");
    assert_success(topo(&["--db", &alice, "clock", "set", "70000"]));
    let rotated = assert_success(topo(&[
        "--db",
        &alice,
        "key-rotate-recipient",
        &workspace_id,
    ]));
    assert_eq!(line_value(&rotated, "old_active_recipient_keys"), "1");
    assert_eq!(line_value(&rotated, "tombstoned_recipient_keys"), "1");
    let clock = assert_success(topo(&["--db", &alice, "clock"]));
    assert_eq!(line_value(&clock, "logical_time"), "70000");
    assert_eq!(line_value(&clock, "max_event_timestamp"), "70001");

    let keys = assert_success(topo(&["--db", &alice, "keys", &workspace_id]));
    assert_eq!(line_value(&keys, "recipient_keys"), "1");
    assert_eq!(line_value(&keys, "recipient_key_tombstones"), "1");
    assert_eq!(line_value(&keys, "local_recipient_keys"), "2");

    let advanced = assert_success(topo(&["--db", &alice, "clock", "advance", "1000"]));
    assert_eq!(line_value(&advanced, "next_timestamp"), "71000");
    let frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let clock = assert_success(topo(&["--db", &alice, "clock"]));
    assert_eq!(line_value(&clock, "max_event_timestamp"), "71000");
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");
    let local_key_secret_id = line_value(&frontier, "local_key_secret_id");
    let old_wrap = topo(&[
        "--db",
        &alice,
        "key-wrap",
        &workspace_id,
        &removal_frontier_id,
        &first_recipient_id,
    ]);
    assert!(
        !old_wrap.status.success(),
        "old recipient key should have been purged\nstdout={}\nstderr={}",
        stdout(&old_wrap),
        stderr(&old_wrap)
    );
    assert!(
        stderr(&old_wrap).contains("recipient key is missing"),
        "{}",
        stderr(&old_wrap)
    );

    let root_node = assert_success(topo(&[
        "--db",
        &alice,
        "key-node",
        &workspace_id,
        &removal_frontier_id,
        &local_key_secret_id,
        "0",
        "8",
    ]));
    let root_node_id = line_value(&root_node, "local_history_node_secret_id");
    let keys = assert_success(topo(&["--db", &alice, "keys", &workspace_id]));
    assert_eq!(line_value(&keys, "local_history_node_secrets"), "1");
    assert_eq!(line_value(&keys, "local_history_node_tombstones"), "0");

    let sibling = assert_success(topo(&[
        "--db",
        &alice,
        "key-node",
        &workspace_id,
        &removal_frontier_id,
        &root_node_id,
        "4",
        "4",
        &root_node_id,
    ]));
    assert_eq!(line_value(&sibling, "tombstoned_node_id"), root_node_id);
    let keys = assert_success(topo(&["--db", &alice, "keys", &workspace_id]));
    assert_eq!(line_value(&keys, "local_history_node_secrets"), "1");
    assert_eq!(line_value(&keys, "local_history_node_tombstones"), "1");
    assert!(keys.contains("start=4 width=4"), "{keys}");

    let from_retired_root = topo(&[
        "--db",
        &alice,
        "key-node",
        &workspace_id,
        &removal_frontier_id,
        &root_node_id,
        "0",
        "4",
    ]);
    assert!(
        !from_retired_root.status.success(),
        "retired path node should not derive children\nstdout={}\nstderr={}",
        stdout(&from_retired_root),
        stderr(&from_retired_root)
    );
    assert!(
        stderr(&from_retired_root).contains("history node source has been tombstoned"),
        "{}",
        stderr(&from_retired_root)
    );
}

fn create_workspace(db: &str, name: &str, username: &str, device_name: &str) -> String {
    let out = assert_success(topo(&[
        "--db",
        db,
        "create-workspace",
        name,
        "--username",
        username,
        "--devicename",
        device_name,
    ]));
    line_value(&out, "workspace_id")
}

fn join_workspace(
    host: &str,
    joiner: &str,
    workspace_id: &str,
    port: u16,
    username: &str,
    device_name: &str,
) {
    let mut listener = spawn_workspace_invite_listener(host, workspace_id, port, 1);
    let invite = listener.invite_link();
    let accepted = match try_accept_with_identity_retry(joiner, &invite, username, device_name) {
        Ok(output) => output,
        Err(err) => listener.fail("workspace invite accept failed", err),
    };
    assert_eq!(line_value(&accepted, "workspace_id"), workspace_id);
    let host_out = listener.wait_success("workspace invite listener");
    assert!(host_out.contains("accepted_connections: 1"), "{host_out}");
}

fn join_invite_server(host: &str, server: &str, workspace_id: &str, port: u16, device_name: &str) {
    let mut listener = spawn_invite_server_listener(host, workspace_id, port, 1);
    let invite = listener.invite_link();
    let accepted = match try_accept_invite_server_with_retry(server, &invite, device_name) {
        Ok(output) => output,
        Err(err) => listener.fail("invite-server accept failed", err),
    };
    assert_eq!(line_value(&accepted, "workspace_id"), workspace_id);
    assert_eq!(line_value(&accepted, "endpoint_role"), "invite-server");
    let host_out = listener.wait_success("invite-server listener");
    assert!(host_out.contains("accepted_connections: 1"), "{host_out}");
}

struct ListeningInvite {
    child: Child,
    invite_rx: Receiver<Result<String, String>>,
    stdout: JoinHandle<String>,
    stderr: JoinHandle<String>,
}

impl ListeningInvite {
    fn invite_link(&mut self) -> String {
        match self.invite_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(line)) => {
                assert!(
                    line.starts_with("topo://invite/"),
                    "missing invite link in first listener line: {line}"
                );
                thread::sleep(Duration::from_millis(50));
                line
            }
            Ok(Err(err)) => {
                let _ = self.child.kill();
                panic!("listener did not print invite link: {err}");
            }
            Err(err) => {
                let _ = self.child.kill();
                panic!("timed out waiting for invite link: {err}");
            }
        }
    }

    fn wait_success(mut self, label: &str) -> String {
        let status = self.child.wait().expect("wait for listener");
        let stdout = self.stdout.join().expect("join stdout reader");
        let stderr = self.stderr.join().expect("join stderr reader");
        assert!(
            status.success(),
            "{label} failed\nstdout={stdout}\nstderr={stderr}"
        );
        stdout
    }

    fn fail(mut self, label: &str, err: String) -> ! {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let stdout = self.stdout.join().expect("join stdout reader");
        let stderr = self.stderr.join().expect("join stderr reader");
        panic!("{label}: {err}\nlistener stdout:\n{stdout}\nlistener stderr:\n{stderr}");
    }
}

fn spawn_workspace_invite_listener(
    db: &str,
    workspace_id: &str,
    port: u16,
    accept: usize,
) -> ListeningInvite {
    let port = port.to_string();
    let accept = accept.to_string();
    let child = spawn_topo(&[
        "--db",
        db,
        "invite",
        "--workspace",
        workspace_id,
        "--listen",
        "127.0.0.1",
        &port,
        "--accept",
        &accept,
    ]);
    listening_invite_from_child(child)
}

fn spawn_invite_server_listener(
    db: &str,
    workspace_id: &str,
    port: u16,
    accept: usize,
) -> ListeningInvite {
    let port = port.to_string();
    let accept = accept.to_string();
    let child = spawn_topo(&[
        "--db",
        db,
        "invite-server",
        workspace_id,
        "--listen",
        "127.0.0.1",
        &port,
        "--accept",
        &accept,
    ]);
    listening_invite_from_child(child)
}

fn spawn_invite_listener(db: &str, port: u16, accept: usize) -> ListeningInvite {
    let port = port.to_string();
    let accept = accept.to_string();
    let child = spawn_topo(&[
        "--db",
        db,
        "invite",
        "--listen",
        "127.0.0.1",
        &port,
        "--accept",
        &accept,
    ]);
    listening_invite_from_child(child)
}

fn listening_invite_from_child(mut child: Child) -> ListeningInvite {
    let stdout = child.stdout.take().expect("listener stdout");
    let stderr = child.stderr.take().expect("listener stderr");
    let (invite_tx, invite_rx) = mpsc::channel();
    let stdout = thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut output = String::new();
        let mut first = String::new();
        match reader.read_line(&mut first) {
            Ok(0) => {
                let _ = invite_tx.send(Err("stdout closed before first line".to_string()));
            }
            Ok(_) => {
                output.push_str(&first);
                let link = first.trim_end_matches(['\r', '\n']).to_string();
                let _ = invite_tx.send(Ok(link));
            }
            Err(err) => {
                let _ = invite_tx.send(Err(err.to_string()));
            }
        }

        let mut rest = String::new();
        if reader.read_to_string(&mut rest).is_ok() {
            output.push_str(&rest);
        }
        output
    });
    let stderr = thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut output = String::new();
        let _ = reader.read_to_string(&mut output);
        output
    });
    ListeningInvite {
        child,
        invite_rx,
        stdout,
        stderr,
    }
}

fn try_accept_with_identity_retry(
    db: &str,
    invite: &str,
    username: &str,
    device_name: &str,
) -> Result<String, String> {
    let mut last = String::new();
    for _ in 0..200 {
        let output = topo(&[
            "--db",
            db,
            "accept",
            invite,
            "--username",
            username,
            "--devicename",
            device_name,
        ]);
        if output.status.success() {
            return Ok(stdout(&output));
        }
        last = stderr(&output);
        if !last.contains("open tcp stream") {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(last)
}

fn try_accept_invite_server_with_retry(
    db: &str,
    invite: &str,
    device_name: &str,
) -> Result<String, String> {
    let mut last = String::new();
    for _ in 0..200 {
        let output = topo(&[
            "--db",
            db,
            "accept-invite-server",
            invite,
            "--devicename",
            device_name,
        ]);
        if output.status.success() {
            return Ok(stdout(&output));
        }
        last = stderr(&output);
        if !last.contains("open tcp stream") {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(last)
}

fn connect_pair(initiator_db: &str, listener_db: &str, listener_port: u16) {
    let mut listener = spawn_invite_listener(listener_db, listener_port, 1);
    let invite = listener.invite_link();
    let connected = accept_with_retry(initiator_db, &invite);
    assert!(connected.contains("connected:"), "{connected}");
    let out = listener.wait_success("transport invite listener");
    assert!(out.contains("accepted_connections: 1"), "{out}");
}

fn accept_with_retry(db: &str, invite: &str) -> String {
    let mut last = String::new();
    for _ in 0..200 {
        let output = topo(&["--db", db, "accept", invite]);
        if output.status.success() {
            return stdout(&output);
        }
        last = stderr(&output);
        if !last.contains("open tcp stream") {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("accept never succeeded: {last}");
}

fn sync_once(from_db: &str, listener_db: &str, listener_port: u16) {
    let listener = start_sync_listener(listener_db, listener_port, 1);
    let mut last = String::new();
    let sync_out = (0..100)
        .find_map(|_| {
            let output = topo(&["--db", from_db, "sync"]);
            if output.status.success() {
                return Some(stdout(&output));
            }
            last = stderr(&output);
            thread::sleep(Duration::from_millis(50));
            None
        })
        .unwrap_or_else(|| panic!("sync never succeeded: {last}"));
    assert!(sync_out.contains("routes_synced:"), "{sync_out}");
    wait_success(listener, "sync listener");
}

fn sync_two_routes(
    from_db: &str,
    first_db: &str,
    first_port: u16,
    second_db: &str,
    second_port: u16,
) {
    let first = start_sync_listener(first_db, first_port, 1);
    let second = start_sync_listener(second_db, second_port, 1);
    let mut last = String::new();
    let sync_out = (0..100)
        .find_map(|_| {
            let output = topo(&["--db", from_db, "sync"]);
            if output.status.success() {
                return Some(stdout(&output));
            }
            last = stderr(&output);
            thread::sleep(Duration::from_millis(50));
            None
        })
        .unwrap_or_else(|| panic!("sync never succeeded: {last}"));
    assert!(sync_out.contains("routes_synced:"), "{sync_out}");
    wait_success(first, "first sync listener");
    wait_success(second, "second sync listener");
}

fn start_sync_listener(db: &str, port: u16, accept: usize) -> Child {
    let port = port.to_string();
    let accept = accept.to_string();
    spawn_topo(&[
        "--db",
        db,
        "sync",
        "--listen",
        "127.0.0.1",
        &port,
        "--accept",
        &accept,
    ])
}

//! Black-box CLI tests for the `connections` and `event tree` debuggability
//! commands.
//!
//! Setup goes through the real `topo` binary: workspace creation, invite
//! listening/accept, message send, react. Reads then run `connections` and
//! `event tree` against the resulting databases and assert observable substring
//! contracts.

mod cli_harness;

use std::io::{BufRead, BufReader, Read};
use std::process::Child;
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use cli_harness::*;

#[test]
fn cli_connections_with_no_peers_prints_zero_count() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    create_workspace(&db, "Empty", "alice", "alice-laptop");

    let listed = assert_success(topo(&["--db", &db, "connections"]));
    assert!(listed.contains("CONNECTIONS (0):"), "{listed}");
    assert!(listed.contains("(none)"), "{listed}");
}

#[test]
fn cli_connections_lists_active_and_recent_peers() {
    let tmp = tempfile::tempdir().unwrap();
    let host = temp_db(&tmp, "alice.db");
    let joiner = temp_db(&tmp, "bob.db");
    let port = free_port();

    let workspace_id = create_workspace(&host, "Alpha", "alice", "alice-laptop");

    let mut listener = spawn_workspace_invite_listener(&host, &workspace_id, port, 1);
    let invite = listener.invite_link();
    let accepted = match try_accept_with_identity_retry(&joiner, &invite, "bob", "bob-phone") {
        Ok(output) => output,
        Err(err) => listener.fail("bob accept failed", err),
    };
    assert!(accepted.contains("connected:"), "{accepted}");
    let host_out = listener.wait_success("workspace invite listener");
    assert!(host_out.contains("accepted_connections: 1"), "{host_out}");

    let alice_listed = assert_success(topo(&["--db", &host, "connections"]));
    assert!(alice_listed.contains("CONNECTIONS (1):"), "{alice_listed}");
    assert!(alice_listed.contains("127.0.0.1:"), "{alice_listed}");

    let bob_identity = assert_success(topo(&["--db", &joiner, "identity"]));
    let bob_endpoint = line_value(&bob_identity, "endpoint_id");
    let bob_short = &bob_endpoint[..8];
    assert!(
        alice_listed.contains(bob_short),
        "alice connections missing bob short endpoint id {bob_short}:\n{alice_listed}"
    );

    let bob_listed = assert_success(topo(&["--db", &joiner, "connections"]));
    assert!(bob_listed.contains("CONNECTIONS (1):"), "{bob_listed}");
    assert!(bob_listed.contains("127.0.0.1:"), "{bob_listed}");
}

#[test]
fn cli_event_tree_prints_workspace_root_and_users() {
    let tmp = tempfile::tempdir().unwrap();
    let host = temp_db(&tmp, "alice.db");
    let joiner = temp_db(&tmp, "bob.db");
    let port = free_port();

    let workspace_id = create_workspace(&host, "Alpha", "alice", "alice-laptop");

    let mut listener = spawn_workspace_invite_listener(&host, &workspace_id, port, 1);
    let invite = listener.invite_link();
    let accepted = match try_accept_with_identity_retry(&joiner, &invite, "bob", "bob-phone") {
        Ok(output) => output,
        Err(err) => listener.fail("bob accept failed", err),
    };
    assert!(accepted.contains("connected:"), "{accepted}");
    listener.wait_success("workspace invite listener");

    let alice_tree = assert_success(topo(&["--db", &host, "event", "tree"]));
    assert!(
        alice_tree.contains("workspace \u{2014} creates the workspace"),
        "alice tree missing workspace label:\n{alice_tree}"
    );
    assert!(
        alice_tree.contains("\u{2190} root"),
        "alice tree missing root marker:\n{alice_tree}"
    );
    assert!(
        alice_tree.contains("user_invite_shared \u{2014} invites a user"),
        "alice tree missing user_invite_shared label:\n{alice_tree}"
    );
    assert!(
        alice_tree.contains("user \u{2014} registers the user"),
        "alice tree missing user label:\n{alice_tree}"
    );

    let bob_tree = assert_success(topo(&["--db", &joiner, "event", "tree"]));
    assert!(
        bob_tree.contains("user \u{2014} registers the user"),
        "bob tree missing user label:\n{bob_tree}"
    );
}

#[test]
fn cli_event_tree_decrypts_messages_and_reactions() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Content", "alice", "alice-laptop");
    assert_success(topo(&["--db", &db, "key-frontier", &workspace_id]));

    assert_success(topo(&["--db", &db, "send", &workspace_id, "first"]));
    assert_success(topo(&["--db", &db, "react", &workspace_id, "#1", "+1"]));

    let tree = assert_success(topo(&["--db", &db, "event", "tree"]));
    assert!(
        tree.contains("message \u{2014} sends a message"),
        "tree missing message label:\n{tree}"
    );
    assert!(
        tree.contains("reaction \u{2014} reacts to a message"),
        "tree missing reaction label:\n{tree}"
    );
    assert!(
        tree.contains("--- decrypted: message \u{2014} sends a message ---"),
        "tree missing decrypted message marker:\n{tree}"
    );
    assert!(
        tree.contains("content: first"),
        "tree missing decrypted message content:\n{tree}"
    );
    assert!(
        tree.contains("--- decrypted: reaction \u{2014} reacts to a message ---"),
        "tree missing decrypted reaction marker:\n{tree}"
    );
    assert!(
        tree.contains("emoji: +1"),
        "tree missing decrypted reaction emoji:\n{tree}"
    );
}

#[test]
fn cli_event_tree_handles_local_only_events() {
    let tmp = tempfile::tempdir().unwrap();
    let host = temp_db(&tmp, "alice.db");
    let port = free_port();

    let workspace_id = create_workspace(&host, "Alpha", "alice", "alice-laptop");
    // Generating a workspace invite stores a local invite_secret event so the
    // tree has a local-only node to render.
    let _addr = format!("127.0.0.1:{port}");
    let mut listener = spawn_workspace_invite_listener(&host, &workspace_id, port, 1);
    let invite = listener.invite_link();
    let _accept_db = temp_db(&tmp, "bob.db");
    let accepted =
        match try_accept_with_identity_retry(&_accept_db, &invite, "bob", "bob-phone") {
            Ok(output) => output,
            Err(err) => listener.fail("bob accept failed", err),
        };
    assert!(accepted.contains("connected:"), "{accepted}");
    listener.wait_success("workspace invite listener");

    let tree = assert_success(topo(&["--db", &host, "event", "tree"]));
    assert!(
        tree.contains("invite_secret \u{2014} stores a local invite key"),
        "tree missing invite_secret label:\n{tree}"
    );
    assert!(
        tree.contains("(local)"),
        "tree missing local-only marker:\n{tree}"
    );
    assert!(
        tree.contains("local_endpoint \u{2014} stores a local signing key"),
        "tree missing local_endpoint label:\n{tree}"
    );
}

// ---------------------------------------------------------------------------
// Local helpers — keep scoped to this scenario file per cli_harness rules.
// ---------------------------------------------------------------------------

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

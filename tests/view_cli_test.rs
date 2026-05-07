//! Black-box CLI tests for the cross-module `view` rendering command.
//!
//! Setup deliberately goes through the real `topo` binary: workspace creation,
//! content key derivation, message/reaction/file send. These tests must not
//! install identity graphs or content rows by importing protocol/store
//! internals; the `view` rendering boundary is the invariant under test.

mod cli_harness;

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::process::Child;
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use cli_harness::*;

#[test]
fn cli_view_renders_sidebar_messages_reactions_files() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Activism", "alice", "laptop");
    assert_success(topo(&["--db", &db, "key-frontier", &workspace_id]));

    assert_success(topo(&["--db", &db, "send", &workspace_id, "hey bob"]));
    assert_success(topo(&["--db", &db, "send", &workspace_id, "second message"]));
    assert_success(topo(&["--db", &db, "react", &workspace_id, "#1", "+1"]));

    let payload = b"hello world".to_vec();
    let in_path = tmp.path().join("payload.txt");
    fs::write(&in_path, &payload).expect("write input");
    assert_success(topo(&[
        "--db",
        &db,
        "send-file",
        &workspace_id,
        "see attached",
        "--file",
        in_path.to_str().expect("path utf-8"),
    ]));

    let view = assert_success(topo(&["--db", &db, "view", &workspace_id]));

    // Sidebar must surface the local endpoint identity, the workspace name,
    // and the local user/device row.
    assert!(view.contains("IDENTITY:"), "missing IDENTITY:\n{view}");
    assert!(
        view.contains("endpoint_id: "),
        "missing endpoint_id line:\n{view}"
    );
    assert!(
        view.contains("signing_public_key: "),
        "missing signing_public_key line:\n{view}"
    );
    assert!(
        view.contains("WORKSPACE:\n  Activism"),
        "missing workspace name block:\n{view}"
    );
    assert!(view.contains("USERS:"), "missing USERS: header:\n{view}");
    assert!(
        view.contains("alice/laptop (you)"),
        "missing local user/device row:\n{view}"
    );

    // The 40-char divider must be present byte-for-byte.
    let divider = "\u{2500}".repeat(40);
    assert!(view.contains(&divider), "missing divider line:\n{view}");

    // Author block + numbered messages.
    assert!(view.contains("    alice ["), "missing author header:\n{view}");
    assert!(
        view.contains("      1. hey bob"),
        "missing first message:\n{view}"
    );
    assert!(
        view.contains("      2. second message"),
        "missing second message:\n{view}"
    );
    assert!(
        view.contains("      3. see attached"),
        "missing send-file message:\n{view}"
    );

    // Reaction row: emoji followed by the reacting user.
    assert!(
        view.contains("         +1 alice"),
        "missing reaction row:\n{view}"
    );

    // File row: complete checkmark + filename + byte size.
    assert!(
        view.contains("\u{2714}  payload.txt (11 B)"),
        "missing file row:\n{view}"
    );
}

#[test]
fn cli_view_with_no_workspace_argument_picks_single_workspace() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Solo", "alice", "laptop");
    assert_success(topo(&["--db", &db, "key-frontier", &workspace_id]));

    assert_success(topo(&["--db", &db, "send", &workspace_id, "first"]));

    let view = assert_success(topo(&["--db", &db, "view"]));

    assert!(
        view.contains("WORKSPACE:\n  Solo"),
        "no-arg view did not pick the single workspace:\n{view}"
    );
    assert!(
        view.contains("alice/laptop (you)"),
        "no-arg view did not surface local user:\n{view}"
    );
    assert!(
        view.contains("      1. first"),
        "no-arg view did not surface message:\n{view}"
    );
}

#[test]
fn cli_view_requires_argument_when_multiple_workspaces() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let one = create_workspace(&db, "WorkspaceOne", "alice", "laptop");
    let _two = create_workspace(&db, "WorkspaceTwo", "alice", "laptop");
    assert_success(topo(&["--db", &db, "key-frontier", &one]));

    let output = topo(&["--db", &db, "view"]);
    assert!(
        !output.status.success(),
        "view should fail without workspace selection: stdout={} stderr={}",
        stdout(&output),
        stderr(&output)
    );
    let err = stderr(&output);
    assert!(
        err.contains("select a workspace") && err.contains("WORKSPACE_ID_HEX"),
        "error message should ask for a workspace argument: {err}"
    );
}

#[test]
fn cli_view_with_explicit_workspace_argument_renders_that_workspace() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let one = create_workspace(&db, "WorkspaceOne", "alice", "laptop");
    let two = create_workspace(&db, "WorkspaceTwo", "alice", "laptop");
    assert_success(topo(&["--db", &db, "key-frontier", &one]));
    assert_success(topo(&["--db", &db, "key-frontier", &two]));

    assert_success(topo(&["--db", &db, "send", &one, "in one"]));
    assert_success(topo(&["--db", &db, "send", &two, "in two"]));

    let view_one = assert_success(topo(&["--db", &db, "view", &one]));
    assert!(
        view_one.contains("WORKSPACE:\n  WorkspaceOne"),
        "expected WorkspaceOne header:\n{view_one}"
    );
    assert!(view_one.contains("      1. in one"), "{view_one}");
    assert!(!view_one.contains("in two"), "{view_one}");

    let view_two = assert_success(topo(&["--db", &db, "view", &two]));
    assert!(
        view_two.contains("WORKSPACE:\n  WorkspaceTwo"),
        "expected WorkspaceTwo header:\n{view_two}"
    );
    assert!(view_two.contains("      1. in two"), "{view_two}");
    assert!(!view_two.contains("in one"), "{view_two}");
}

#[test]
fn cli_view_collapses_consecutive_messages_from_same_author() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let workspace_id = create_workspace(&alice, "Activism", "alice", "laptop");
    assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));

    let bob_join_port = free_port();
    join_workspace(
        &alice,
        &bob,
        &workspace_id,
        bob_join_port,
        "bob",
        "phone",
    );

    // Alice sends two consecutive messages. Both should appear under one
    // author header on her local view.
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "first by alice"]));
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "second by alice"]));

    let view = assert_success(topo(&["--db", &alice, "view", &workspace_id]));
    let alice_header_count = view.matches("    alice [").count();
    assert_eq!(
        alice_header_count, 1,
        "expected one alice author header for two consecutive messages:\n{view}"
    );
    // Both numbered messages should appear.
    assert!(
        view.contains("      1. first by alice"),
        "missing first message:\n{view}"
    );
    assert!(
        view.contains("      2. second by alice"),
        "missing second message:\n{view}"
    );
    // Both bob and alice should appear in the USERS list.
    assert!(view.contains("alice/laptop (you)"), "{view}");
    assert!(view.contains("bob/phone"), "{view}");
}

// --------------------------------------------------------------------------
// Helpers (mirror the structure from content_cli_test.rs/encryption_cli_test.rs)
// --------------------------------------------------------------------------

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
    let _ = listener.wait_success("workspace invite listener");
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

//! Black-box CLI tests for content events.
//!
//! Setup deliberately goes through the real `topo` binary: workspace creation,
//! invite listening, invite acceptance, connection learning, sync, and content
//! commands. These tests must not install identity graphs or content rows by
//! importing protocol/store internals.

mod cli_harness;

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::process::Child;
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use cli_harness::*;

#[test]
fn cli_send_then_messages_lists_authored_messages() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Content", "alice", "alice-laptop");
    assert_success(topo(&["--db", &db, "key-frontier", &workspace_id]));

    let send1 = assert_success(topo(&["--db", &db, "send", &workspace_id, "first message"]));
    assert!(send1.contains("text: first message"), "{send1}");

    let send2 = assert_success(topo(&[
        "--db",
        &db,
        "send",
        &workspace_id,
        "second message",
    ]));
    assert!(send2.contains("text: second message"), "{send2}");

    let listing = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert_eq!(line_value(&listing, "messages"), "2");
    assert!(listing.contains("alice: first message"), "{listing}");
    assert!(listing.contains("alice: second message"), "{listing}");
}

#[test]
fn cli_react_appears_in_messages_listing() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Content", "alice", "alice-laptop");
    assert_success(topo(&["--db", &db, "key-frontier", &workspace_id]));

    assert_success(topo(&["--db", &db, "send", &workspace_id, "hello"]));
    let react = assert_success(topo(&["--db", &db, "react", &workspace_id, "#1", "+1"]));
    assert!(react.contains("emoji: +1"), "{react}");

    let listing = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert!(listing.contains("reactions: +1"), "{listing}");
}

#[test]
fn cli_delete_message_purges_target_from_listing() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Content", "alice", "alice-laptop");
    assert_success(topo(&["--db", &db, "key-frontier", &workspace_id]));

    assert_success(topo(&["--db", &db, "send", &workspace_id, "regret"]));
    assert_success(topo(&["--db", &db, "react", &workspace_id, "#1", "ack"]));

    let before = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert!(!before.contains("(deleted)"), "{before}");

    let deleted = assert_success(topo(&["--db", &db, "delete-message", &workspace_id, "#1"]));
    assert!(deleted.contains("event_id:"), "{deleted}");

    let after = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert_eq!(line_value(&after, "messages"), "0");
    assert!(!after.contains("(deleted)"), "{after}");
    assert!(!after.contains("regret"), "{after}");
}

#[test]
fn cli_send_file_then_save_file_round_trips_bytes_through_real_binary() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Content", "alice", "alice-laptop");
    assert_success(topo(&["--db", &db, "key-frontier", &workspace_id]));

    let payload: Vec<u8> = (0..8192u32).map(|byte| byte as u8).collect();
    let in_path = tmp.path().join("input.bin");
    fs::write(&in_path, &payload).expect("write input");

    let sent = assert_success(topo(&[
        "--db",
        &db,
        "send-file",
        &workspace_id,
        "see attached",
        "--file",
        in_path.to_str().expect("path utf-8"),
    ]));
    assert!(sent.contains("filename: input.bin"), "{sent}");
    assert_eq!(line_value(&sent, "blob_bytes"), "8192");
    let file_event_id = line_value(&sent, "file_event_id");

    let files = assert_success(topo(&["--db", &db, "files", &workspace_id]));
    assert_eq!(line_value(&files, "files"), "1");
    assert!(files.contains("input.bin"), "{files}");

    let messages = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert!(
        messages.contains("see attached") && messages.contains("file: input.bin"),
        "{messages}"
    );

    let out_path = tmp.path().join("out.bin");
    let saved = assert_success(topo(&[
        "--db",
        &db,
        "save-file",
        &workspace_id,
        "#1",
        out_path.to_str().expect("path utf-8"),
    ]));
    assert_eq!(line_value(&saved, "filename"), "input.bin");
    assert_eq!(line_value(&saved, "bytes_written"), "8192");

    let read_back = fs::read(&out_path).expect("read output");
    assert_eq!(read_back, payload);

    assert_success(topo(&["--db", &db, "delete-message", &workspace_id, "#1"]));
    let messages_after_delete = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert_eq!(line_value(&messages_after_delete, "messages"), "0");
    let files_after_delete = assert_success(topo(&["--db", &db, "files", &workspace_id]));
    assert_eq!(line_value(&files_after_delete, "files"), "0");

    let hidden_save = topo(&[
        "--db",
        &db,
        "save-file",
        &workspace_id,
        &file_event_id,
        out_path.to_str().expect("path utf-8"),
    ]);
    assert!(
        !hidden_save.status.success(),
        "deleted parent message must hide direct file saves\nstdout={}\nstderr={}",
        stdout(&hidden_save),
        stderr(&hidden_save)
    );
}

#[test]
fn cli_messages_and_reactions_sync_between_two_peers() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let workspace_id = create_workspace(&alice, "Shared", "alice", "alice-laptop");
    let invite_port = free_port();
    let alice_port = free_port();
    let bob_port = free_port();

    join_workspace(&alice, &bob, &workspace_id, invite_port, "bob", "bob-phone");
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    connect_daemon_pair(&alice, alice_port, &bob, bob_port);
    grant_content_key_to_peer(&alice, &bob, &workspace_id);

    assert_success(topo(&["--db", &alice, "send", &workspace_id, "from alice"]));
    assert_success(topo(&[
        "--db",
        &alice,
        "react",
        &workspace_id,
        "#1",
        "seen",
    ]));

    wait_for_messages_count(&bob, &workspace_id, "1");
    wait_for_messages_contains(&bob, &workspace_id, "reactions: seen");
    let bob_listing = assert_success(topo(&["--db", &bob, "messages", &workspace_id]));
    assert_eq!(line_value(&bob_listing, "messages"), "1");
    assert!(bob_listing.contains("alice: from alice"), "{bob_listing}");
    assert!(bob_listing.contains("reactions: seen"), "{bob_listing}");
}

#[test]
fn cli_send_file_syncs_bytes_to_peer_for_save() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let workspace_id = create_workspace(&alice, "Files", "alice", "alice-laptop");
    let invite_port = free_port();
    let alice_port = free_port();
    let bob_port = free_port();

    join_workspace(&alice, &bob, &workspace_id, invite_port, "bob", "bob-phone");
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    connect_daemon_pair(&alice, alice_port, &bob, bob_port);
    grant_content_key_to_peer(&alice, &bob, &workspace_id);

    let payload: Vec<u8> = (0..4096u32).map(|byte| byte as u8).collect();
    let in_path = tmp.path().join("payload.bin");
    fs::write(&in_path, &payload).expect("write input");

    assert_success(topo(&[
        "--db",
        &alice,
        "send-file",
        &workspace_id,
        "see attached",
        "--file",
        in_path.to_str().expect("path"),
    ]));

    wait_for_files_count(&bob, &workspace_id, "1");
    let listing = assert_success(topo(&["--db", &bob, "files", &workspace_id]));
    assert_eq!(line_value(&listing, "files"), "1");
    let out_path = tmp.path().join("out.bin");
    let saved = wait_for_save_file(&bob, &workspace_id, "#1", out_path.to_str().expect("path"));
    assert_eq!(line_value(&saved, "filename"), "payload.bin");
    let read_back = fs::read(&out_path).expect("read output");
    assert_eq!(read_back, payload);
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

struct RunningDaemon {
    child: Child,
}

impl Drop for RunningDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_daemon(db: &str, port: u16) -> RunningDaemon {
    let port = port.to_string();
    let mut child = spawn_topo(&[
        "--db",
        db,
        "start",
        "--listen",
        "127.0.0.1",
        &port,
        "--tick-ms",
        "50",
        "--quiet-ms",
        "50",
    ]);
    let stdout = child.stdout.take().expect("daemon stdout");
    let mut reader = BufReader::new(stdout);
    let mut first = String::new();
    reader.read_line(&mut first).expect("daemon first line");
    assert!(
        first.starts_with("listening: "),
        "daemon did not report listening: {first}"
    );
    RunningDaemon { child }
}

fn connect_daemon_pair(left_db: &str, left_port: u16, right_db: &str, right_port: u16) {
    let left_invite = transport_invite(left_db, left_port);
    let right_invite = transport_invite(right_db, right_port);
    let right_to_left = connect_with_retry(right_db, &left_invite);
    assert!(right_to_left.contains("connected:"), "{right_to_left}");
    let left_to_right = connect_with_retry(left_db, &right_invite);
    assert!(left_to_right.contains("connected:"), "{left_to_right}");
}

fn transport_invite(db: &str, port: u16) -> String {
    let addr = format!("127.0.0.1:{port}");
    let out = assert_success(topo(&["--db", db, "invite", "--public-addr", &addr]));
    invite_link_from_output(&out)
}

fn connect_with_retry(db: &str, invite: &str) -> String {
    let mut last = String::new();
    for _ in 0..200 {
        let output = topo(&["--db", db, "connect", invite]);
        if output.status.success() {
            return stdout(&output);
        }
        last = stderr(&output);
        thread::sleep(Duration::from_millis(50));
    }
    panic!("connect never succeeded: {last}");
}

fn grant_content_key_to_peer(alice: &str, peer: &str, workspace_id: &str) {
    let recipient = assert_success(topo(&["--db", peer, "key-recipient", workspace_id]));
    let recipient_key_id = line_value(&recipient, "recipient_key_id");
    let frontier = assert_success(topo(&["--db", alice, "key-frontier", workspace_id]));
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");
    let wrapped = key_wrap_with_retry(alice, workspace_id, &removal_frontier_id, &recipient_key_id);
    assert_eq!(line_value(&wrapped, "recipient_key_id"), recipient_key_id);
    let derived = wait_for_key_derive(peer, "1");
    assert_eq!(line_value(&derived, "derived_key_secrets"), "1");
}

fn key_wrap_with_retry(
    db: &str,
    workspace_id: &str,
    removal_frontier_id: &str,
    recipient_key_id: &str,
) -> String {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&[
            "--db",
            db,
            "key-wrap",
            workspace_id,
            removal_frontier_id,
            recipient_key_id,
        ]);
        if output.status.success() {
            return stdout(&output);
        }
        last = stderr(&output);
        thread::sleep(Duration::from_millis(100));
    }
    panic!("key-wrap never succeeded: {last}");
}

fn wait_for_key_derive(db: &str, expected: &str) -> String {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "key-derive"]);
        if output.status.success() {
            let out = stdout(&output);
            if line_value(&out, "derived_key_secrets") == expected {
                return out;
            }
            last = out;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("key derive did not reach {expected}: {last}");
}

fn invite_link_from_output(output: &str) -> String {
    output
        .lines()
        .find(|line| line.starts_with("topo://invite/"))
        .unwrap_or_else(|| panic!("missing invite link in output:\n{output}"))
        .to_string()
}

fn wait_for_messages_count(db: &str, workspace_id: &str, expected: &str) {
    wait_for_count(db, "messages", workspace_id, "messages", expected);
}

fn wait_for_files_count(db: &str, workspace_id: &str, expected: &str) {
    wait_for_count(db, "files", workspace_id, "files", expected);
}

fn wait_for_messages_contains(db: &str, workspace_id: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let out = assert_success(topo(&["--db", db, "messages", workspace_id]));
        if out.contains(expected) {
            return;
        }
        last = out;
        thread::sleep(Duration::from_millis(100));
    }
    panic!("messages never contained `{expected}`; last output:\n{last}");
}

fn wait_for_save_file(db: &str, workspace_id: &str, selector: &str, out_path: &str) -> String {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "save-file", workspace_id, selector, out_path]);
        if output.status.success() {
            return stdout(&output);
        }
        last = stderr(&output);
        thread::sleep(Duration::from_millis(100));
    }
    panic!("save-file never succeeded; last stderr:\n{last}");
}

fn wait_for_count(db: &str, command: &str, workspace_id: &str, key: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let out = assert_success(topo(&["--db", db, command, workspace_id]));
        if line_value(&out, key) == expected {
            return;
        }
        last = out;
        thread::sleep(Duration::from_millis(100));
    }
    panic!("{command} count did not reach {expected}; last output:\n{last}");
}

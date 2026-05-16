mod cli_harness;

use std::io::{BufRead, BufReader, Read};
use std::process::Child;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

use cli_harness::*;

#[test]
fn two_endpoints_sync_multiple_mutual_workspaces() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let alice_port = free_port();
    let bob_port = free_port();

    let workspace_a = create_workspace(&alice, "workspace-a", "alice-a", "alice-a-laptop");
    let workspace_b = create_workspace(&alice, "workspace-b", "alice-b", "alice-b-laptop");
    let mut alice_daemon = spawn_daemon(&alice, alice_port);
    let mut bob_daemon = spawn_daemon(&bob, bob_port);
    accept_workspace_invite(
        &alice,
        &bob,
        &workspace_a,
        alice_port,
        "bob-a",
        "bob-a-phone",
    );
    accept_workspace_invite(
        &alice,
        &bob,
        &workspace_b,
        alice_port,
        "bob-b",
        "bob-b-phone",
    );
    alice_daemon.assert_running();
    bob_daemon.assert_running();
    poll_for_workspace_member(&bob, &workspace_a, "bob-a", 10_000);
    poll_for_workspace_member(&bob, &workspace_b, "bob-b", 10_000);

    generate(&alice, &workspace_a, 3, 128);
    generate(&alice, &workspace_b, 4, 129);

    wait_for_content_count(&bob, &workspace_a, 3);
    wait_for_content_count(&bob, &workspace_b, 4);
}

#[test]
fn two_player_sync_does_not_leak_alice_private_workspace_to_bob() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let alice_port = free_port();
    let bob_port = free_port();

    let shared = create_workspace(&alice, "shared-a", "alice-a", "alice-a-laptop");
    let alice_private = create_workspace(&alice, "alice-b", "alice-b", "alice-b-laptop");
    let mut alice_daemon = spawn_daemon(&alice, alice_port);
    let mut bob_daemon = spawn_daemon(&bob, bob_port);
    accept_workspace_invite(&alice, &bob, &shared, alice_port, "bob-a", "bob-a-phone");
    alice_daemon.assert_running();
    bob_daemon.assert_running();
    poll_for_workspace_member(&bob, &shared, "bob-a", 10_000);

    generate(&alice, &shared, 2, 128);

    wait_for_content_count(&bob, &shared, 2);
    generate(&alice, &alice_private, 5, 128);
    thread::sleep(Duration::from_millis(1200));
    assert_content_count(&bob, &alice_private, 0);
}

#[test]
fn three_player_sync_through_alice_keeps_workspace_scopes_separate() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let carol = temp_db(&tmp, "carol.db");
    let alice_port = free_port();
    let bob_port = free_port();
    let carol_port = free_port();

    let workspace_a = create_workspace(&alice, "alice-bob-a", "alice-a", "alice-a-laptop");
    let workspace_b = create_workspace(&alice, "alice-carol-b", "alice-b", "alice-b-laptop");
    let mut alice_daemon = spawn_daemon(&alice, alice_port);
    let mut bob_daemon = spawn_daemon(&bob, bob_port);
    let mut carol_daemon = spawn_daemon(&carol, carol_port);
    accept_workspace_invite(
        &alice,
        &bob,
        &workspace_a,
        alice_port,
        "bob-a",
        "bob-a-phone",
    );
    accept_workspace_invite(
        &alice,
        &carol,
        &workspace_b,
        alice_port,
        "carol-b",
        "carol-b-phone",
    );
    alice_daemon.assert_running();
    bob_daemon.assert_running();
    carol_daemon.assert_running();
    poll_for_workspace_member(&bob, &workspace_a, "bob-a", 10_000);
    poll_for_workspace_member(&carol, &workspace_b, "carol-b", 10_000);

    generate(&bob, &workspace_a, 3, 128);
    generate(&carol, &workspace_b, 4, 128);

    wait_for_content_count(&alice, &workspace_a, 3);
    wait_for_content_count(&alice, &workspace_b, 4);
    wait_for_content_count(&bob, &workspace_a, 3);
    assert_content_count(&bob, &workspace_b, 0);
    assert_content_count(&carol, &workspace_a, 0);
    wait_for_content_count(&carol, &workspace_b, 4);
}

#[test]
fn daemons_sync_cli_generated_content_without_manual_sync() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice-daemon.db");
    let bob = temp_db(&tmp, "bob-daemon.db");
    let alice_port = free_port();
    let bob_port = free_port();
    let workspace = create_workspace(&alice, "daemon-shared", "alice-daemon", "alice-laptop");
    let mut alice_daemon = spawn_daemon(&alice, alice_port);
    let mut bob_daemon = spawn_daemon(&bob, bob_port);
    accept_workspace_invite(
        &alice,
        &bob,
        &workspace,
        alice_port,
        "bob-daemon",
        "bob-phone",
    );
    alice_daemon.assert_running();
    bob_daemon.assert_running();
    poll_for_workspace_member(&bob, &workspace, "bob-daemon", 10_000);

    generate(&alice, &workspace, 3, 128);

    wait_for_content_count(&bob, &workspace, 3);
}

#[test]
fn cli_two_long_running_daemons_converge_messages_without_manual_sync() {
    // Asymmetric: alice runs `start` and prints an invite that points at her
    // daemon listener. Bob runs `start` and then `accept INVITE` once. After
    // accept finishes there is no manual `connect` from either side.
    // Convergence must come from the daemon's periodic outbound sync alone.
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice-asym.db");
    let bob = temp_db(&tmp, "bob-asym.db");
    let alice_port = free_port();
    let bob_port = free_port();

    let workspace = create_workspace(&alice, "asym-shared", "alice", "alice-laptop");
    let invite = workspace_invite_for_addr(&alice, &workspace, alice_port);

    let mut alice_daemon = spawn_daemon(&alice, alice_port);
    let mut bob_daemon = spawn_daemon(&bob, bob_port);

    let accepted = accept_with_identity_retry(&bob, &invite, "bob", "bob-phone");
    assert!(accepted.contains("connected:"), "{accepted}");
    assert_eq!(line_value(&accepted, "workspace_id"), workspace);
    alice_daemon.assert_running();
    bob_daemon.assert_running();

    // Wait for the membership graph to reach bob through the daemon's
    // periodic sync. The daemons exchange compare/have/need rounds without
    // any operator running `sync`.
    poll_for_workspace_member(&bob, &workspace, "bob", 10_000);

    let bob_recipient_id = line_value(
        &assert_success(topo(&["--db", &bob, "key-recipient", &workspace])),
        "recipient_key_id",
    );

    let removal_frontier_id = line_value(
        &assert_success(topo(&["--db", &alice, "key-frontier", &workspace])),
        "removal_frontier_id",
    );
    let wrap = poll_for_wrap_eligibility(
        &alice,
        &workspace,
        &removal_frontier_id,
        &bob_recipient_id,
        10_000,
    );
    assert_eq!(line_value(&wrap, "recipient_key_id"), bob_recipient_id);

    poll_for_key_access(&bob, &workspace, &removal_frontier_id, "yes", 10_000);

    let alice_send = assert_success(topo(&["--db", &alice, "send", &workspace, "hello"]));
    assert_eq!(line_value(&alice_send, "text"), "hello");

    poll_for_message_text(&bob, &workspace, "hello", 10_000);
}

#[test]
#[ignore = "asymmetric three-peer late-joiner convergence still has a transit \
admission race when alice processes bob's sync compares while accepting carol's \
bootstrap stream; tracked as a follow-on \
fix"]
fn cli_three_long_running_daemons_converge_messages_among_late_joiner() {
    // alice runs a daemon. bob accepts alice's daemon-served invite, then
    // carol does the same. All three converge on shared messages from alice
    // and bob without anyone running manual `sync`.
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice-three.db");
    let bob = temp_db(&tmp, "bob-three.db");
    let carol = temp_db(&tmp, "carol-three.db");
    let alice_port = free_port();
    let bob_port = free_port();
    let carol_port = free_port();

    let workspace = create_workspace(&alice, "three-shared", "alice", "alice-laptop");
    let invite_for_bob = workspace_invite_for_addr(&alice, &workspace, alice_port);

    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);

    let accepted_bob = accept_with_identity_retry(&bob, &invite_for_bob, "bob", "bob-phone");
    assert_eq!(line_value(&accepted_bob, "workspace_id"), workspace);

    // Late joiner: carol accepts a fresh invite from alice's daemon and starts
    // her own daemon BEFORE bob/alice exchange any encrypted content. The
    // periodic outbound sync still has to fan out alice's identity events to
    // both bob and carol, and sync their own join/identity events back to
    // alice and to each other.
    let invite_for_carol = workspace_invite_for_addr(&alice, &workspace, alice_port);
    let _carol_daemon = spawn_daemon(&carol, carol_port);
    let accepted_carol =
        accept_with_identity_retry(&carol, &invite_for_carol, "carol", "carol-tablet");
    assert_eq!(line_value(&accepted_carol, "workspace_id"), workspace);

    poll_for_workspace_member(&bob, &workspace, "bob", 10_000);
    poll_for_workspace_member(&carol, &workspace, "carol", 10_000);

    let bob_recipient_id = line_value(
        &assert_success(topo(&["--db", &bob, "key-recipient", &workspace])),
        "recipient_key_id",
    );
    let carol_recipient_id = line_value(
        &assert_success(topo(&["--db", &carol, "key-recipient", &workspace])),
        "recipient_key_id",
    );

    let removal_frontier_id = line_value(
        &assert_success(topo(&["--db", &alice, "key-frontier", &workspace])),
        "removal_frontier_id",
    );
    poll_for_wrap_eligibility(
        &alice,
        &workspace,
        &removal_frontier_id,
        &bob_recipient_id,
        10_000,
    );
    poll_for_wrap_eligibility(
        &alice,
        &workspace,
        &removal_frontier_id,
        &carol_recipient_id,
        10_000,
    );
    poll_for_key_access(&bob, &workspace, &removal_frontier_id, "yes", 10_000);
    poll_for_key_access(&carol, &workspace, &removal_frontier_id, "yes", 10_000);

    let alice_send = assert_success(topo(&["--db", &alice, "send", &workspace, "from-alice"]));
    assert_eq!(line_value(&alice_send, "text"), "from-alice");
    let bob_send = assert_success(topo(&["--db", &bob, "send", &workspace, "from-bob"]));
    assert_eq!(line_value(&bob_send, "text"), "from-bob");

    poll_for_message_text(&bob, &workspace, "from-alice", 30_000);
    poll_for_message_text(&carol, &workspace, "from-alice", 30_000);
    poll_for_message_text(&alice, &workspace, "from-bob", 30_000);
    poll_for_message_text(&carol, &workspace, "from-bob", 30_000);
}

fn workspace_invite_for_addr(db: &str, workspace_id: &str, port: u16) -> String {
    let addr = format!("127.0.0.1:{port}");
    let out = assert_success(topo(&[
        "--db",
        db,
        "invite",
        "--workspace",
        workspace_id,
        "--public-addr",
        &addr,
    ]));
    invite_link_from_output(&out)
}

fn invite_link_from_output(output: &str) -> String {
    output
        .lines()
        .find(|line| line.starts_with("topo://invite/"))
        .unwrap_or_else(|| panic!("missing invite link in output:\n{output}"))
        .to_string()
}

fn accept_with_identity_retry(db: &str, invite: &str, username: &str, device_name: &str) -> String {
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
            return stdout(&output);
        }
        last = stderr(&output);
        // Bootstrap can retry on transient TCP failures or when alice's
        // daemon has not yet committed the new user_invite to its events
        // table for the just-created invite link.
        if !last.contains("open tcp stream") && !last.contains("user invite was not received") {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("accept never succeeded: {last}");
}

fn poll_for_workspace_member(db: &str, workspace_id: &str, username: &str, timeout_ms: u64) {
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        let recipient = topo(&["--db", db, "key-recipient", workspace_id]);
        let users = topo(&["--db", db, "users", workspace_id]);
        if recipient.status.success() && users.status.success() {
            let text = stdout(&users);
            if text.contains(username) {
                return;
            }
            last = text;
        } else {
            last = format!(
                "key-recipient stderr:\n{}\nusers stderr:\n{}",
                stderr(&recipient),
                stderr(&users)
            );
        }
        thread::sleep(Duration::from_millis(250));
    }
    let count = topo(&["--db", db, "count"]);
    let count_output = if count.status.success() {
        stdout(&count)
    } else {
        stderr(&count)
    };
    panic!(
        "user {username} did not converge into {db}; last users output:\n{last}\ncount output:\n{count_output}"
    );
}

fn poll_for_wrap_eligibility(
    db: &str,
    workspace_id: &str,
    removal_frontier_id: &str,
    recipient_key_id: &str,
    timeout_ms: u64,
) -> String {
    // `key-wrap` is only allowed once both sides of the recipient/frontier
    // pair are visible locally. Polling its success doubles as a sync-arrival
    // probe without leaning on internal storage.
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        let out = topo(&[
            "--db",
            db,
            "key-wrap",
            workspace_id,
            removal_frontier_id,
            recipient_key_id,
        ]);
        if out.status.success() {
            return stdout(&out);
        }
        last = stderr(&out);
        thread::sleep(Duration::from_millis(250));
    }
    panic!("key-wrap never succeeded in {db}; last error:\n{last}");
}

fn poll_for_key_access(
    db: &str,
    workspace_id: &str,
    removal_frontier_id: &str,
    expected: &str,
    timeout_ms: u64,
) {
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        let out = topo(&["--db", db, "key-access", workspace_id, removal_frontier_id]);
        if out.status.success() {
            let text = stdout(&out);
            if line_value(&text, "access") == expected {
                return;
            }
            last = text;
        } else {
            last = stderr(&out);
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic!("key-access did not reach {expected} in {db}; last output:\n{last}");
}

fn poll_for_message_text(db: &str, workspace_id: &str, expected_text: &str, timeout_ms: u64) {
    let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        let out = topo(&["--db", db, "messages", workspace_id]);
        if out.status.success() {
            let text = stdout(&out);
            if text.contains(expected_text) {
                return;
            }
            last = text;
        } else {
            last = stderr(&out);
        }
        thread::sleep(Duration::from_millis(250));
    }
    panic!("messages in {db} never contained {expected_text}; last output:\n{last}");
}

#[test]
fn second_daemon_for_same_db_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice-single-daemon.db");
    let first_port = free_port();
    let second_port = free_port();
    let _daemon = spawn_daemon(&alice, first_port);

    let output = topo(&[
        "--db",
        &alice,
        "start",
        "--listen",
        "127.0.0.1",
        &second_port.to_string(),
        "--sync-ms",
        "100",
        "--quiet-ms",
        "100",
    ]);
    assert!(
        !output.status.success(),
        "second daemon unexpectedly started\nstdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("daemon already running"),
        "unexpected second-daemon stderr:\n{}",
        stderr(&output)
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

fn accept_workspace_invite(
    host_db: &str,
    joiner_db: &str,
    workspace_id: &str,
    port: u16,
    username: &str,
    device_name: &str,
) {
    let invite = workspace_invite_for_addr(host_db, workspace_id, port);
    let accepted = match try_accept_with_identity_retry(joiner_db, &invite, username, device_name) {
        Ok(output) => output,
        Err(err) => panic!("workspace invite accept failed: {err}"),
    };
    assert_eq!(line_value(&accepted, "workspace_id"), workspace_id);
}

struct RunningDaemon {
    child: Child,
    label: String,
    stdout: Option<JoinHandle<String>>,
    stderr: Option<JoinHandle<String>>,
}

impl Drop for RunningDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(stdout) = self.stdout.take() {
            let _ = stdout.join();
        }
        if let Some(stderr) = self.stderr.take() {
            if let Ok(text) = stderr.join() {
                if !text.trim().is_empty() {
                    eprintln!("[daemon-stderr label={}] {}", self.label, text.trim_end());
                }
            }
        }
    }
}

impl RunningDaemon {
    fn assert_running(&mut self) {
        match self.child.try_wait() {
            Ok(None) => {}
            Ok(Some(status)) => panic!("daemon {} exited early: {status}", self.label),
            Err(err) => panic!("poll daemon {}: {err}", self.label),
        }
    }
}

fn spawn_daemon(db: &str, port: u16) -> RunningDaemon {
    let port_str = port.to_string();
    let mut child = spawn_topo(&[
        "--db",
        db,
        "start",
        "--listen",
        "127.0.0.1",
        &port_str,
        "--sync-ms",
        "100",
        "--quiet-ms",
        "100",
    ]);
    let stdout = child.stdout.take().expect("daemon stdout");
    let stderr = child.stderr.take().expect("daemon stderr");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read daemon line");
    assert!(
        line.starts_with("listening: "),
        "daemon did not report listening: {line}"
    );
    let stdout_handle = thread::spawn(move || {
        let mut text = String::new();
        let _ = reader.read_to_string(&mut text);
        text
    });
    let stderr_handle = thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut text = String::new();
        let _ = reader.read_to_string(&mut text);
        text
    });
    RunningDaemon {
        child,
        label: format!("{db}@{port}"),
        stdout: Some(stdout_handle),
        stderr: Some(stderr_handle),
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

fn generate(db: &str, workspace: &str, count: usize, size: usize) -> String {
    let count = count.to_string();
    let size = size.to_string();
    assert_success(topo(&["--db", db, "generate", workspace, &count, &size]))
}

fn assert_content_count(db: &str, workspace: &str, expected: usize) {
    let out = assert_success(topo(&["--db", db, "content-count", workspace]));
    assert_eq!(
        line_value(&out, "content_events"),
        expected.to_string(),
        "content-count output:\n{out}"
    );
}

fn wait_for_content_count(db: &str, workspace: &str, expected: usize) {
    let mut last = String::new();
    for _ in 0..300 {
        let out = assert_success(topo(&["--db", db, "content-count", workspace]));
        if line_value(&out, "content_events") == expected.to_string() {
            return;
        }
        last = out;
        thread::sleep(Duration::from_millis(100));
    }
    panic!("content count did not reach {expected}; last output:\n{last}");
}

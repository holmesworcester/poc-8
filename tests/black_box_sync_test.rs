mod cli_harness;

use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Output};
use std::sync::mpsc::{self, Receiver};
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
    accept_workspace_invite(
        &alice,
        &bob,
        &workspace_a,
        free_port(),
        "bob-a",
        "bob-a-phone",
    );
    let workspace_b = create_workspace(&alice, "workspace-b", "alice-b", "alice-b-laptop");
    accept_workspace_invite(
        &alice,
        &bob,
        &workspace_b,
        free_port(),
        "bob-b",
        "bob-b-phone",
    );
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    connect_daemon_pair(&alice, alice_port, &bob, bob_port);

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
    accept_workspace_invite(&alice, &bob, &shared, free_port(), "bob-a", "bob-a-phone");
    let alice_private = create_workspace(&alice, "alice-b", "alice-b", "alice-b-laptop");
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    connect_daemon_pair(&alice, alice_port, &bob, bob_port);

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
    accept_workspace_invite(
        &alice,
        &bob,
        &workspace_a,
        alice_port,
        "bob-a",
        "bob-a-phone",
    );
    let workspace_b = create_workspace(&alice, "alice-carol-b", "alice-b", "alice-b-laptop");
    accept_workspace_invite(
        &alice,
        &carol,
        &workspace_b,
        alice_port,
        "carol-b",
        "carol-b-phone",
    );
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    let _carol_daemon = spawn_daemon(&carol, carol_port);
    connect_daemon_pair(&alice, alice_port, &bob, bob_port);
    connect_daemon_pair(&alice, alice_port, &carol, carol_port);

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
    accept_workspace_invite(
        &alice,
        &bob,
        &workspace,
        alice_port,
        "bob-daemon",
        "bob-phone",
    );
    let alice_invite = invite(&alice, alice_port);
    let reverse_invite = invite(&bob, bob_port);

    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    let connected = connect_with_retry(&bob, &alice_invite);
    assert!(connected.contains("connected:"), "{connected}");
    let reverse_connected = connect_with_retry(&alice, &reverse_invite);
    assert!(
        reverse_connected.contains("connected:"),
        "{reverse_connected}"
    );

    generate(&alice, &workspace, 3, 128);

    wait_for_content_count(&bob, &workspace, 3);
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
    let mut listener = spawn_workspace_invite_listener(host_db, workspace_id, port, 1);
    let invite = listener.invite_link();
    let accepted = match try_accept_with_identity_retry(joiner_db, &invite, username, device_name) {
        Ok(output) => output,
        Err(err) => listener.fail("workspace invite accept failed", err),
    };
    assert_eq!(line_value(&accepted, "workspace_id"), workspace_id);
    let host_out = listener.wait_success("workspace invite listener");
    assert!(host_out.contains("accepted_connections: 1"), "{host_out}");
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
        "--sync-ms",
        "100",
        "--quiet-ms",
        "100",
    ]);
    let stdout = child.stdout.take().expect("daemon stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read daemon line");
    assert!(
        line.starts_with("listening: "),
        "daemon did not report listening: {line}"
    );
    RunningDaemon { child }
}

fn connect_daemon_pair(left_db: &str, left_port: u16, right_db: &str, right_port: u16) {
    let left_invite = invite(left_db, left_port);
    let right_invite = invite(right_db, right_port);
    let right_to_left = connect_with_retry(right_db, &left_invite);
    assert!(right_to_left.contains("connected:"), "{right_to_left}");
    let left_to_right = connect_with_retry(left_db, &right_invite);
    assert!(left_to_right.contains("connected:"), "{left_to_right}");
}

fn invite(db: &str, port: u16) -> String {
    let addr = format!("127.0.0.1:{port}");
    let out = assert_success(topo(&["--db", db, "invite", "--public-addr", &addr]));
    out.lines()
        .find(|line| line.starts_with("topo://invite/"))
        .unwrap_or_else(|| panic!("missing invite link in output:\n{out}"))
        .to_string()
}

fn connect_with_retry(db: &str, invite: &str) -> String {
    let mut last = String::new();
    for _ in 0..200 {
        let output = connect_with_invite(db, invite);
        if output.status.success() {
            return stdout(&output);
        }
        last = stderr(&output);
        thread::sleep(Duration::from_millis(50));
    }
    panic!("connect never succeeded: {last}");
}

fn connect_with_invite(db: &str, invite: &str) -> Output {
    topo(&["--db", db, "connect", invite])
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

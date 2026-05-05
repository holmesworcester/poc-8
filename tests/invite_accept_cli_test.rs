mod cli_harness;

use std::io::{BufRead, BufReader, Read};
use std::process::Child;
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use cli_harness::*;

#[test]
fn invite_listens_and_accept_connects_two_cli_processes() {
    let tmp = tempfile::tempdir().unwrap();
    let host = temp_db(&tmp, "host.db");
    let joiner = temp_db(&tmp, "joiner.db");
    let port = free_port();

    let mut listener = spawn_invite_listener(&host, port, 1);
    let invite = listener.invite_link();
    let accepted = accept_with_retry(&joiner, &invite);
    assert!(accepted.contains("connected:"), "{accepted}");

    let host_out = listener.wait_success("single invite listener");
    assert!(host_out.contains("accepted_connections: 1"), "{host_out}");
    assert_eq!(connection_count(&host), 1);
    assert_eq!(connection_count(&joiner), 1);
    assert_eq!(connection_event_count(&host), 2);
    assert_eq!(connection_event_count(&joiner), 2);
}

#[test]
fn invite_listens_for_two_separate_accepting_cli_processes() {
    let tmp = tempfile::tempdir().unwrap();
    let host = temp_db(&tmp, "host.db");
    let joiner_a = temp_db(&tmp, "joiner-a.db");
    let joiner_b = temp_db(&tmp, "joiner-b.db");
    let port = free_port();

    let mut listener = spawn_invite_listener(&host, port, 2);
    let invite = listener.invite_link();

    let accepted_a = accept_with_retry(&joiner_a, &invite);
    assert!(accepted_a.contains("connected:"), "{accepted_a}");
    let accepted_b = accept_with_retry(&joiner_b, &invite);
    assert!(accepted_b.contains("connected:"), "{accepted_b}");

    let host_out = listener.wait_success("two-accept invite listener");
    assert!(host_out.contains("accepted_connections: 2"), "{host_out}");
    assert_eq!(connection_count(&host), 2);
    assert_eq!(connection_count(&joiner_a), 1);
    assert_eq!(connection_count(&joiner_b), 1);
    assert_eq!(connection_event_count(&host), 4);
    assert_eq!(connection_event_count(&joiner_a), 2);
    assert_eq!(connection_event_count(&joiner_b), 2);
}

#[test]
fn workspace_invite_accept_builds_identity_graph_over_two_cli_processes() {
    let tmp = tempfile::tempdir().unwrap();
    let host = temp_db(&tmp, "host.db");
    let joiner = temp_db(&tmp, "joiner.db");
    let port = free_port();

    let created = assert_success(topo(&[
        "--db",
        &host,
        "create-workspace",
        "Alpha",
        "--username",
        "alice",
        "--devicename",
        "alice-laptop",
    ]));
    let workspace_id = line_value(&created, "workspace_id");

    let mut listener = spawn_workspace_invite_listener(&host, &workspace_id, port, 1);
    let invite = listener.invite_link();
    let accepted = match try_accept_with_identity_retry(&joiner, &invite, "bob", "bob-phone") {
        Ok(output) => output,
        Err(err) => {
            listener.fail("bob accept failed", err);
        }
    };
    assert!(accepted.contains("connected:"), "{accepted}");
    assert_eq!(line_value(&accepted, "workspace_id"), workspace_id);

    let host_out = listener.wait_success("workspace invite listener");
    assert!(host_out.contains("accepted_connections: 1"), "{host_out}");

    let workspaces = assert_success(topo(&["--db", &joiner, "workspaces"]));
    assert!(workspaces.contains("Alpha"), "{workspaces}");
    assert!(workspaces.contains(&workspace_id), "{workspaces}");

    let users = assert_success(topo(&["--db", &joiner, "users", &workspace_id]));
    assert!(users.contains("alice"), "{users}");
    assert!(users.contains("bob"), "{users}");

    let host_users = assert_success(topo(&["--db", &host, "users", &workspace_id]));
    assert!(host_users.contains("alice"), "{host_users}");
    assert!(host_users.contains("bob"), "{host_users}");

    let duplicate = topo(&[
        "--db",
        &joiner,
        "accept",
        &invite,
        "--username",
        "bob-again",
        "--devicename",
        "bob-second",
    ]);
    assert!(
        !duplicate.status.success(),
        "duplicate join unexpectedly succeeded:\n{}",
        stdout(&duplicate)
    );
    assert!(
        stderr(&duplicate).contains("endpoint is already joined to workspace"),
        "{}",
        stderr(&duplicate)
    );
}

#[test]
fn workspace_invite_is_multi_use_for_two_accepting_users() {
    let tmp = tempfile::tempdir().unwrap();
    let host = temp_db(&tmp, "host.db");
    let bob = temp_db(&tmp, "bob.db");
    let carol = temp_db(&tmp, "carol.db");
    let port = free_port();

    let created = assert_success(topo(&[
        "--db",
        &host,
        "create-workspace",
        "Alpha",
        "--username",
        "alice",
        "--devicename",
        "alice-laptop",
    ]));
    let workspace_id = line_value(&created, "workspace_id");

    let mut listener = spawn_workspace_invite_listener(&host, &workspace_id, port, 2);
    let invite = listener.invite_link();
    let accepted_bob = match try_accept_with_identity_retry(&bob, &invite, "bob", "bob-phone") {
        Ok(output) => output,
        Err(err) => {
            listener.fail("bob accept failed", err);
        }
    };
    assert_eq!(line_value(&accepted_bob, "workspace_id"), workspace_id);
    thread::sleep(Duration::from_millis(50));
    let accepted_carol =
        match try_accept_with_identity_retry(&carol, &invite, "carol", "carol-phone") {
            Ok(output) => output,
            Err(err) => {
                listener.fail("carol accept failed", err);
            }
        };
    assert_eq!(line_value(&accepted_carol, "workspace_id"), workspace_id);

    let host_out = listener.wait_success("multi-use workspace invite listener");
    assert!(host_out.contains("accepted_connections: 2"), "{host_out}");

    let bob_users = assert_success(topo(&["--db", &bob, "users", &workspace_id]));
    assert!(bob_users.contains("alice"), "{bob_users}");
    assert!(bob_users.contains("bob"), "{bob_users}");

    let carol_users = assert_success(topo(&["--db", &carol, "users", &workspace_id]));
    assert!(carol_users.contains("alice"), "{carol_users}");
    assert!(carol_users.contains("carol"), "{carol_users}");

    let host_users = assert_success(topo(&["--db", &host, "users", &workspace_id]));
    assert!(host_users.contains("alice"), "{host_users}");
    assert!(host_users.contains("bob"), "{host_users}");
    assert!(host_users.contains("carol"), "{host_users}");
}

#[test]
fn device_link_accept_links_second_device_over_two_cli_processes() {
    let tmp = tempfile::tempdir().unwrap();
    let host = temp_db(&tmp, "host.db");
    let phone = temp_db(&tmp, "phone.db");
    let port = free_port();

    let created = assert_success(topo(&[
        "--db",
        &host,
        "create-workspace",
        "Alpha",
        "--username",
        "alice",
        "--devicename",
        "alice-laptop",
    ]));
    let workspace_id = line_value(&created, "workspace_id");
    let user_id = line_value(&created, "user_id");

    let mut listener = spawn_device_link_listener(&host, &workspace_id, port, 1);
    let link = listener.invite_link();
    let accepted = match try_accept_link_with_retry(&phone, &link, "alice-phone") {
        Ok(output) => output,
        Err(err) => {
            listener.fail("device link accept failed", err);
        }
    };
    assert!(accepted.contains("connected:"), "{accepted}");
    assert_eq!(line_value(&accepted, "workspace_id"), workspace_id);

    let host_out = listener.wait_success("device link listener");
    assert!(host_out.contains("accepted_connections: 1"), "{host_out}");

    let identity = assert_success(topo(&["--db", &phone, "identity"]));
    assert!(identity.contains(&workspace_id), "{identity}");
    assert!(
        identity.contains(&format!("user_id={user_id}")),
        "{identity}"
    );

    let host_users = assert_success(topo(&["--db", &host, "users", &workspace_id]));
    assert!(host_users.contains("alice"), "{host_users}");
    assert!(host_users.contains(&user_id), "{host_users}");

    let host_peers = assert_success(topo(&["--db", &host, "peers", &workspace_id]));
    assert!(host_peers.contains("alice-laptop"), "{host_peers}");
    assert!(host_peers.contains("alice-phone"), "{host_peers}");
    assert!(
        host_peers.contains(&format!("user_id={user_id}")),
        "{host_peers}"
    );

    let duplicate = topo(&[
        "--db",
        &phone,
        "accept-link",
        &link,
        "--devicename",
        "alice-phone-again",
    ]);
    assert!(
        !duplicate.status.success(),
        "duplicate link unexpectedly succeeded:\n{}",
        stdout(&duplicate)
    );
    assert!(
        stderr(&duplicate).contains("endpoint is already joined to workspace"),
        "{}",
        stderr(&duplicate)
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

fn spawn_device_link_listener(
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
        "link",
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

fn try_accept_link_with_retry(db: &str, invite: &str, device_name: &str) -> Result<String, String> {
    let mut last = String::new();
    for _ in 0..200 {
        let output = topo(&[
            "--db",
            db,
            "accept-link",
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

fn connection_count(db: &str) -> usize {
    count_value(db, "connections")
}

fn connection_event_count(db: &str) -> usize {
    count_value(db, "connection_events")
}

fn count_value(db: &str, key: &str) -> usize {
    let out = assert_success(topo(&["--db", db, "count"]));
    line_value(&out, key).parse().expect("parse count value")
}

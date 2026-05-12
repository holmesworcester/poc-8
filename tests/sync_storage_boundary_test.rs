#[path = "cli_harness/mod.rs"]
mod cli_harness;

use std::io::{BufRead, BufReader};
use std::process::{Child, Output};
use std::thread;
use std::time::Duration;

use cli_harness::*;

#[test]
fn accept_handshake_does_not_create_durable_events() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let port = free_port();
    let alice_port = free_port();
    let bob_invite = invite(&bob, port);
    assert_eq!(count(&bob), 0, "invite facts must be local-only events");

    let _daemon = spawn_daemon(&bob, port);
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let connected = accept_connection_with_retry(&alice, &bob_invite);
    assert!(connected.contains("connected:"), "{connected}");
    wait_for_connection_count(&bob, 1);
    wait_for_connection_event_count(&bob, 2);

    assert_eq!(count(&alice), 0, "accept must not store local sync items");
    assert_eq!(count(&bob), 0, "connect must not store remote sync items");
    assert_eq!(connection_count(&alice), 1);
    assert_eq!(connection_count(&bob), 1);
    assert_eq!(connection_event_count(&alice), 2);
    assert_eq!(connection_event_count(&bob), 2);
}

#[test]
fn wrong_invite_private_key_does_not_project_receiver_connection() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let port = free_port();
    let alice_port = free_port();
    let bob_invite = invite(&bob, port);
    let wrong_invite = replace_invite_private_key(&bob_invite, &"00".repeat(32));

    let _daemon = spawn_daemon(&bob, port);
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let connected = accept_invite(&alice, &wrong_invite);
    assert!(
        !connected.status.success(),
        "wrong invite unexpectedly connected:\n{}",
        stdout(&connected)
    );
    assert!(
        stderr(&connected).contains("did not produce a connection"),
        "stderr:\n{}",
        stderr(&connected)
    );
    thread::sleep(Duration::from_millis(500));

    assert_eq!(count(&alice), 0);
    assert_eq!(count(&bob), 0);
    assert_eq!(connection_count(&alice), 0);
    assert_eq!(connection_count(&bob), 0);
    assert_eq!(connection_event_count(&alice), 1);
    assert_eq!(connection_event_count(&bob), 0);
}

#[test]
fn accept_reports_unreachable_invite_address() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let unreachable_invite = invite(&alice, free_port());
    let connected = accept_invite(&alice, &unreachable_invite);
    assert!(
        !connected.status.success(),
        "accept unexpectedly reached unused port:\n{}",
        stdout(&connected)
    );
    assert!(
        stderr(&connected).contains("open tcp stream"),
        "stderr:\n{}",
        stderr(&connected)
    );
    assert_eq!(count(&alice), 0);
    assert_eq!(connection_count(&alice), 0);
    assert_eq!(connection_event_count(&alice), 1);
}

struct RunningDaemon {
    child: Child,
}

impl Drop for RunningDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        thread::sleep(Duration::from_millis(100));
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

fn invite(db: &str, port: u16) -> String {
    let addr = format!("127.0.0.1:{port}");
    let out = assert_success(topo(&["--db", db, "invite", "--public-addr", &addr]));
    out.lines()
        .find(|line| line.starts_with("topo://invite/"))
        .unwrap_or_else(|| panic!("missing invite link in output:\n{out}"))
        .to_string()
}

fn accept_connection_with_retry(db: &str, invite: &str) -> String {
    let mut last = String::new();
    for _ in 0..200 {
        let output = accept_invite(db, invite);
        if output.status.success() {
            return stdout(&output);
        }
        last = stderr(&output);
        thread::sleep(Duration::from_millis(50));
    }
    panic!("accept never succeeded: {last}");
}

fn accept_invite(db: &str, invite: &str) -> Output {
    topo(&["--db", db, "accept", invite])
}

fn wait_for_connection_count(db: &str, expected: usize) {
    for _ in 0..100 {
        if connection_count(db) == expected {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "connection count never reached {expected}; current {}",
        connection_count(db)
    );
}

fn wait_for_connection_event_count(db: &str, expected: usize) {
    for _ in 0..100 {
        if connection_event_count(db) == expected {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "connection event count never reached {expected}; current {}",
        connection_event_count(db)
    );
}

fn replace_invite_private_key(link: &str, private_key_hex: &str) -> String {
    replace_invite_part(link, "INVITE_PRIVKEY", private_key_hex)
}

fn replace_invite_part(link: &str, label: &str, value: &str) -> String {
    let prefix = format!("{label}.");
    link.split('/')
        .map(|part| {
            if part.starts_with(&prefix) {
                format!("{prefix}{value}")
            } else {
                part.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn count(db: &str) -> usize {
    let out = assert_success(topo(&["--db", db, "count"]));
    line_value(&out, "events")
        .parse()
        .expect("parse event count")
}

fn connection_count(db: &str) -> usize {
    let out = assert_success(topo(&["--db", db, "count"]));
    line_value(&out, "connections")
        .parse()
        .expect("parse connection count")
}

fn connection_event_count(db: &str) -> usize {
    let out = assert_success(topo(&["--db", db, "count"]));
    line_value(&out, "connection_events")
        .parse()
        .expect("parse connection event count")
}

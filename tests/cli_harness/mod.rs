#![allow(dead_code)]

use std::net::TcpListener;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::Duration;

pub fn topo(db: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_topo"))
        .arg("--db")
        .arg(db)
        .args(args)
        .output()
        .expect("run topo")
}

pub fn topo_no_db(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_topo"))
        .args(args)
        .output()
        .expect("run topo")
}

pub fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

pub fn assert_success(output: Output) -> String {
    assert!(
        output.status.success(),
        "command failed: stdout={} stderr={}",
        stdout(&output),
        stderr(&output)
    );
    stdout(&output)
}

pub fn assert_failure(output: Output) -> String {
    assert!(
        !output.status.success(),
        "command unexpectedly succeeded: stdout={} stderr={}",
        stdout(&output),
        stderr(&output)
    );
    stderr(&output)
}

pub fn temp_db(dir: &tempfile::TempDir, name: &str) -> String {
    dir.path().join(name).to_string_lossy().to_string()
}

pub fn create_workspace(db: &str, name: &str) -> String {
    assert_success(topo(db, &["create-workspace", "--workspace-name", name]))
}

pub fn create_account(db: &str, username: &str, device_name: &str) -> String {
    assert_success(topo(
        db,
        &[
            "create-account",
            "--username",
            username,
            "--device-name",
            device_name,
        ],
    ))
}

pub fn create_invite(db: &str) -> String {
    let out = assert_success(topo(db, &["invite"]));
    out.lines()
        .find(|line| line.starts_with("topo://invite/"))
        .expect("invite link")
        .to_string()
}

pub fn accept_invite(db: &str, invite: &str, username: &str, device_name: &str) -> String {
    assert_success(topo(
        db,
        &[
            "accept",
            invite,
            "--username",
            username,
            "--device-name",
            device_name,
        ],
    ))
}

pub fn send_message(db: &str, message: &str) -> String {
    assert_success(topo(db, &["send", message]))
}

pub fn line_value(output: &str, key: &str) -> String {
    let prefix = format!("{key}: ");
    output
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .expect("line value")
        .to_string()
}

pub fn free_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr.to_string()
}

pub fn spawn_receive(db: &str, addr: &str, count: usize) -> Child {
    Command::new(env!("CARGO_BIN_EXE_topo"))
        .arg("--db")
        .arg(db)
        .arg("receive")
        .arg("--bind")
        .arg(addr)
        .arg("--count")
        .arg(count.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn receiver")
}

pub fn send_pending_with_retry(db: &str, connection_id: &str, addr: &str) -> String {
    let mut last_stderr = String::new();
    for _ in 0..30 {
        let output = topo(
            db,
            &[
                "send-pending",
                "--connection-id",
                connection_id,
                "--addr",
                addr,
            ],
        );
        if output.status.success() {
            return stdout(&output);
        }
        last_stderr = stderr(&output);
        thread::sleep(Duration::from_millis(50));
    }
    panic!("send-pending never succeeded: {last_stderr}");
}

pub fn queue_event(db: &str, event_id: &str, connection_id: &str) -> String {
    assert_success(topo(
        db,
        &["queue-event", event_id, "--connection-id", connection_id],
    ))
}

pub fn queue_events(db: &str, connection_id: &str, type_filter: Option<&str>) -> String {
    let mut args = vec!["queue-events", "--connection-id", connection_id];
    if let Some(type_filter) = type_filter {
        args.push("--type");
        args.push(type_filter);
    }
    assert_success(topo(db, &args))
}

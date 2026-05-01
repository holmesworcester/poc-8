#![allow(dead_code)]

use std::process::{Command, Output};

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

pub fn send_message(db: &str, message: &str) -> String {
    assert_success(topo(db, &["send", message]))
}

pub fn sync_from(db: &str, peer_db: &str) -> String {
    assert_success(topo(db, &["sync-from", peer_db]))
}

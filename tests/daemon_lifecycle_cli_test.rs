//! Black-box tests for `topo stop` and `topo reset`.
//!
//! These drive the real `topo` binary to prove the daemon actually exits, the
//! lock file is released, and reset removes the local store files. They use
//! only the public CLI surface: process spawn, signal observation through
//! `/proc`, and file-existence checks.

mod cli_harness;

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::Child;
use std::thread;
use std::time::{Duration, Instant};

use cli_harness::*;

fn lock_path(db: &str) -> String {
    format!("{db}.daemon.lock")
}

fn process_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

fn wait_until<F: FnMut() -> bool>(timeout: Duration, mut check: F) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if check() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    check()
}

struct StartedDaemon {
    child: Option<Child>,
    pid: u32,
}

impl StartedDaemon {
    fn pid(&self) -> u32 {
        self.pid
    }

    /// Disarm the drop guard and reap the child once it exits. Use this when
    /// the test driver expects an external command (`topo stop` or
    /// `topo reset`) to terminate the daemon cleanly: this returns the exit
    /// status from `wait()` without sending SIGKILL.
    fn wait_clean_exit(mut self, timeout: Duration) -> bool {
        let mut child = match self.child.take() {
            Some(child) => child,
            None => return true,
        };
        let pid = self.pid;
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(status)) => return status.success(),
                Ok(None) => thread::sleep(Duration::from_millis(20)),
                Err(_) => return false,
            }
        }
        let _ = child.kill();
        let _ = child.wait();
        panic!("daemon pid {pid} did not exit within {timeout:?}");
    }
}

impl Drop for StartedDaemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn start_daemon(db: &str, port: u16) -> StartedDaemon {
    let port_string = port.to_string();
    let mut child = spawn_topo(&[
        "--db",
        db,
        "start",
        "--listen",
        "127.0.0.1",
        &port_string,
        "--sync-ms",
        "100",
        "--quiet-ms",
        "100",
    ]);
    let stdout = child.stdout.take().expect("daemon stdout");
    let stderr = child.stderr.take().expect("daemon stderr");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read listening line");
    assert!(
        line.starts_with("listening: "),
        "daemon did not announce listening: {line}"
    );
    // Drain stdout/stderr so the daemon never blocks on a full pipe.
    thread::spawn(move || {
        let mut sink = String::new();
        let _ = std::io::Read::read_to_string(&mut reader, &mut sink);
    });
    thread::spawn(move || {
        let mut sink = String::new();
        let _ = std::io::Read::read_to_string(&mut std::io::BufReader::new(stderr), &mut sink);
    });
    let pid = child.id();
    StartedDaemon {
        child: Some(child),
        pid,
    }
}

#[test]
fn cli_stop_terminates_running_daemon_and_releases_lock() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let port = free_port();
    let daemon = start_daemon(&db, port);
    let pid = daemon.pid();

    let lock = lock_path(&db);
    assert!(Path::new(&lock).exists(), "lock should exist while daemon runs");

    let stop_out = assert_success(topo(&["--db", &db, "stop"]));
    assert!(
        stop_out.contains("stopped daemon"),
        "stop output: {stop_out}"
    );
    assert!(
        daemon.wait_clean_exit(Duration::from_secs(10)),
        "daemon did not exit cleanly"
    );
    assert!(
        !process_alive(pid),
        "daemon process {pid} should be gone after wait_clean_exit"
    );
    assert!(
        wait_until(Duration::from_secs(2), || !Path::new(&lock).exists()),
        "lock file should be removed after clean shutdown"
    );

    // A subsequent `start` must succeed without lock contention.
    let next_port = free_port();
    let again = start_daemon(&db, next_port);
    assert!(Path::new(&lock).exists(), "second daemon should re-acquire lock");
    drop(again);
}

#[test]
fn cli_stop_when_no_daemon_running_is_a_clean_no_op() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "idle.db");
    let out = assert_success(topo(&["--db", &db, "stop"]));
    assert!(
        out.contains("no daemon running"),
        "stop output should report no daemon: {out}"
    );
}

#[test]
fn cli_stop_with_stale_lock_file_recovers() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "stale.db");
    let lock = lock_path(&db);
    // Pick a PID we are confident is not running. Picking a deliberately
    // large reserved value avoids colliding with the test runner. If by
    // misfortune a process exists at that pid, /proc will report it and the
    // test will see that path; using a non-numeric token would also force the
    // unreadable-lock branch but we want to exercise the PID-check path.
    std::fs::write(&lock, "999999999\n").expect("write stale lock");

    let out = assert_success(topo(&["--db", &db, "stop"]));
    assert!(
        out.contains("no daemon running"),
        "stop should report no daemon for stale lock: {out}"
    );
    assert!(
        !Path::new(&lock).exists(),
        "stop should remove the stale lock"
    );
}

#[test]
fn cli_reset_deletes_db_and_lock_files() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "victim.db");
    let port = free_port();
    let daemon = start_daemon(&db, port);
    assert_success(topo(&["--db", &db, "stop"]));
    assert!(
        daemon.wait_clean_exit(Duration::from_secs(10)),
        "daemon did not exit cleanly"
    );

    // The DB and side files should still exist; -wal/-shm are conventional
    // SQLite side files. They may have been auto-cleaned by SQLite, but the
    // db file itself must be present.
    assert!(Path::new(&db).exists(), "db should exist before reset");

    let out = assert_success(topo(&["--db", &db, "reset"]));
    assert!(out.contains("reset complete"), "reset output: {out}");

    for suffix in ["", "-wal", "-shm", ".daemon.lock"] {
        let path = format!("{db}{suffix}");
        assert!(
            !Path::new(&path).exists(),
            "reset should delete {path}"
        );
    }

    // A fresh `start` succeeds against the (recreated) empty db.
    let next_port = free_port();
    let again = start_daemon(&db, next_port);
    drop(again);
}

#[test]
fn cli_reset_stops_running_daemon_first() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "live.db");
    let port = free_port();
    let daemon = start_daemon(&db, port);
    let pid = daemon.pid();

    let out = assert_success(topo(&["--db", &db, "reset"]));
    assert!(
        out.contains("stopped daemon"),
        "reset should report stopping daemon: {out}"
    );
    assert!(out.contains("reset complete"), "reset output: {out}");
    assert!(
        daemon.wait_clean_exit(Duration::from_secs(10)),
        "daemon did not exit cleanly after reset"
    );
    assert!(
        !process_alive(pid),
        "daemon process {pid} should be gone after wait_clean_exit"
    );
    for suffix in ["", "-wal", "-shm", ".daemon.lock"] {
        let path = format!("{db}{suffix}");
        assert!(
            !Path::new(&path).exists(),
            "reset should delete {path}"
        );
    }
}

#![allow(dead_code)]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

pub fn topo(db: &str, args: &[&str]) -> Output {
    Command::new(topo_bin())
        .arg("--db")
        .arg(db)
        .args(args)
        .output()
        .expect("run topo")
}

pub fn spawn_topo(db: &str, args: &[&str]) -> Child {
    Command::new(topo_bin())
        .arg("--db")
        .arg(db)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn topo")
}

fn topo_bin() -> &'static Path {
    static TOPO_BIN: OnceLock<PathBuf> = OnceLock::new();
    TOPO_BIN.get_or_init(|| {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let target_dir = manifest_dir.join("target").join("cli-black-box");
        let status = Command::new("cargo")
            .arg("build")
            .arg("--quiet")
            .arg("--bin")
            .arg("topo")
            .arg("--manifest-path")
            .arg(manifest_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir)
            .status()
            .expect("build topo binary");
        assert!(status.success(), "build topo binary");
        target_dir.join("debug").join("topo")
    })
}

pub fn assert_success(output: Output) -> String {
    assert!(
        output.status.success(),
        "command failed\nstdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );
    stdout(&output)
}

pub fn wait_success(child: Child, label: &str) -> String {
    let output = child.wait_with_output().expect("wait for child");
    assert!(
        output.status.success(),
        "{label} failed\nstdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );
    stdout(&output)
}

pub fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

pub fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

pub fn temp_db(dir: &tempfile::TempDir, name: &str) -> String {
    dir.path().join(name).to_string_lossy().to_string()
}

pub fn start_listener(db: &str, port: u16, accept: usize) -> Child {
    spawn_topo(
        db,
        &[
            "sync",
            "--listen",
            "127.0.0.1",
            &port.to_string(),
            "--accept",
            &accept.to_string(),
        ],
    )
}

pub fn invite(db: &str, port: u16) -> String {
    invite_with_addr(db, &format!("127.0.0.1:{port}"))
}

pub fn invite_with_addr(db: &str, addr: &str) -> String {
    let out = assert_success(topo(db, &["invite", "--public-addr", addr]));
    out.lines()
        .find(|line| line.starts_with("topo://invite/"))
        .unwrap_or_else(|| panic!("missing invite link in output:\n{out}"))
        .to_string()
}

pub fn connect_with_retry(db: &str, invite: &str) -> String {
    let mut last = String::new();
    for _ in 0..50 {
        let output = connect_with_invite(db, invite);
        if output.status.success() {
            return stdout(&output);
        }
        last = stderr(&output);
        thread::sleep(Duration::from_millis(50));
    }
    panic!("connect never succeeded: {last}");
}

pub fn connect_with_invite(db: &str, invite: &str) -> Output {
    topo(db, &["connect", invite])
}

pub fn connect_with_invite_after_listener(db: &str, invite: &str) -> Output {
    let mut last = None;
    for _ in 0..50 {
        let output = connect_with_invite(db, invite);
        if output.status.success() || !stderr(&output).contains("open tcp stream") {
            return output;
        }
        last = Some(output);
        thread::sleep(Duration::from_millis(50));
    }
    last.expect("connect attempted")
}

pub fn replace_invite_private_key(link: &str, private_key_hex: &str) -> String {
    replace_invite_part(link, "INVITE_PRIVKEY", private_key_hex)
}

pub fn rewrite_invite_address(link: &str, addr: &str) -> String {
    replace_invite_part(link, "ADDRESS", &addr.replace(':', "_"))
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

pub fn generate(db: &str, count: usize, size: usize) -> String {
    assert_success(topo(
        db,
        &["generate", &count.to_string(), &size.to_string()],
    ))
}

pub fn sync(db: &str) -> String {
    assert_success(topo(db, &["sync"]))
}

pub fn count(db: &str) -> usize {
    let out = assert_success(topo(db, &["count"]));
    line_value(&out, "events")
        .parse()
        .expect("parse event count")
}

pub fn connection_count(db: &str) -> usize {
    let out = assert_success(topo(db, &["count"]));
    line_value(&out, "connections")
        .parse()
        .expect("parse connection count")
}

pub fn connection_event_count(db: &str) -> usize {
    let out = assert_success(topo(db, &["count"]));
    line_value(&out, "connection_events")
        .parse()
        .expect("parse connection event count")
}

pub fn assert_eventually_count(db: &str, expected: usize, timeout: Duration) {
    let start = Instant::now();
    loop {
        let actual = count(db);
        if actual == expected {
            return;
        }
        assert!(
            start.elapsed() < timeout,
            "event count did not reach {expected}; actual={actual}"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

pub fn line_value(output: &str, key: &str) -> String {
    let prefix = format!("{key}: ");
    output
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing `{key}:` in output:\n{output}"))
        .to_string()
}

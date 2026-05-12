#![allow(dead_code)]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

pub fn topo(args: &[&str]) -> Output {
    Command::new(topo_bin())
        .args(args)
        .output()
        .expect("run topo")
}

pub fn spawn_topo(args: &[&str]) -> Child {
    Command::new(topo_bin())
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
        let profile = std::env::var("TOPO_CLI_PROFILE").unwrap_or_else(|_| "release".to_string());
        assert!(
            profile == "release" || profile == "debug",
            "TOPO_CLI_PROFILE must be `release` or `debug`"
        );
        let mut build = Command::new("cargo");
        build
            .arg("build")
            .arg("--quiet")
            .arg("--bin")
            .arg("topo")
            .arg("--manifest-path")
            .arg(manifest_dir.join("Cargo.toml"))
            .arg("--target-dir")
            .arg(&target_dir);
        if profile == "release" {
            build.arg("--release");
        }
        let status = build.status().expect("build topo binary");
        assert!(status.success(), "build topo binary");
        target_dir.join(profile).join("topo")
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
    static NEXT_PORT: OnceLock<AtomicUsize> = OnceLock::new();

    let next_port = NEXT_PORT.get_or_init(|| {
        let offset = (std::process::id() as usize % 100) * 200;
        AtomicUsize::new(41000 + offset)
    });
    for _ in 0..20_000 {
        let port = next_port.fetch_add(1, Ordering::Relaxed);
        if port > 61000 {
            break;
        }
        if TcpListener::bind(("127.0.0.1", port as u16)).is_ok() {
            return port as u16;
        }
    }

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

pub fn temp_db(dir: &tempfile::TempDir, name: &str) -> String {
    dir.path().join(name).to_string_lossy().to_string()
}

pub fn line_value(output: &str, key: &str) -> String {
    let prefix = format!("{key}: ");
    output
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing `{key}:` in output:\n{output}"))
        .to_string()
}

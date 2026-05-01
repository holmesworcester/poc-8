use std::process::{Command, Output};

fn topo(db: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_topo"))
        .arg("--db")
        .arg(db)
        .args(args)
        .output()
        .expect("run topo")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[test]
fn cli_creates_workspace_sends_message_and_views_projection() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("node.db").to_string_lossy().to_string();

    let created = topo(
        &db,
        &["create-workspace", "--workspace-name", "rewrite-lab"],
    );
    assert!(
        created.status.success(),
        "create-workspace failed: {}",
        stderr(&created)
    );
    assert!(stdout(&created).contains("workspace_event_id:"));

    let sent = topo(&db, &["send", "hello from the tiny kernel"]);
    assert!(sent.status.success(), "send failed: {}", stderr(&sent));
    assert!(stdout(&sent).contains("event_id:"));

    let viewed = topo(&db, &["view"]);
    assert!(viewed.status.success(), "view failed: {}", stderr(&viewed));
    let view = stdout(&viewed);
    assert!(view.contains("workspace: rewrite-lab"));
    assert!(view.contains("- hello from the tiny kernel"));
}

#[test]
fn cli_rejects_send_before_workspace() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("node.db").to_string_lossy().to_string();

    let sent = topo(&db, &["send", "too early"]);

    assert!(!sent.status.success());
    assert!(stderr(&sent).contains("no workspace"));
}

#[test]
fn cli_workspace_creation_is_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    let db = tmp.path().join("node.db").to_string_lossy().to_string();

    let first = topo(&db, &["create-workspace", "--workspace-name", "same"]);
    let second = topo(&db, &["create-workspace", "--workspace-name", "same"]);
    let status = topo(&db, &["status"]);

    assert!(first.status.success(), "first failed: {}", stderr(&first));
    assert!(
        second.status.success(),
        "second failed: {}",
        stderr(&second)
    );
    assert!(
        status.status.success(),
        "status failed: {}",
        stderr(&status)
    );
    assert!(stdout(&status).contains("events: 1"));
}

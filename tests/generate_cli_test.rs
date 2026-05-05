mod cli_harness;

use cli_harness::*;

#[test]
fn generate_cli_uses_real_store_and_reports_applied_events() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "generate.db");
    let workspace_id = create_workspace(&db);

    let generated = assert_success(topo(&["--db", &db, "generate", &workspace_id, "7", "128"]));
    assert!(generated.contains("generated_events: 7"), "{generated}");
    assert!(generated.contains("applied_events: 7"), "{generated}");
    assert!(generated.contains("event_size_bytes: 128"), "{generated}");
    assert!(generated.contains("first_timestamp: 1"), "{generated}");
    assert!(generated.contains("last_timestamp: 7"), "{generated}");

    let content = assert_success(topo(&["--db", &db, "content-count", &workspace_id]));
    assert_eq!(line_value(&content, "content_events"), "7");
    assert_eq!(line_value(&content, "content_payload_bytes"), "896");

    let status = assert_success(topo(&["--db", &db, "count"]));
    assert_eq!(line_value(&status, "events"), "14");
    assert_eq!(line_value(&status, "applied_events"), "14");
    assert_eq!(line_value(&status, "ready_events"), "0");
    assert_eq!(line_value(&status, "blocked_events"), "0");
}

fn create_workspace(db: &str) -> String {
    let out = assert_success(topo(&[
        "--db",
        db,
        "create-workspace",
        "Generate",
        "--username",
        "alice",
        "--devicename",
        "alice-laptop",
    ]));
    line_value(&out, "workspace_id")
}

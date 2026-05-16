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
    // create-workspace emits 8 events (workspace + initial setting + bootstrap admin
    // + user invite + user + device invite + endpoint_shared + creator admin), and
    // `generate` adds 7 messages on top.
    assert_eq!(line_value(&status, "events"), "15");
    assert_eq!(line_value(&status, "applied_events"), "15");
}

#[test]
fn clock_cli_sets_logical_timestamp_lower_bound_for_generated_events() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "clocked-generate.db");
    let workspace_id = create_workspace(&db);

    let set = assert_success(topo(&["--db", &db, "clock", "set", "5000"]));
    assert_eq!(line_value(&set, "logical_time"), "5000");
    assert_eq!(line_value(&set, "next_timestamp"), "5000");

    let generated = assert_success(topo(&["--db", &db, "generate", &workspace_id, "3", "32"]));
    assert_eq!(line_value(&generated, "first_timestamp"), "5000");
    assert_eq!(line_value(&generated, "last_timestamp"), "5002");

    let advanced = assert_success(topo(&["--db", &db, "clock", "advance", "100"]));
    assert_eq!(line_value(&advanced, "logical_time"), "5100");
    assert_eq!(line_value(&advanced, "max_event_timestamp"), "5002");
    assert_eq!(line_value(&advanced, "next_timestamp"), "5100");

    let generated = assert_success(topo(&["--db", &db, "generate", &workspace_id, "1", "32"]));
    assert_eq!(line_value(&generated, "first_timestamp"), "5100");
    assert_eq!(line_value(&generated, "last_timestamp"), "5100");

    let cleared = assert_success(topo(&["--db", &db, "clock", "clear"]));
    assert_eq!(line_value(&cleared, "logical_time"), "unset");
    assert_eq!(line_value(&cleared, "next_timestamp"), "5101");
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

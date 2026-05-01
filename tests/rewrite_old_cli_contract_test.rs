mod cli_harness;

use cli_harness::*;

#[test]
fn old_cli_send_and_messages_contract() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "messages.db");

    create_workspace(&db, "chat");
    send_message(&db, "First message");
    send_message(&db, "Second message");

    let messages = assert_success(topo(&db, &["messages"]));
    assert!(messages.contains("MESSAGES (2):"));
    assert!(messages.contains("1."));
    assert!(messages.contains("First message"));
    assert!(messages.contains("Second message"));
}

#[test]
fn old_cli_generate_and_file_contracts() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "files.db");
    let path = tmp.path().join("sample.bin");
    let bytes = b"deterministic file payload";
    std::fs::write(&path, bytes).unwrap();

    create_workspace(&db, "files");

    let generated = assert_success(topo(&db, &["generate", "--count", "3", "--prefix", "bulk"]));
    assert!(generated.contains("generated_messages: 3"));
    let messages = assert_success(topo(&db, &["messages"]));
    assert!(messages.contains("MESSAGES (3):"));
    assert!(messages.contains("bulk 000000"));
    assert!(messages.contains("bulk 000002"));

    let sent_file = assert_success(topo(&db, &["send-file", path.to_str().unwrap()]));
    let expected_hash = blake3::hash(bytes).to_hex().to_string();
    assert!(sent_file.contains("file: sample.bin"));
    assert!(sent_file.contains(&expected_hash));

    let files = assert_success(topo(&db, &["files"]));
    assert!(files.contains("FILES (1):"));
    assert!(files.contains("sample.bin"));
    assert!(files.contains("26 bytes"));
    assert!(files.contains(&expected_hash));

    let out_path = tmp.path().join("roundtrip.bin");
    let saved = assert_success(topo(
        &db,
        &["save-file", "1", "--out", out_path.to_str().unwrap()],
    ));
    assert!(saved.contains("file: sample.bin"));
    assert_eq!(std::fs::read(out_path).unwrap(), bytes);

    let file_ids = assert_success(topo(
        &db,
        &["event", "list", "--type", "file", "--ids-only"],
    ));
    assert!(file_ids.contains("EVENT IDS (1):"));
}

#[test]
fn old_cli_workspaces_contract() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "workspaces.db");

    create_workspace(&db, "alpha");
    create_workspace(&db, "beta");

    let workspaces = assert_success(topo(&db, &["workspaces"]));
    assert!(workspaces.contains("WORKSPACES (2):"));
    assert!(workspaces.contains("alpha"));
    assert!(workspaces.contains("beta"));
}

#[test]
fn old_cli_event_list_and_tree_contracts() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "events.db");

    let empty_tree = assert_success(topo(&db, &["event", "tree"]));
    assert!(empty_tree.contains("no events"));
    let empty_list = assert_success(topo(&db, &["event", "list"]));
    assert!(empty_list.contains("no events"));

    create_workspace(&db, "events");
    send_message(&db, "event list should see me");

    let tree = assert_success(topo(&db, &["event", "tree"]));
    assert!(tree.contains("workspace"));
    assert!(tree.contains("message"));
    assert!(tree.contains("├──") || tree.contains("└──"));
    assert!(tree.contains("root"));
    assert!(tree.contains("events."));

    let list = assert_success(topo(&db, &["event", "list"]));
    assert!(list.contains("workspace"));
    assert!(list.contains("message"));
    assert!(list.contains("deps:"));
    assert!(list.contains("events. Sorted by insertion order."));

    let ids = assert_success(topo(&db, &["event", "list", "--ids-only"]));
    assert!(ids.contains("EVENT IDS (2):"));

    let message_ids = assert_success(topo(
        &db,
        &["event", "list", "--type", "message", "--ids-only"],
    ));
    assert!(message_ids.contains("EVENT IDS (1):"));
}

#[test]
fn old_cli_event_show_contract() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "show.db");

    create_workspace(&db, "show");
    let ids = assert_success(topo(
        &db,
        &["event", "list", "--type", "workspace", "--ids-only"],
    ));
    let id = ids
        .lines()
        .find(|line| line.len() == 64)
        .expect("workspace id");
    let prefix = &id[..12];

    let show = assert_success(topo(&db, &["event", "show", prefix]));
    assert!(show.contains("workspace"));
    assert!(show.contains(id));

    let missing = assert_success(topo(&db, &["event", "show", "ffffffffffff"]));
    assert!(missing.contains("No events matching that prefix."));
}

#[test]
fn old_cli_reaction_by_message_number_contract() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "react.db");

    create_workspace(&db, "react");
    send_message(&db, "first msg");
    send_message(&db, "second msg");

    let reacted = assert_success(topo(&db, &["react", "thumbsup", "1"]));
    assert!(reacted.contains("Reacted"));
    assert_success(topo(&db, &["react", "heart", "#2"]));

    let messages = assert_success(topo(&db, &["messages"]));
    assert!(messages.contains("first msg"));
    assert!(messages.contains("thumbsup"));
    assert!(messages.contains("second msg"));
    assert!(messages.contains("heart"));

    let err = assert_failure(topo(&db, &["react", "sad", "99"]));
    assert!(err.contains("invalid message number"));
}

#[test]
fn old_cli_delete_message_hides_message_and_reaction() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "delete.db");

    create_workspace(&db, "delete");
    send_message(&db, "purge me");
    assert_success(topo(&db, &["react", "fire", "1"]));

    let deleted = assert_success(topo(&db, &["delete-message", "1"]));
    assert!(deleted.contains("Deleted"));

    let messages = assert_success(topo(&db, &["messages"]));
    assert!(messages.contains("MESSAGES (0):"));
    assert!(!messages.contains("purge me"));
    assert!(!messages.contains("fire"));

    let deletion_ids = assert_success(topo(
        &db,
        &["event", "list", "--type", "message_deletion", "--ids-only"],
    ));
    assert!(deletion_ids.contains("EVENT IDS (1):"));
}

#[test]
fn cli_completion_mentions_real_network_commands() {
    let bash = assert_success(topo_no_db(&["completions", "bash"]));
    assert!(bash.contains("topo"));
    assert!(bash.contains("send-pending"));
    assert!(bash.contains("receive"));

    let zsh = assert_success(topo_no_db(&["completions", "zsh"]));
    assert!(zsh.contains("topo"));
    assert!(zsh.contains("queue-event"));
}

#[test]
fn rewrite_cli_keeps_databases_isolated_until_sync() {
    let tmp = tempfile::tempdir().unwrap();
    let alice_db = temp_db(&tmp, "alice.db");
    let bob_db = temp_db(&tmp, "bob.db");

    create_workspace(&alice_db, "alice-only");
    create_workspace(&bob_db, "bob-only");
    send_message(&alice_db, "alice private");
    send_message(&bob_db, "bob private");

    let alice_before = assert_success(topo(&alice_db, &["view"]));
    let bob_before = assert_success(topo(&bob_db, &["view"]));
    assert!(alice_before.contains("alice private"));
    assert!(!alice_before.contains("bob private"));
    assert!(bob_before.contains("bob private"));
    assert!(!bob_before.contains("alice private"));
}

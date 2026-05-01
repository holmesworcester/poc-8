mod cli_harness;

use cli_harness::*;

const ALICE_TO_BOB: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const BOB_TO_ALICE: &str = "2222222222222222222222222222222222222222222222222222222222222222";

#[test]
fn cli_creates_workspace_sends_message_and_views_projection() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "node.db");

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
    let db = temp_db(&tmp, "node.db");

    let sent = topo(&db, &["send", "too early"]);

    assert!(!sent.status.success());
    assert!(stderr(&sent).contains("no workspace"));
}

#[test]
fn cli_workspace_creation_is_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "node.db");

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

#[test]
fn two_cli_nodes_exchange_messages_over_tcp() {
    let tmp = tempfile::tempdir().unwrap();
    let alice_db = temp_db(&tmp, "alice.db");
    let bob_db = temp_db(&tmp, "bob.db");

    let created = create_workspace(&alice_db, "two-people");
    let workspace_event_id = line_value(&created, "workspace_event_id");
    let alice_msg = send_message(&alice_db, "alice: hi bob");
    let alice_msg_id = line_value(&alice_msg, "event_id");

    queue_event(&alice_db, &workspace_event_id, ALICE_TO_BOB);
    queue_event(&alice_db, &alice_msg_id, ALICE_TO_BOB);

    let bob_addr = free_addr();
    let bob_receiver = spawn_receive(&bob_db, &bob_addr, 2);
    let sent = send_pending_with_retry(&alice_db, ALICE_TO_BOB, &bob_addr);
    assert!(sent.contains("sent_events: 2"));
    let bob_receive = bob_receiver.wait_with_output().unwrap();
    assert!(
        bob_receive.status.success(),
        "bob receive failed: stdout={} stderr={}",
        stdout(&bob_receive),
        stderr(&bob_receive)
    );
    assert!(stdout(&topo(&bob_db, &["view"])).contains("- alice: hi bob"));

    let bob_msg = send_message(&bob_db, "bob: hi alice");
    let bob_msg_id = line_value(&bob_msg, "event_id");
    queue_event(&bob_db, &bob_msg_id, BOB_TO_ALICE);

    let alice_addr = free_addr();
    let alice_receiver = spawn_receive(&alice_db, &alice_addr, 1);
    let sent = send_pending_with_retry(&bob_db, BOB_TO_ALICE, &alice_addr);
    assert!(sent.contains("sent_events: 1"));
    let alice_receive = alice_receiver.wait_with_output().unwrap();
    assert!(
        alice_receive.status.success(),
        "alice receive failed: stdout={} stderr={}",
        stdout(&alice_receive),
        stderr(&alice_receive)
    );

    let alice_view = stdout(&topo(&alice_db, &["view"]));
    assert!(alice_view.contains("- alice: hi bob"));
    assert!(alice_view.contains("- bob: hi alice"));

    let bob_view = stdout(&topo(&bob_db, &["view"]));
    assert!(bob_view.contains("- alice: hi bob"));
    assert!(bob_view.contains("- bob: hi alice"));
}

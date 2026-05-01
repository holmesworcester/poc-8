mod cli_harness;

use cli_harness::*;

const ALICE_TO_BOB: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const BOB_TO_ALICE: &str = "4444444444444444444444444444444444444444444444444444444444444444";

#[test]
fn account_creation_is_a_cli_event_flow() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");

    create_workspace(&db, "accounts");
    let created = create_account(&db, "alice", "laptop");
    assert!(created.contains("account: alice"));
    assert!(created.contains("device: laptop"));

    let accounts = assert_success(topo(&db, &["accounts"]));
    assert!(accounts.contains("ACCOUNTS (1):"));
    assert!(accounts.contains("alice @ laptop"));

    let account_events = assert_success(topo(
        &db,
        &["event", "list", "--type", "account", "--ids-only"],
    ));
    assert!(account_events.contains("EVENT IDS (1):"));
}

#[test]
fn invite_joining_unblocks_over_tcp_and_then_round_trips() {
    let tmp = tempfile::tempdir().unwrap();
    let alice_db = temp_db(&tmp, "alice.db");
    let bob_db = temp_db(&tmp, "bob.db");

    let workspace = create_workspace(&alice_db, "joined");
    create_account(&alice_db, "alice", "laptop");
    let invite = create_invite(&alice_db);
    let workspace_event_id = line_value(&workspace, "workspace_event_id");

    let accepted = accept_invite(&bob_db, &invite, "bob", "phone");
    assert!(accepted.contains("accepted_invite:"));
    assert!(accepted.contains("status: blocked_until_invite_sync"));
    let bob_accept_id = line_value(&accepted, "event_id");

    let bob_accounts_before = assert_success(topo(&bob_db, &["accounts"]));
    assert!(bob_accounts_before.contains("ACCOUNTS (0):"));

    queue_event(&alice_db, &workspace_event_id, ALICE_TO_BOB);
    queue_events(&alice_db, ALICE_TO_BOB, Some("account"));
    queue_events(&alice_db, ALICE_TO_BOB, Some("invite"));
    let bob_addr = free_addr();
    let bob_receiver = spawn_receive(&bob_db, &bob_addr, 3);
    let sent = send_pending_with_retry(&alice_db, ALICE_TO_BOB, &bob_addr);
    assert!(sent.contains("sent_events: 3"));
    let received = bob_receiver.wait_with_output().unwrap();
    assert!(
        received.status.success(),
        "bob receive failed: stdout={} stderr={}",
        stdout(&received),
        stderr(&received)
    );

    let bob_accounts = assert_success(topo(&bob_db, &["accounts"]));
    assert!(bob_accounts.contains("alice @ laptop"));
    assert!(bob_accounts.contains("bob @ phone"));

    send_message(&bob_db, "bob joined from an invite");
    queue_event(&bob_db, &bob_accept_id, BOB_TO_ALICE);
    queue_events(&bob_db, BOB_TO_ALICE, Some("message"));

    let alice_addr = free_addr();
    let alice_receiver = spawn_receive(&alice_db, &alice_addr, 2);
    let sent = send_pending_with_retry(&bob_db, BOB_TO_ALICE, &alice_addr);
    assert!(sent.contains("sent_events: 2"));
    let received = alice_receiver.wait_with_output().unwrap();
    assert!(
        received.status.success(),
        "alice receive failed: stdout={} stderr={}",
        stdout(&received),
        stderr(&received)
    );

    let alice_messages = assert_success(topo(&alice_db, &["messages"]));
    assert!(alice_messages.contains("bob joined from an invite"));

    let alice_accounts = assert_success(topo(&alice_db, &["accounts"]));
    assert!(alice_accounts.contains("alice @ laptop"));
    assert!(alice_accounts.contains("bob @ phone"));
}

#[test]
fn peer_can_send_file_back_over_tcp() {
    let tmp = tempfile::tempdir().unwrap();
    let alice_db = temp_db(&tmp, "alice.db");
    let bob_db = temp_db(&tmp, "bob.db");
    let input = tmp.path().join("joined-file.bin");
    let output = tmp.path().join("alice-copy.bin");
    let bytes = (0..8192)
        .map(|idx| ((idx * 19 + 5) % 251) as u8)
        .collect::<Vec<_>>();
    let expected_hash = blake3::hash(&bytes).to_hex().to_string();
    std::fs::write(&input, &bytes).unwrap();

    let workspace = create_workspace(&alice_db, "files");
    let workspace_event_id = line_value(&workspace, "workspace_event_id");
    queue_event(&alice_db, &workspace_event_id, ALICE_TO_BOB);

    let bob_addr = free_addr();
    let bob_receiver = spawn_receive(&bob_db, &bob_addr, 1);
    let sent = send_pending_with_retry(&alice_db, ALICE_TO_BOB, &bob_addr);
    assert!(sent.contains("sent_events: 1"));
    let received = bob_receiver.wait_with_output().unwrap();
    assert!(
        received.status.success(),
        "bob receive failed: stdout={} stderr={}",
        stdout(&received),
        stderr(&received)
    );

    let sent = assert_success(topo(&bob_db, &["send-file", input.to_str().unwrap()]));
    assert!(sent.contains(&expected_hash));
    let file_event_id = line_value(&sent, "event_id");
    queue_event(&bob_db, &file_event_id, BOB_TO_ALICE);

    let alice_addr = free_addr();
    let alice_receiver = spawn_receive(&alice_db, &alice_addr, 1);
    let sent = send_pending_with_retry(&bob_db, BOB_TO_ALICE, &alice_addr);
    assert!(sent.contains("sent_events: 1"));
    let received = alice_receiver.wait_with_output().unwrap();
    assert!(
        received.status.success(),
        "alice receive failed: stdout={} stderr={}",
        stdout(&received),
        stderr(&received)
    );

    let files = assert_success(topo(&alice_db, &["files"]));
    assert!(files.contains("joined-file.bin"));
    assert!(files.contains("8192 bytes"));
    assert!(files.contains(&expected_hash));

    let saved = assert_success(topo(
        &alice_db,
        &["save-file", "1", "--out", output.to_str().unwrap()],
    ));
    assert!(saved.contains("file: joined-file.bin"));
    assert_eq!(std::fs::read(output).unwrap(), bytes);
}

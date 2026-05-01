mod cli_harness;

use cli_harness::*;

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
fn invite_joining_unblocks_after_sync_and_then_messages_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let alice_db = temp_db(&tmp, "alice.db");
    let bob_db = temp_db(&tmp, "bob.db");

    create_workspace(&alice_db, "joined");
    create_account(&alice_db, "alice", "laptop");
    let invite = create_invite(&alice_db);

    let accepted = accept_invite(&bob_db, &invite, "bob", "phone");
    assert!(accepted.contains("accepted_invite:"));
    assert!(accepted.contains("status: blocked_until_invite_sync"));

    let bob_accounts_before = assert_success(topo(&bob_db, &["accounts"]));
    assert!(bob_accounts_before.contains("ACCOUNTS (0):"));

    sync_from(&bob_db, &alice_db);
    let bob_accounts = assert_success(topo(&bob_db, &["accounts"]));
    assert!(bob_accounts.contains("alice @ laptop"));
    assert!(bob_accounts.contains("bob @ phone"));

    send_message(&bob_db, "bob joined from an invite");
    sync_from(&alice_db, &bob_db);

    let alice_messages = assert_success(topo(&alice_db, &["messages"]));
    assert!(alice_messages.contains("bob joined from an invite"));

    let alice_accounts = assert_success(topo(&alice_db, &["accounts"]));
    assert!(alice_accounts.contains("alice @ laptop"));
    assert!(alice_accounts.contains("bob @ phone"));
}

#[test]
fn invited_peer_can_sync_files_back_to_inviter() {
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

    create_workspace(&alice_db, "files");
    let invite = create_invite(&alice_db);
    accept_invite(&bob_db, &invite, "bob", "phone");
    sync_from(&bob_db, &alice_db);

    let sent = assert_success(topo(&bob_db, &["send-file", input.to_str().unwrap()]));
    assert!(sent.contains(&expected_hash));
    sync_from(&alice_db, &bob_db);

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

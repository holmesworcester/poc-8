mod cli_harness;

use cli_harness::*;
use std::process::Output;

const A_TO_B: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B_TO_A: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const A_TO_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const B_TO_C: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const C_TO_A: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const C_TO_B: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

fn count_value(output: &str, key: &str) -> usize {
    line_value(output, key)
        .parse::<usize>()
        .unwrap_or_else(|err| panic!("parse {key} count from {output:?}: {err}"))
}

fn wait_success(child: std::process::Child, label: &str) -> Output {
    let output = child
        .wait_with_output()
        .unwrap_or_else(|err| panic!("wait for {label}: {err}"));
    assert!(
        output.status.success(),
        "{label} failed: stdout={} stderr={}",
        stdout(&output),
        stderr(&output)
    );
    output
}

fn transfer_queued(src_db: &str, dst_db: &str, connection_id: &str, queued: usize, label: &str) {
    if queued == 0 {
        return;
    }

    let addr = free_addr();
    let receiver = spawn_receive(dst_db, &addr, queued);
    let sent = send_pending_with_retry(src_db, connection_id, &addr);
    assert!(
        sent.contains(&format!("sent_events: {queued}")),
        "{label} send count mismatch: {sent}"
    );
    let received = wait_success(receiver, label);
    let receive_out = stdout(&received);
    assert!(
        receive_out.contains(&format!("received_events: {queued}")),
        "{label} receive count mismatch: {receive_out}"
    );
}

fn transfer_all(src_db: &str, dst_db: &str, connection_id: &str, label: &str) {
    let queued = queue_events(src_db, connection_id, None);
    let count = count_value(&queued, "queued_events");
    transfer_queued(src_db, dst_db, connection_id, count, label);
}

fn transfer_type(src_db: &str, dst_db: &str, connection_id: &str, type_name: &str, label: &str) {
    let queued = queue_events(src_db, connection_id, Some(type_name));
    let count = count_value(&queued, "queued_events");
    transfer_queued(src_db, dst_db, connection_id, count, label);
}

fn transfer_event(src_db: &str, dst_db: &str, connection_id: &str, event_id: &str, label: &str) {
    let queued = queue_event(src_db, event_id, connection_id);
    let inserted = count_value(&queued, "inserted");
    transfer_queued(src_db, dst_db, connection_id, inserted, label);
}

#[test]
fn poc7_invite_bootstrap_catches_up_existing_history_and_allows_reply() {
    let tmp = tempfile::tempdir().unwrap();
    let alice_db = temp_db(&tmp, "alice.db");
    let bob_db = temp_db(&tmp, "bob.db");

    create_workspace(&alice_db, "bootstrap-catchup");
    create_account(&alice_db, "alice", "laptop");
    send_message(&alice_db, "bootstrap-before-invite");
    let invite = create_invite(&alice_db);

    let accepted = accept_invite(&bob_db, &invite, "bob", "phone");
    assert!(accepted.contains("status: blocked_until_invite_sync"));

    transfer_all(&alice_db, &bob_db, A_TO_B, "alice history to bob");

    let bob_messages = assert_success(topo(&bob_db, &["messages"]));
    assert!(bob_messages.contains("bootstrap-before-invite"));
    let bob_accounts = assert_success(topo(&bob_db, &["accounts"]));
    assert!(bob_accounts.contains("alice @ laptop"));
    assert!(bob_accounts.contains("bob @ phone"));

    send_message(&bob_db, "reply-after-bootstrap-catchup");
    transfer_all(&bob_db, &alice_db, B_TO_A, "bob reply to alice");

    let alice_messages = assert_success(topo(&alice_db, &["messages"]));
    assert!(alice_messages.contains("bootstrap-before-invite"));
    assert!(alice_messages.contains("reply-after-bootstrap-catchup"));
}

#[test]
fn poc7_reusable_invite_can_join_multiple_peers_and_converge_messages() {
    let tmp = tempfile::tempdir().unwrap();
    let alice_db = temp_db(&tmp, "alice.db");
    let bob_db = temp_db(&tmp, "bob.db");
    let carol_db = temp_db(&tmp, "carol.db");

    create_workspace(&alice_db, "reusable-invite");
    let invite = create_invite(&alice_db);

    assert!(accept_invite(&bob_db, &invite, "bob", "phone").contains("accepted_invite:"));
    assert!(accept_invite(&carol_db, &invite, "carol", "tablet").contains("accepted_invite:"));

    transfer_all(&alice_db, &bob_db, A_TO_B, "alice invite to bob");
    transfer_all(&alice_db, &carol_db, A_TO_C, "alice invite to carol");

    send_message(&bob_db, "bob-through-reused-invite");
    transfer_all(&bob_db, &alice_db, B_TO_A, "bob to alice");
    transfer_all(&bob_db, &carol_db, B_TO_C, "bob to carol");

    send_message(&carol_db, "carol-through-reused-invite");
    transfer_all(&carol_db, &alice_db, C_TO_A, "carol to alice");
    transfer_all(&carol_db, &bob_db, C_TO_B, "carol to bob");

    for db in [&alice_db, &bob_db, &carol_db] {
        let messages = assert_success(topo(db, &["messages"]));
        assert!(messages.contains("bob-through-reused-invite"));
        assert!(messages.contains("carol-through-reused-invite"));
    }
}

#[test]
fn poc7_reaction_sync_waits_for_message_dependency() {
    let tmp = tempfile::tempdir().unwrap();
    let alice_db = temp_db(&tmp, "alice.db");
    let bob_db = temp_db(&tmp, "bob.db");

    create_workspace(&alice_db, "reaction-sync");
    transfer_type(&alice_db, &bob_db, A_TO_B, "workspace", "workspace to bob");

    let message = send_message(&alice_db, "react-over-the-wire");
    let message_id = line_value(&message, "event_id");
    let reaction = assert_success(topo(&alice_db, &["react", "fire", "1"]));
    let reaction_id = line_value(&reaction, "event_id");

    transfer_event(&alice_db, &bob_db, A_TO_B, &reaction_id, "reaction before message");
    let before_message = assert_success(topo(&bob_db, &["messages"]));
    assert!(!before_message.contains("react-over-the-wire"));

    transfer_event(&alice_db, &bob_db, A_TO_B, &message_id, "message after reaction");
    let after_message = assert_success(topo(&bob_db, &["messages"]));
    assert!(after_message.contains("react-over-the-wire"));
    assert!(after_message.contains("fire"));
}

#[test]
fn poc7_delete_message_converges_over_network() {
    let tmp = tempfile::tempdir().unwrap();
    let alice_db = temp_db(&tmp, "alice.db");
    let bob_db = temp_db(&tmp, "bob.db");

    create_workspace(&alice_db, "delete-sync");
    send_message(&alice_db, "delete-me-over-network");
    transfer_all(&alice_db, &bob_db, A_TO_B, "initial message to bob");
    assert!(assert_success(topo(&bob_db, &["messages"])).contains("delete-me-over-network"));

    let deleted = assert_success(topo(&alice_db, &["delete-message", "1"]));
    let deletion_id = line_value(&deleted, "event_id");
    transfer_event(&alice_db, &bob_db, A_TO_B, &deletion_id, "delete to bob");

    let bob_messages = assert_success(topo(&bob_db, &["messages"]));
    assert!(bob_messages.contains("MESSAGES (0):"));
    assert!(!bob_messages.contains("delete-me-over-network"));

    let deletion_events = assert_success(topo(
        &bob_db,
        &["event", "list", "--type", "message_deletion", "--ids-only"],
    ));
    assert!(deletion_events.contains("EVENT IDS (1):"));
}

#[test]
fn poc7_independent_workspace_pairs_remain_isolated_after_tcp_sync() {
    let tmp = tempfile::tempdir().unwrap();
    let alpha_a = temp_db(&tmp, "alpha-a.db");
    let alpha_b = temp_db(&tmp, "alpha-b.db");
    let beta_a = temp_db(&tmp, "beta-a.db");
    let beta_b = temp_db(&tmp, "beta-b.db");

    create_workspace(&alpha_a, "alpha");
    create_workspace(&beta_a, "beta");
    send_message(&alpha_a, "alpha-only-message");
    send_message(&beta_a, "beta-only-message");

    transfer_all(&alpha_a, &alpha_b, A_TO_B, "alpha pair sync");
    transfer_all(&beta_a, &beta_b, C_TO_A, "beta pair sync");

    let alpha_messages = assert_success(topo(&alpha_b, &["messages"]));
    assert!(alpha_messages.contains("alpha-only-message"));
    assert!(!alpha_messages.contains("beta-only-message"));

    let beta_messages = assert_success(topo(&beta_b, &["messages"]));
    assert!(beta_messages.contains("beta-only-message"));
    assert!(!beta_messages.contains("alpha-only-message"));
}

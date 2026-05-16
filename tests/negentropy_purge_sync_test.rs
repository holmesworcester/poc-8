//! CLI tests for sync-visible expiry and purge behavior.
//!
//! Exercises the deferred sync-vs-purge interaction noted in
//! `tests/disappearing_messages_cli_test.rs::cli_disappearing_messages_two_peer_convergence`:
//!
//!   * Two peers that purge the same set of admitted shared event ids
//!     reach byte-identical negentropy `root_fingerprint` values.
//!   * Expired content disappears locally and is not reintroduced by
//!     follow-up sync rounds.
//!
//! All assertions go through public CLI surface — `sync-status`,
//! `keys`, `content-count`, and `messages`.

mod cli_harness;

use std::io::{BufRead, BufReader};
use std::process::Child;
use std::thread;
use std::time::Duration;

use cli_harness::*;

// ---------------------------------------------------------------------------
// Test 1: single-peer expiry updates the sync summary after expired
// messages disappear.
// ---------------------------------------------------------------------------

#[test]
fn cli_negentropy_settles_root_after_expiry() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let alice_port = free_port();

    let workspace_id = create_workspace_with_ttl(&alice, "DrainerSolo", "alice", "alice-laptop", 1);
    assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));

    // Pin the clock and author three messages so the workspace has a
    // non-trivial pre-expiry `root_fingerprint`.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    for body in ["hello-1", "hello-2", "hello-3"] {
        assert_success(topo(&["--db", &alice, "send", &workspace_id, body]));
    }
    assert_eq!(message_lines(&alice, &workspace_id).len(), 3);

    let pre = sync_status(&alice);
    let pre_count: u64 = line_value(&pre, "indexed_events").parse().expect("count");
    assert!(
        pre_count >= 3,
        "indexed events must include at least the three authored messages:\n{pre}"
    );
    let pre_fingerprint = line_value(&pre, "root_fingerprint");

    // Spawn the daemon, advance past expiry, and wait for CLI-visible
    // message removal.
    let alice_daemon = spawn_daemon(&alice, alice_port);
    assert_success(topo(&["--db", &alice, "clock", "set", "6120000"]));
    wait_for_leaf_count(&alice, &workspace_id, "0");
    wait_for_content_count(&alice, &workspace_id, "0");

    // The root_fingerprint should differ from the pre-expiry fingerprint
    // because the expired messages no longer contribute to the sync summary.
    let post = wait_for_root_fingerprint_to_change(&alice, &pre_fingerprint);
    let post_fingerprint = line_value(&post, "root_fingerprint");
    assert_ne!(
        pre_fingerprint, post_fingerprint,
        "root fingerprint must change after expired ids disappear:\n\
         pre={pre_fingerprint}\npost={post_fingerprint}"
    );
    let post_count: u64 = line_value(&post, "root_count").parse().expect("count");
    assert!(
        post_count <= pre_count.saturating_sub(3),
        "root count must drop by at least the three purged messages: \
         pre={pre_count}, post={post_count}"
    );

    drop(alice_daemon);
}

// ---------------------------------------------------------------------------
// Test 2: two peers that purge the same admitted set reach byte-identical
// negentropy root_fingerprint values, and a sync round between them after
// purge does not redeliver any of the purged ids (asserted indirectly via
// content_count remaining zero on both peers).
// ---------------------------------------------------------------------------

#[test]
fn cli_negentropy_two_peers_converge_on_root_after_synchronized_purge() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let alice_port = free_port();
    let bob_port = free_port();

    let workspace_id = create_workspace_with_ttl(&alice, "DrainerPair", "alice", "alice-laptop", 1);
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    join_workspace(&alice, &bob, &workspace_id, alice_port, "bob", "bob-phone");

    let alice_recipient = assert_success(topo(&["--db", &alice, "key-recipient", &workspace_id]));
    let alice_recipient_id = line_value(&alice_recipient, "recipient_key_id");
    let bob_recipient = assert_success(topo(&["--db", &bob, "key-recipient", &workspace_id]));
    let bob_recipient_id = line_value(&bob_recipient, "recipient_key_id");

    let frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");

    let _ = key_wrap_with_retry(
        &alice,
        &workspace_id,
        &removal_frontier_id,
        &bob_recipient_id,
    );
    let _ = key_wrap_with_retry(
        &alice,
        &workspace_id,
        &removal_frontier_id,
        &alice_recipient_id,
    );
    let _ = wait_for_key_derive(&bob, "1");

    // Pin both clocks to the same minute and have alice author messages
    // that bob will receive via sync.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &bob, "clock", "set", "6000000"]));
    for body in ["secret-a", "secret-b", "secret-c"] {
        assert_success(topo(&["--db", &alice, "send", &workspace_id, body]));
    }
    for body in ["secret-a", "secret-b", "secret-c"] {
        wait_for_message_text(&alice, &workspace_id, &format!("alice: {body}"));
        wait_for_message_text(&bob, &workspace_id, &format!("alice: {body}"));
    }
    assert_eq!(message_lines(&alice, &workspace_id).len(), 3);
    assert_eq!(message_lines(&bob, &workspace_id).len(), 3);

    // Pre-expiry: both peers must have byte-identical root_fingerprints.
    let pre_alice = wait_for_root_fingerprint_to_match(&alice, &bob);
    let pre_bob = sync_status(&bob);
    assert_eq!(
        line_value(&pre_alice, "root_fingerprint"),
        line_value(&pre_bob, "root_fingerprint"),
        "root fingerprints must converge cross-peer pre-expiry:\nalice={pre_alice}\nbob={pre_bob}"
    );

    // Trigger expiry on both peers in lockstep.
    assert_success(topo(&["--db", &alice, "clock", "set", "6120000"]));
    assert_success(topo(&["--db", &bob, "clock", "set", "6120000"]));
    wait_for_leaf_count(&alice, &workspace_id, "0");
    wait_for_leaf_count(&bob, &workspace_id, "0");
    wait_for_content_count(&alice, &workspace_id, "0");
    wait_for_content_count(&bob, &workspace_id, "0");
    let pre_alice_fp = line_value(&pre_alice, "root_fingerprint");
    wait_for_root_fingerprint_to_change(&alice, &pre_alice_fp);
    wait_for_root_fingerprint_to_change(&bob, &pre_alice_fp);

    // Load-bearing assertion: cross-peer root_fingerprint converges to
    // the SAME value after both peers have purged the same id set. This
    // is the determinism property the sync summary must uphold.
    let post_alice = wait_for_root_fingerprint_to_match(&alice, &bob);
    let post_bob = sync_status(&bob);
    assert_eq!(
        line_value(&post_alice, "root_fingerprint"),
        line_value(&post_bob, "root_fingerprint"),
        "root fingerprints must converge cross-peer post-purge:\nalice={post_alice}\nbob={post_bob}"
    );
    assert_eq!(
        line_value(&post_alice, "root_count"),
        line_value(&post_bob, "root_count"),
        "root count must converge cross-peer post-purge"
    );

    // The post-purge fingerprint must differ from the pre-purge value
    // so this is not just a no-op sync round.
    assert_ne!(
        line_value(&pre_alice, "root_fingerprint"),
        line_value(&post_alice, "root_fingerprint"),
        "root fingerprint must change after purge"
    );

    // Sync round after purge: neither peer should re-request the
    // purged ids. The strongest CLI-visible signal is that
    // content_count stays at 0 on both peers across a follow-up sync
    // round, which we drive by waiting a short time and re-checking.
    thread::sleep(Duration::from_millis(500));
    assert_eq!(content_event_count(&alice, &workspace_id), "0");
    assert_eq!(content_event_count(&bob, &workspace_id), "0");
    // And one more cross-peer summary check after the follow-up round
    // to prove the sync exchange did not perturb the converged state.
    let stable_alice = sync_status(&alice);
    let stable_bob = sync_status(&bob);
    assert_eq!(
        line_value(&stable_alice, "root_fingerprint"),
        line_value(&stable_bob, "root_fingerprint"),
        "root fingerprint must remain converged across follow-up sync rounds"
    );
}

// ---------------------------------------------------------------------------
// Test 3: asymmetric purge across peers.
//
// A authors X and syncs to B. A then expires X locally (via clock advance)
// while B's clock stays under the expiry horizon. A must keep those
// messages absent across a follow-up A↔B sync round, even though B can
// still display them locally until its own clock advances.
// ---------------------------------------------------------------------------

#[test]
fn cli_negentropy_asymmetric_purge_alice_does_not_readmit_from_bob() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let alice_port = free_port();
    let bob_port = free_port();

    let workspace_id = create_workspace_with_ttl(&alice, "Asym", "alice", "alice-laptop", 1);
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    join_workspace(&alice, &bob, &workspace_id, alice_port, "bob", "bob-phone");

    let alice_recipient = assert_success(topo(&["--db", &alice, "key-recipient", &workspace_id]));
    let alice_recipient_id = line_value(&alice_recipient, "recipient_key_id");
    let bob_recipient = assert_success(topo(&["--db", &bob, "key-recipient", &workspace_id]));
    let bob_recipient_id = line_value(&bob_recipient, "recipient_key_id");

    let frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");

    let _ = key_wrap_with_retry(
        &alice,
        &workspace_id,
        &removal_frontier_id,
        &bob_recipient_id,
    );
    let _ = key_wrap_with_retry(
        &alice,
        &workspace_id,
        &removal_frontier_id,
        &alice_recipient_id,
    );
    let _ = wait_for_key_derive(&bob, "1");

    // Alice authors at minute 100. Bob's clock stays at minute 100 too so
    // bob has the same TTL view at admission time. Both peers receive the
    // ciphertext and project the message under the same time pin.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &bob, "clock", "set", "6000000"]));
    for body in ["x-1", "x-2"] {
        assert_success(topo(&["--db", &alice, "send", &workspace_id, body]));
    }
    for body in ["x-1", "x-2"] {
        wait_for_message_text(&alice, &workspace_id, &format!("alice: {body}"));
        wait_for_message_text(&bob, &workspace_id, &format!("alice: {body}"));
    }

    // Capture the converged baseline so we can prove alice's fingerprint
    // changes after the asymmetric expiry.
    let pre_alice = wait_for_root_fingerprint_to_match(&alice, &bob);
    let pre_alice_fp = line_value(&pre_alice, "root_fingerprint");

    // Asymmetric expiry: only alice advances past the TTL horizon. Bob's
    // clock stays at minute 100, so bob keeps both messages visible.
    assert_success(topo(&["--db", &alice, "clock", "set", "6120000"]));
    wait_for_leaf_count(&alice, &workspace_id, "0");
    wait_for_content_count(&alice, &workspace_id, "0");

    let post_alice = wait_for_root_fingerprint_to_change(&alice, &pre_alice_fp);
    let post_alice_fp = line_value(&post_alice, "root_fingerprint");

    assert_ne!(
        pre_alice_fp, post_alice_fp,
        "alice's fingerprint must change after she purges:\npre={pre_alice_fp}\npost={post_alice_fp}"
    );
    assert_eq!(message_lines(&bob, &workspace_id).len(), 2);

    // Drive a follow-up sync round by waiting and re-querying. Alice's
    // expired messages must remain absent from the CLI projections.
    thread::sleep(Duration::from_millis(1500));
    assert_eq!(
        content_event_count(&alice, &workspace_id),
        "0",
        "content events must stay at 0 after the follow-up sync round"
    );
    assert!(
        message_lines(&alice, &workspace_id).is_empty(),
        "alice's messages must stay absent after the follow-up sync round"
    );
}

// ---------------------------------------------------------------------------
// Test 4: batched expiry updates the sync summary.
//
// Author N=10 messages in one minute, expire all, and verify that the
// CLI-visible content and sync summary both reflect their removal.
// The fingerprint must end at a value that differs from the pre-purge
// state, and the indexed count must drop by exactly the purged count.
// ---------------------------------------------------------------------------

#[test]
fn cli_negentropy_batched_chop_updates_root_after_expiry() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let alice_port = free_port();

    let workspace_id = create_workspace_with_ttl(&alice, "Batch", "alice", "alice-laptop", 1);
    assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));

    // Author N=10 messages all at the same minute so a single TTL-1
    // expiry transition retires all of them together.
    const N: usize = 10;
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    for i in 0..N {
        let body = format!("batch-{i}");
        assert_success(topo(&["--db", &alice, "send", &workspace_id, &body]));
    }
    assert_eq!(message_lines(&alice, &workspace_id).len(), N);
    let pre = sync_status(&alice);
    let pre_count: u64 = line_value(&pre, "indexed_events")
        .parse()
        .expect("pre count");
    let pre_fp = line_value(&pre, "root_fingerprint");

    let _alice_daemon = spawn_daemon(&alice, alice_port);
    assert_success(topo(&["--db", &alice, "clock", "set", "6120000"]));
    wait_for_leaf_count(&alice, &workspace_id, "0");
    wait_for_content_count(&alice, &workspace_id, "0");

    let post = wait_for_root_fingerprint_to_change(&alice, &pre_fp);
    let post_count: u64 = line_value(&post, "indexed_events")
        .parse()
        .expect("post count");
    let post_fp = line_value(&post, "root_fingerprint");
    assert_ne!(
        pre_fp, post_fp,
        "fingerprint must change after batched expiry:\npre={pre_fp}\npost={post_fp}"
    );
    assert!(
        post_count + (N as u64) <= pre_count,
        "indexed_events must drop by at least N=10: pre={pre_count}, post={post_count}"
    );
}

// ---------------------------------------------------------------------------
// Test 5: sync summary is stable when nothing expires.
//
// With no expired events, repeated CLI invocations of `sync-status` must
// leave indexed_events, root_count, and root_fingerprint byte-identical.
// ---------------------------------------------------------------------------

#[test]
fn cli_negentropy_sync_status_is_stable_when_nothing_expires() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");

    let workspace_id = create_workspace_with_ttl(&alice, "NoOp", "alice", "alice-laptop", 60);
    assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));

    // Pin clock well under the TTL=60 horizon so nothing expires.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    for body in ["alpha", "beta"] {
        assert_success(topo(&["--db", &alice, "send", &workspace_id, body]));
    }
    assert_eq!(message_lines(&alice, &workspace_id).len(), 2);

    // First snapshot captures the baseline.
    let first = sync_status(&alice);
    let first_indexed = line_value(&first, "indexed_events");
    let first_count = line_value(&first, "root_count");
    let first_fp = line_value(&first, "root_fingerprint");

    // Second snapshot should match while all messages are still live.
    let second = sync_status(&alice);
    assert_eq!(
        line_value(&second, "indexed_events"),
        first_indexed,
        "no-op sync-status must not change indexed_events"
    );
    assert_eq!(
        line_value(&second, "root_count"),
        first_count,
        "no-op sync-status must not change root_count"
    );
    assert_eq!(
        line_value(&second, "root_fingerprint"),
        first_fp,
        "no-op sync-status must not perturb root_fingerprint"
    );

    // Third snapshot for good measure — three back-to-back reads must
    // yield byte-identical sync-status outputs.
    let third = sync_status(&alice);
    assert_eq!(line_value(&third, "indexed_events"), first_indexed);
    assert_eq!(line_value(&third, "root_count"), first_count);
    assert_eq!(line_value(&third, "root_fingerprint"), first_fp);
}

// ---------------------------------------------------------------------------
// Test 6: expiry order independence (CLI confirmation).
//
// Two peers that author the same set of messages (in different orders)
// and then expire them all must converge on byte-identical fingerprints
// after both remove the content. This test pins that property at the CLI level.
// ---------------------------------------------------------------------------

#[test]
fn cli_negentropy_expiry_order_independence_two_peers_distinct_authoring_order() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let alice_port = free_port();
    let bob_port = free_port();

    let workspace_id = create_workspace_with_ttl(&alice, "Order", "alice", "alice-laptop", 1);
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    join_workspace(&alice, &bob, &workspace_id, alice_port, "bob", "bob-phone");

    let alice_recipient = assert_success(topo(&["--db", &alice, "key-recipient", &workspace_id]));
    let alice_recipient_id = line_value(&alice_recipient, "recipient_key_id");
    let bob_recipient = assert_success(topo(&["--db", &bob, "key-recipient", &workspace_id]));
    let bob_recipient_id = line_value(&bob_recipient, "recipient_key_id");

    let frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");

    let _ = key_wrap_with_retry(
        &alice,
        &workspace_id,
        &removal_frontier_id,
        &bob_recipient_id,
    );
    let _ = key_wrap_with_retry(
        &alice,
        &workspace_id,
        &removal_frontier_id,
        &alice_recipient_id,
    );
    let _ = wait_for_key_derive(&bob, "1");

    // Five messages, authored alternating between alice and bob so each
    // peer sees a distinct authoring order. Both
    // peers pin to the same minute so all five expire together.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &bob, "clock", "set", "6000000"]));
    let bodies = ["m-a", "m-b", "m-c", "m-d", "m-e"];
    for (i, body) in bodies.iter().enumerate() {
        let db = if i % 2 == 0 { &alice } else { &bob };
        assert_success(topo(&["--db", db, "send", &workspace_id, body]));
    }
    let expected_author = |i: usize| if i % 2 == 0 { "alice" } else { "bob" };
    for (i, body) in bodies.iter().enumerate() {
        let suffix = format!("{}: {body}", expected_author(i));
        wait_for_message_text(&alice, &workspace_id, &suffix);
        wait_for_message_text(&bob, &workspace_id, &suffix);
    }
    assert_eq!(message_lines(&alice, &workspace_id).len(), bodies.len());
    assert_eq!(message_lines(&bob, &workspace_id).len(), bodies.len());

    let pre = wait_for_root_fingerprint_to_match(&alice, &bob);
    let pre_fp = line_value(&pre, "root_fingerprint");

    // Both peers expire in lockstep. They authored the shared content in
    // different local orders, but the final sync summaries must still match.
    assert_success(topo(&["--db", &alice, "clock", "set", "6120000"]));
    assert_success(topo(&["--db", &bob, "clock", "set", "6120000"]));
    wait_for_leaf_count(&alice, &workspace_id, "0");
    wait_for_leaf_count(&bob, &workspace_id, "0");
    wait_for_content_count(&alice, &workspace_id, "0");
    wait_for_content_count(&bob, &workspace_id, "0");
    wait_for_root_fingerprint_to_change(&alice, &pre_fp);
    wait_for_root_fingerprint_to_change(&bob, &pre_fp);

    let post_alice = wait_for_root_fingerprint_to_match(&alice, &bob);
    let post_bob = sync_status(&bob);
    assert_eq!(
        line_value(&post_alice, "root_fingerprint"),
        line_value(&post_bob, "root_fingerprint"),
        "authoring order must not affect cross-peer fingerprint convergence:\n\
         alice={post_alice}\nbob={post_bob}"
    );
    assert_eq!(
        line_value(&post_alice, "root_count"),
        line_value(&post_bob, "root_count"),
        "root_count must converge regardless of authoring order"
    );
    assert_ne!(
        pre_fp,
        line_value(&post_alice, "root_fingerprint"),
        "expiry must actually change the sync summary"
    );
}

// ---------------------------------------------------------------------------
// Test 7: restart resilience — daemon stop + restart preserves expiry behavior.
//
// Pin a TTL=1 workspace at a pre-expiry clock. Run the daemon long enough
// to admit messages, then stop it WITHOUT advancing the clock past
// expiry. Restart the daemon and only THEN advance the clock past the
// TTL horizon. The post-restart state must show the messages gone and
// the root summary updated, with no drift before the clock advances.
// ---------------------------------------------------------------------------

#[test]
fn cli_negentropy_expiry_survives_daemon_stop_and_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let alice_port = free_port();

    let workspace_id = create_workspace_with_ttl(&alice, "Restart", "alice", "alice-laptop", 1);
    assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));

    // Author 4 messages at minute 100. Spawn the daemon under the expiry
    // horizon so messages get admitted but no expiry fires.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    for body in ["r-1", "r-2", "r-3", "r-4"] {
        assert_success(topo(&["--db", &alice, "send", &workspace_id, body]));
    }
    assert_eq!(message_lines(&alice, &workspace_id).len(), 4);

    let pre_restart = sync_status(&alice);
    let pre_fp = line_value(&pre_restart, "root_fingerprint");
    let pre_count: u64 = line_value(&pre_restart, "indexed_events")
        .parse()
        .expect("pre count");

    // Bring the daemon up briefly and then stop it. This exercises the
    // "daemon was running, we stopped it, will restart" case rather than
    // a never-started cold start.
    let daemon = spawn_daemon(&alice, alice_port);
    thread::sleep(Duration::from_millis(300));
    drop(daemon);
    // Spin until the lock file is released so a restart can re-acquire.
    let lock = format!("{alice}.daemon.lock");
    for _ in 0..100 {
        if !std::path::Path::new(&lock).exists() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    // Pre-restart sync-status (with the daemon dead): no expiry fired,
    // so the root summary must not drift.
    let mid = sync_status(&alice);
    assert_eq!(
        line_value(&mid, "root_fingerprint"),
        pre_fp,
        "fingerprint must not drift across a daemon restart with no clock advance"
    );

    // Now restart the daemon and advance the clock so expiry is observable
    // after the process boundary.
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    assert_success(topo(&["--db", &alice, "clock", "set", "6120000"]));

    wait_for_leaf_count(&alice, &workspace_id, "0");
    wait_for_content_count(&alice, &workspace_id, "0");

    let post = wait_for_root_fingerprint_to_change(&alice, &pre_fp);
    let post_fp = line_value(&post, "root_fingerprint");
    let post_count: u64 = line_value(&post, "indexed_events")
        .parse()
        .expect("post count");
    assert_ne!(
        pre_fp, post_fp,
        "fingerprint must change after post-restart expiry:\n\
         pre={pre_fp}\npost={post_fp}"
    );
    assert!(
        post_count + 4 <= pre_count,
        "indexed_events must drop by at least the 4 purged messages \
         after a stop/restart cycle: pre={pre_count}, post={post_count}"
    );
}

// ---------------------------------------------------------------------------
// Test 8: two peers purge the same id from independent expiry triggers.
//
// Both peers admit the same shared events and then independently advance
// their clocks past TTL. They must converge on byte-identical root
// fingerprints. This is the same end-state as test 2 (synchronized
// purge), but the trigger paths are independent — neither peer's purge
// depends on observing the other's.
// ---------------------------------------------------------------------------

#[test]
fn cli_negentropy_two_peers_same_id_independent_triggers_converge() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let alice_port = free_port();
    let bob_port = free_port();

    let workspace_id = create_workspace_with_ttl(&alice, "Indep", "alice", "alice-laptop", 1);
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    join_workspace(&alice, &bob, &workspace_id, alice_port, "bob", "bob-phone");

    let alice_recipient = assert_success(topo(&["--db", &alice, "key-recipient", &workspace_id]));
    let alice_recipient_id = line_value(&alice_recipient, "recipient_key_id");
    let bob_recipient = assert_success(topo(&["--db", &bob, "key-recipient", &workspace_id]));
    let bob_recipient_id = line_value(&bob_recipient, "recipient_key_id");

    let frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");

    let _ = key_wrap_with_retry(
        &alice,
        &workspace_id,
        &removal_frontier_id,
        &bob_recipient_id,
    );
    let _ = key_wrap_with_retry(
        &alice,
        &workspace_id,
        &removal_frontier_id,
        &alice_recipient_id,
    );
    let _ = wait_for_key_derive(&bob, "1");

    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &bob, "clock", "set", "6000000"]));
    for body in ["dual-1", "dual-2", "dual-3"] {
        assert_success(topo(&["--db", &alice, "send", &workspace_id, body]));
    }
    for body in ["dual-1", "dual-2", "dual-3"] {
        wait_for_message_text(&alice, &workspace_id, &format!("alice: {body}"));
        wait_for_message_text(&bob, &workspace_id, &format!("alice: {body}"));
    }
    let pre = wait_for_root_fingerprint_to_match(&alice, &bob);
    let pre_fp = line_value(&pre, "root_fingerprint");

    // Independent expiry triggers: alice expires FIRST, alone. Bob's
    // clock stays under the horizon, so bob still has the messages.
    assert_success(topo(&["--db", &alice, "clock", "set", "6120000"]));
    wait_for_leaf_count(&alice, &workspace_id, "0");
    wait_for_content_count(&alice, &workspace_id, "0");
    wait_for_root_fingerprint_to_change(&alice, &pre_fp);

    // Cross-peer state at this midpoint MUST diverge: alice has purged,
    // bob has not. This proves alice's purge is locally driven, not a
    // function of bob's state.
    let mid_alice = sync_status(&alice);
    let mid_bob = sync_status(&bob);
    assert_ne!(
        line_value(&mid_alice, "root_fingerprint"),
        line_value(&mid_bob, "root_fingerprint"),
        "mid-test divergence required: alice purged, bob still holds the ids"
    );

    // Now bob crosses the horizon independently.
    assert_success(topo(&["--db", &bob, "clock", "set", "6120000"]));
    wait_for_leaf_count(&bob, &workspace_id, "0");
    wait_for_content_count(&bob, &workspace_id, "0");
    wait_for_root_fingerprint_to_change(&bob, &pre_fp);

    // Both peers, after independently triggered expiry, must converge
    // on byte-identical fingerprints.
    let post_alice = wait_for_root_fingerprint_to_match(&alice, &bob);
    let post_bob = sync_status(&bob);
    assert_eq!(
        line_value(&post_alice, "root_fingerprint"),
        line_value(&post_bob, "root_fingerprint"),
        "independent-trigger purges must converge cross-peer:\n\
         alice={post_alice}\nbob={post_bob}"
    );
    assert_eq!(
        line_value(&post_alice, "root_count"),
        line_value(&post_bob, "root_count"),
    );
    assert_ne!(
        pre_fp,
        line_value(&post_alice, "root_fingerprint"),
        "fingerprint must change after both peers purge"
    );
}

// ---------------------------------------------------------------------------
// Helpers (local to this test file). Mirror the patterns in
// `tests/disappearing_messages_cli_test.rs`. Code duplication is
// deliberate — each top-level test file owns its harness so per-test
// changes are isolated.
// ---------------------------------------------------------------------------

fn create_workspace_with_ttl(
    db: &str,
    name: &str,
    username: &str,
    device_name: &str,
    ttl_minutes: u32,
) -> String {
    let ttl = ttl_minutes.to_string();
    let out = assert_success(topo(&[
        "--db",
        db,
        "create-workspace",
        name,
        "--username",
        username,
        "--devicename",
        device_name,
        "--ttl-minutes",
        &ttl,
    ]));
    line_value(&out, "workspace_id")
}

fn keys_value(db: &str, workspace_id: &str) -> String {
    assert_success(topo(&["--db", db, "keys", workspace_id]))
}

fn sync_status(db: &str) -> String {
    assert_success(topo(&["--db", db, "sync-status"]))
}

fn messages_text(db: &str, workspace_id: &str) -> String {
    assert_success(topo(&["--db", db, "messages", workspace_id]))
}

fn message_lines(db: &str, workspace_id: &str) -> Vec<String> {
    messages_text(db, workspace_id)
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            trimmed
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
                && line.contains(". [")
        })
        .map(ToOwned::to_owned)
        .collect()
}

fn content_event_count(db: &str, workspace_id: &str) -> String {
    let out = assert_success(topo(&["--db", db, "content-count", workspace_id]));
    line_value(&out, "content_events")
}

fn wait_for_leaf_count(db: &str, workspace_id: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let out = keys_value(db, workspace_id);
        if line_value(&out, "local_history_leaves") == expected {
            return;
        }
        last = out;
        thread::sleep(Duration::from_millis(100));
    }
    panic!("leaf count did not reach {expected}:\n{last}");
}

fn wait_for_content_count(db: &str, workspace_id: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "content-count", workspace_id]);
        if output.status.success() {
            let out = stdout(&output);
            if line_value(&out, "content_events") == expected {
                return;
            }
            last = out;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("content count did not reach {expected}:\n{last}");
}

fn wait_for_root_fingerprint_to_change(db: &str, previous: &str) -> String {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "sync-status"]);
        if output.status.success() {
            let out = stdout(&output);
            if line_value(&out, "root_fingerprint") != previous {
                return out;
            }
            last = out;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("root_fingerprint did not change from {previous}:\n{last}");
}

fn wait_for_key_derive(db: &str, expected: &str) -> String {
    let want: usize = expected
        .parse()
        .unwrap_or_else(|_| panic!("invalid expected count for wait_for_key_derive: {expected}"));
    let mut last = String::new();
    let mut last_total = 0;
    for _ in 0..300 {
        let output = topo(&["--db", db, "key-derive"]);
        if output.status.success() {
            let out = stdout(&output);
            if line_value(&out, "derived_key_secrets") == expected {
                return out;
            }
            // Background processing may have already handled the key wraps
            // before this CLI invocation, in which case `derived_key_secrets`
            // stays at 0. Treat "key already present in db" as success by
            // inspecting `keys` for every workspace.
            let total = local_key_secrets_total(db);
            last_total = total;
            if total >= want {
                return out;
            }
            last = out;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("key derive did not reach {expected} (last total {last_total}):\n{last}");
}

/// Sum `local_key_secrets` across every workspace bob/alice has joined.
/// Used by `wait_for_key_derive` so a daemon that already processed key
/// unwraps does not appear as "no derivation happened".
fn local_key_secrets_total(db: &str) -> usize {
    let workspaces = topo(&["--db", db, "workspaces"]);
    if !workspaces.status.success() {
        return 0;
    }
    let mut total = 0;
    for line in stdout(&workspaces).lines() {
        let Some(workspace_id) = line.split_whitespace().next() else {
            continue;
        };
        let keys = topo(&["--db", db, "keys", workspace_id]);
        if !keys.status.success() {
            continue;
        }
        let out = stdout(&keys);
        if let Some(value) = out
            .lines()
            .find_map(|line| line.strip_prefix("local_key_secrets: "))
        {
            if let Ok(count) = value.parse::<usize>() {
                total += count;
            }
        }
    }
    total
}

fn wait_for_message_text(db: &str, workspace_id: &str, expected_suffix: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "messages", workspace_id]);
        if output.status.success() {
            let out = stdout(&output);
            if out
                .lines()
                .any(|line| line.trim_end().ends_with(expected_suffix))
            {
                return;
            }
            last = out;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("message text {expected_suffix:?} never appeared on db={db}:\n{last}");
}

/// Poll until `db` and `other` agree on `root_fingerprint`. Returns
/// the final `db` sync-status output. Convergence requires both
/// daemons to have caught up on each other's events; the wait is
/// bounded by the same 300-tick budget as the rest of the harness.
fn wait_for_root_fingerprint_to_match(db: &str, other: &str) -> String {
    let mut last = String::new();
    for _ in 0..300 {
        let a = sync_status(db);
        let b = sync_status(other);
        if line_value(&a, "root_fingerprint") == line_value(&b, "root_fingerprint") {
            return a;
        }
        last = format!("db={a}\nother={b}");
        thread::sleep(Duration::from_millis(100));
    }
    panic!("root_fingerprint never converged:\n{last}");
}

fn key_wrap_with_retry(
    db: &str,
    workspace_id: &str,
    removal_frontier_id: &str,
    recipient_key_id: &str,
) -> String {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&[
            "--db",
            db,
            "key-wrap",
            workspace_id,
            removal_frontier_id,
            recipient_key_id,
        ]);
        if output.status.success() {
            return stdout(&output);
        }
        last = stderr(&output);
        thread::sleep(Duration::from_millis(100));
    }
    panic!("key-wrap never succeeded: {last}");
}

// --- two-peer setup helpers (mirrored from tests/disappearing_messages_cli_test.rs) ---

/// Join `joiner` to `host`'s workspace through the daemon-served invite flow.
///
/// The caller must already have a running `topo start` daemon on `host` bound
/// to `port` and a running daemon on `joiner` (any port). The host's daemon
/// serves the bootstrap; the joiner's daemon admits the user/endpoint events
/// and connects back. After this returns, both peers' projections include the
/// new membership and sync continues over the daemons' transport routes.
fn join_workspace(
    host: &str,
    joiner: &str,
    workspace_id: &str,
    port: u16,
    username: &str,
    device_name: &str,
) {
    let invite = workspace_invite_for_addr(host, workspace_id, port);
    let accepted = match try_accept_with_identity_retry(joiner, &invite, username, device_name) {
        Ok(output) => output,
        Err(err) => panic!("workspace invite accept failed: {err}"),
    };
    assert_eq!(line_value(&accepted, "workspace_id"), workspace_id);
    wait_for_local_workspace_join(joiner, workspace_id, username);
    wait_for_users_contains(host, workspace_id, username);
}

fn workspace_invite_for_addr(db: &str, workspace_id: &str, port: u16) -> String {
    let addr = format!("127.0.0.1:{port}");
    let out = assert_success(topo(&[
        "--db",
        db,
        "invite",
        "--workspace",
        workspace_id,
        "--public-addr",
        &addr,
    ]));
    invite_link_from_output(&out)
}

fn wait_for_local_workspace_join(db: &str, workspace_id: &str, username: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let recipient = topo(&["--db", db, "key-recipient", workspace_id]);
        let users = topo(&["--db", db, "users", workspace_id]);
        if recipient.status.success() && users.status.success() {
            let users = stdout(&users);
            if users.contains(username) {
                return;
            }
            last = users;
        } else {
            last = format!(
                "key-recipient stderr:\n{}\nusers stderr:\n{}",
                stderr(&recipient),
                stderr(&users)
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("workspace join never projected for {username}: {last}");
}

fn wait_for_users_contains(db: &str, workspace_id: &str, username: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let users = topo(&["--db", db, "users", workspace_id]);
        if users.status.success() {
            let users = stdout(&users);
            if users.contains(username) {
                return;
            }
            last = users;
        } else {
            last = stderr(&users);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("user {username} never appeared in {db}: {last}");
}

fn try_accept_with_identity_retry(
    db: &str,
    invite: &str,
    username: &str,
    device_name: &str,
) -> Result<String, String> {
    let mut last = String::new();
    for _ in 0..200 {
        let output = topo(&[
            "--db",
            db,
            "accept",
            invite,
            "--username",
            username,
            "--devicename",
            device_name,
        ]);
        if output.status.success() {
            return Ok(stdout(&output));
        }
        last = stderr(&output);
        if !last.contains("open tcp stream") && !last.contains("user invite was not received") {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(last)
}

struct RunningDaemon {
    child: Child,
}

impl Drop for RunningDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_daemon(db: &str, port: u16) -> RunningDaemon {
    let port = port.to_string();
    let mut child = spawn_topo(&[
        "--db",
        db,
        "start",
        "--listen",
        "127.0.0.1",
        &port,
        "--tick-ms",
        "50",
        "--quiet-ms",
        "50",
    ]);
    let stdout = child.stdout.take().expect("daemon stdout");
    let mut reader = BufReader::new(stdout);
    let mut first = String::new();
    reader.read_line(&mut first).expect("daemon first line");
    assert!(
        first.starts_with("listening: "),
        "daemon did not report listening: {first}"
    );
    RunningDaemon { child }
}

fn invite_link_from_output(output: &str) -> String {
    output
        .lines()
        .find(|line| line.starts_with("topo://invite/"))
        .unwrap_or_else(|| panic!("missing invite link in output:\n{output}"))
        .to_string()
}

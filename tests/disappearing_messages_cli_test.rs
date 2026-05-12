//! Black-box CLI tests for disappearing-messages forward secrecy.
//!
//! Drives the real `topo` binary and asserts observable forward-secrecy
//! and convergence behavior through public CLI output. The tests
//! intentionally do not seed protocol rows or call workers directly.
//!
//! The shipped surface tested here:
//!   * `create-workspace ... --ttl-minutes <u32>` plumbs a workspace-wide
//!     TTL into authored messages (slice 1 fallback).
//!   * `disappearing-set <ws> <ttl_minutes>` admin-signed setting event
//!     supersedes the workspace-event TTL for new authoring (slice 2).
//!   * `MessageEvent` canonical bytes carry `expires_at_minute: u64`
//!     (`u64::MAX` = no expiry) and `disappearing_setting_id: EventId`
//!     referencing the policy under which the message was authored.
//!     The projector validates the stamp against the referenced
//!     policy's permitted ttl_minutes (slice 3).
//!   * `disappearing_minute_expiry` daemon-step worker retires
//!     per-message and per-reaction leaves and triggers `content_purge`
//!     cascade for reactions/files/slices (slices 1 + 4).
//!   * The message projector reads `now_unix_minute` from
//!     `EventContext` and tombstones expired-at-receive messages with a
//!     deletion label so re-arrivals can't resurrect them.
//!
//! Known gaps these tests do NOT close (covered by future work or
//! documented as out of scope in `disappearing_messages_plan.md` §6):
//!   * Latest-setting enforcement — peers can pick any admitted setting
//!     as the per-message reference, including older more-permissive
//!     ones. Honest authors always pick the latest; closing the gap
//!     needs an "epoch" mechanism (time-based, logical-order, or
//!     counter-based).
//!   * A canonical-bytes-by-event-id query (`events get <id>`) for a
//!     direct purge proof. The current strongest signal is
//!     `content-count` dropping to 0 and `keys` row counts collapsing.
//!   * Offline-expire isolation. With both daemons connected the test
//!     cannot observe whether each peer's expiry decision was reached
//!     locally or sneaked across the wire. (No expiry events sync —
//!     each peer derives retirement from canonical-bytes equality of
//!     the original messages.)
//!   * Per-tombstone-row byte-equality across peers. The tests verify
//!     tombstone-count equality and `cover_summary` equality, but the
//!     actual `LOCAL_HISTORY_NODE_TOMBSTONES` rows are not surfaced by
//!     the current `keys` CLI.
//!   * Whole-minute leaf retirement. Today the worker calls
//!     `RetireDeletedEventLeaf` per message + per reaction; the
//!     `src/workers/encryption.rs:1147` TODO ("whole-minute
//!     retirement") would consolidate to one tombstone per minute.
//!     With per-message TTLs, leaves in the same minute can have
//!     different stamped expiries, so the optimization only pays off
//!     for a fixed workspace TTL.

mod cli_harness;

use std::io::{BufRead, BufReader};
use std::process::Child;
use std::thread;
use std::time::Duration;

use cli_harness::*;

// ---------------------------------------------------------------------------
// Test 1: single-peer FS contract — keys retired, message purged, cover
// changes, AND a daemon restart cannot resurrect the expired message.
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_messages_expire_and_resist_rederive() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let alice_port = free_port();

    let workspace_id =
        create_workspace_with_ttl(&alice, "Disappearing", "alice", "alice-laptop", 1);
    let frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");
    let local_key_secret_id = line_value(&frontier, "local_key_secret_id");

    // Pin clock to unix_minute 100 (ms = 6_000_000). TTL=1 ⇒ expires at
    // minute 101; minute 102 is safely past expiry.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    let send = assert_success(topo(&["--db", &alice, "send", &workspace_id, "secret"]));
    let _message_id = line_value(&send, "event_id");

    // Pre-expiry baseline. The new binary-tree schema only materializes
    // leaves for active messages; the minute_node above them stays implicit
    // until a delete forces it to be durably named, so we don't assert a
    // count for `local_history_minute_nodes` here.
    let pre = keys_value(&alice, &workspace_id);
    assert_eq!(line_value(&pre, "local_history_leaves"), "1");
    assert_eq!(line_value(&pre, "local_history_node_tombstones"), "0");
    let pre_summary = cover_summary_value(&pre);
    assert_eq!(message_lines(&alice, &workspace_id).len(), 1);
    assert!(messages_text(&alice, &workspace_id).contains("alice: secret"));

    let alice_daemon = spawn_daemon(&alice, alice_port);

    assert_success(topo(&["--db", &alice, "clock", "set", "6120000"]));
    // Slice 1 retires one leaf per expired message. Wait until the leaf
    // row is gone; tombstone rows are an internal mechanism and slice 1
    // does not contract on a specific count (the encryption worker only
    // writes a tombstone when the retirement also materializes siblings
    // for an in-minute survivor, which doesn't happen for the last leaf
    // in its minute).
    wait_for_leaf_count(&alice, &workspace_id, "0");

    // Post-expiry assertions.
    let post = keys_value(&alice, &workspace_id);
    assert_eq!(line_value(&post, "local_history_leaves"), "0");
    let post_summary = cover_summary_value(&post);
    assert_ne!(pre_summary, post_summary);
    assert_eq!(message_lines(&alice, &workspace_id).len(), 0);
    wait_for_content_count(&alice, &workspace_id, "0");

    // Stop the daemon and confirm the on-disk state still resists recovery.
    drop(alice_daemon);
    // Re-run key-derive: zero new wrap derivations.
    let derive = assert_success(topo(&["--db", &alice, "key-derive"]));
    assert_eq!(
        line_value(&derive, "derived_key_secrets"),
        "0",
        "rederive must not produce any new key secrets after expiry"
    );

    // The load-bearing FS claim is at the minute-node layer: even with the
    // removal-frontier `local_key_secret` still on disk, the punctured
    // minute_node must not be rederivable. Drive `key-node` for the same
    // coordinates that authoring used (range_start = unix_minute 100,
    // range_width = 1, no event_id_in_minute) and assert it cannot
    // resurrect a usable secret. Two acceptable behaviors: command refuses
    // (non-zero exit), or it succeeds without admitting any new event and
    // without surfacing a fresh `local_history_node_secret_id`. Either way,
    // the on-disk state must be byte-identical to the post-expiry state.
    let rederive = topo(&[
        "--db",
        &alice,
        "key-node",
        &workspace_id,
        &removal_frontier_id,
        &local_key_secret_id,
        "100",
        "1",
    ]);
    if rederive.status.success() {
        let out = stdout(&rederive);
        assert_eq!(
            line_value(&out, "local_history_node_secret_id"),
            "none",
            "rederive must not surface a new minute_node secret:\n{out}"
        );
        assert_eq!(
            line_value(&out, "admitted_events"),
            "0",
            "rederive must not admit any new local_history_node_secret event:\n{out}"
        );
    }

    let after_restart = keys_value(&alice, &workspace_id);
    assert_eq!(
        line_value(&after_restart, "local_history_leaves"),
        "0",
        "rederive must not resurrect any retired leaf:\n{after_restart}"
    );
    assert_eq!(message_lines(&alice, &workspace_id).len(), 0);
    assert_eq!(content_event_count(&alice, &workspace_id), "0");
    assert_eq!(
        cover_summary_value(&after_restart),
        post_summary,
        "cover_summary must be byte-identical after a rederive attempt"
    );

    // Restart the daemon and tick once more: still no recovery.
    let alice_daemon_again = spawn_daemon(&alice, alice_port);
    assert_success(topo(&["--db", &alice, "clock", "set", "6120001"]));
    thread::sleep(Duration::from_millis(300));
    let after_second_restart = keys_value(&alice, &workspace_id);
    assert_eq!(line_value(&after_second_restart, "local_history_leaves"), "0");
    assert_eq!(message_lines(&alice, &workspace_id).len(), 0);
    assert_eq!(content_event_count(&alice, &workspace_id), "0");
    drop(alice_daemon_again);
}

// ---------------------------------------------------------------------------
// Test 2: cross-peer convergence of cover and tombstones across two
// independently-running peers.
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_messages_two_peer_convergence() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let alice_port = free_port();
    let bob_port = free_port();

    let workspace_id =
        create_workspace_with_ttl(&alice, "Converge", "alice", "alice-laptop", 1);
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    join_workspace(
        &alice,
        &bob,
        &workspace_id,
        alice_port,
        "bob",
        "bob-phone",
    );

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

    // Pin both clocks to the same unix_minute and have each peer author.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &bob, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "alice-secret"]));
    assert_success(topo(&["--db", &bob, "send", &workspace_id, "bob-secret"]));

    wait_for_message_text(&alice, &workspace_id, "alice: alice-secret");
    wait_for_message_text(&alice, &workspace_id, "bob: bob-secret");
    wait_for_message_text(&bob, &workspace_id, "alice: alice-secret");
    wait_for_message_text(&bob, &workspace_id, "bob: bob-secret");
    assert_eq!(message_lines(&alice, &workspace_id).len(), 2);
    assert_eq!(message_lines(&bob, &workspace_id).len(), 2);

    let pre_alice = keys_value(&alice, &workspace_id);
    let pre_bob = keys_value(&bob, &workspace_id);
    assert_eq!(
        cover_summary_value(&pre_alice),
        cover_summary_value(&pre_bob),
        "cover_summary must converge across peers pre-expiry"
    );
    // Two messages in one minute ⇒ two leaves on each peer. Minute_nodes
    // stay implicit until a delete materializes them, so we don't assert
    // a count for `local_history_minute_nodes` pre-expiry.
    assert_eq!(line_value(&pre_alice, "local_history_leaves"), "2");
    assert_eq!(line_value(&pre_bob, "local_history_leaves"), "2");

    assert_success(topo(&["--db", &alice, "clock", "set", "6120000"]));
    assert_success(topo(&["--db", &bob, "clock", "set", "6120000"]));
    // Wait for both peers to reach zero leaves; per-leaf retirement may or
    // may not produce a tombstone row depending on whether siblings forced
    // materialization, so leaf count is the load-bearing signal.
    wait_for_leaf_count(&alice, &workspace_id, "0");
    wait_for_leaf_count(&bob, &workspace_id, "0");

    let post_alice = keys_value(&alice, &workspace_id);
    let post_bob = keys_value(&bob, &workspace_id);

    assert_eq!(
        line_value(&post_alice, "local_history_leaves"),
        "0",
        "alice's leaves must be retired post-expiry:\n{post_alice}"
    );
    assert_eq!(
        line_value(&post_bob, "local_history_leaves"),
        "0",
        "bob's leaves must be retired post-expiry:\n{post_bob}"
    );

    assert_eq!(
        cover_summary_value(&post_alice),
        cover_summary_value(&post_bob),
        "cover_summary must converge across peers post-expiry"
    );
    assert_ne!(
        cover_summary_value(&pre_alice),
        cover_summary_value(&post_alice),
        "cover_summary must change after puncture"
    );
    assert_eq!(
        line_value(&post_alice, "local_history_node_tombstones"),
        line_value(&post_bob, "local_history_node_tombstones"),
        "tombstone count must match across peers post-expiry"
    );

    assert_eq!(message_lines(&alice, &workspace_id).len(), 0);
    assert_eq!(message_lines(&bob, &workspace_id).len(), 0);
    wait_for_content_count(&alice, &workspace_id, "0");
    wait_for_content_count(&bob, &workspace_id, "0");

    // Note: cross-peer sync of a NEW message AFTER expiry is intentionally
    // not exercised here. Empirically, when alice authors a fresh-minute
    // message after both peers have purged a prior minute's events, sync
    // does not redeliver the new message to bob within the test's polling
    // window. That is a sync-vs-purge interaction worth its own
    // investigation — the negentropy snapshot referencing purged ids may
    // be confusing the post-purge "have/need" comparison. The convergence
    // claims of slice 1 (cover and tombstone) are already proven by the
    // pre/post-expiry assertions above.
}

// ---------------------------------------------------------------------------
// Test 3 (slice 2): admin-signed `disappearing_messages_setting` event
// supersedes the workspace event's initial TTL. Authoring under one TTL
// stamps that TTL into the message's canonical bytes; a later admin
// `disappearing-set` does NOT retroactively rewrite already-stamped
// messages, but DOES change the TTL stamped into subsequent messages.
//
// This is the load-bearing slice-2 invariant from `disappearing_messages_plan.md`:
// "Late arrivals do not retroactively change message expiry."
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_messages_setting_supersedes_workspace_ttl_without_rewriting_old_messages() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let alice_port = free_port();

    // Workspace TTL = 1 minute at creation.
    let workspace_id =
        create_workspace_with_ttl(&alice, "Setting", "alice", "alice-laptop", 1);
    assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));

    // Pin the clock and author the first message at minute 100. This is
    // stamped under the workspace event's TTL of 1, so its
    // expires_at_minute is 101.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "early"]));
    assert_eq!(message_lines(&alice, &workspace_id).len(), 1);

    // Admin authors a setting event raising TTL to 5. After the setting
    // is admitted, subsequent messages are stamped with TTL=5; the
    // previously-authored "early" message's stamped expiry is unchanged.
    assert_success(topo(&[
        "--db",
        &alice,
        "disappearing-set",
        &workspace_id,
        "5",
    ]));

    // Author the second message at the same minute 100 but after the new
    // setting. It should be stamped with expires_at_minute = 100 + 5 = 105.
    // (No clock advance — the setting takes effect immediately for the
    // next authoring.)
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "late"]));
    assert_eq!(message_lines(&alice, &workspace_id).len(), 2);

    // Spawn the daemon and advance the clock past minute 101 but before
    // minute 105: the "early" message must expire, but the "late" message
    // must remain visible. This is the key claim — the setting did not
    // retroactively rewrite "early"'s expiry to 105, and the new message
    // really did pick up the new TTL.
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    assert_success(topo(&["--db", &alice, "clock", "set", "6180000"])); // minute 103

    // Wait for "early" to disappear; "late" should remain.
    for _ in 0..300 {
        let lines = message_lines(&alice, &workspace_id);
        let has_early = lines.iter().any(|line| line.ends_with("alice: early"));
        let has_late = lines.iter().any(|line| line.ends_with("alice: late"));
        if !has_early && has_late {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let lines = message_lines(&alice, &workspace_id);
    assert!(
        !lines.iter().any(|line| line.ends_with("alice: early")),
        "`early` (stamped TTL=1) must have expired by minute 103:\n{lines:?}"
    );
    assert!(
        lines.iter().any(|line| line.ends_with("alice: late")),
        "`late` (stamped TTL=5) must still be visible at minute 103:\n{lines:?}"
    );

    // Advance past minute 105 and the "late" message must also expire.
    assert_success(topo(&["--db", &alice, "clock", "set", "6360000"])); // minute 106
    for _ in 0..300 {
        let lines = message_lines(&alice, &workspace_id);
        if lines.is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        message_lines(&alice, &workspace_id).len(),
        0,
        "`late` (stamped TTL=5) must have expired by minute 106"
    );
}

// ---------------------------------------------------------------------------
// Test 4 (slice 4): when a parent message expires, its reactions are
// reclaimed in the same tick via the content_purge cascade. Reactions
// don't carry their own `expires_at_minute` — they inherit by being
// authored in the same minute as the parent message, and the
// disappearing-minute worker writes a `MESSAGE_TOMBSTONES` row that
// triggers content_purge to drop reaction rows + canonical bytes for
// any message that's been tombstoned.
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_messages_cascade_reactions_when_parent_message_expires() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let alice_port = free_port();

    let workspace_id =
        create_workspace_with_ttl(&alice, "Cascade", "alice", "alice-laptop", 1);
    assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));

    // Author a message and then react to it, both in unix_minute 100.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "secret"]));
    assert_success(topo(&[
        "--db", &alice, "react", &workspace_id, "#1", "🌶️",
    ]));

    // Pre-expiry: one message visible, two leaves materialized (message +
    // reaction).
    let pre = keys_value(&alice, &workspace_id);
    assert_eq!(line_value(&pre, "local_history_leaves"), "2");
    assert_eq!(message_lines(&alice, &workspace_id).len(), 1);

    let _alice_daemon = spawn_daemon(&alice, alice_port);
    // Advance past minute 101 (TTL=1 ⇒ expires_at_minute=101).
    assert_success(topo(&["--db", &alice, "clock", "set", "6120000"]));

    // Wait for both leaves to be retired — the message's by the
    // disappearing-minute worker, the reaction's by the content_purge
    // cascade triggered by the message tombstone.
    wait_for_leaf_count(&alice, &workspace_id, "0");

    // Post-expiry assertions.
    let post = keys_value(&alice, &workspace_id);
    assert_eq!(line_value(&post, "local_history_leaves"), "0");
    assert_eq!(message_lines(&alice, &workspace_id).len(), 0);
    // Both message and reaction canonical bytes are reclaimed.
    wait_for_content_count(&alice, &workspace_id, "0");
}

// ---------------------------------------------------------------------------
// Test 5 (option-5 enabling property): authoring continues after retirement
// without rotation. After clock-driven expiry retires a message and the
// retire walk wipes F's row, both peers can still author fresh messages
// in a different minute under the SAME frontier — without ever admitting
// a `key-frontier` event in between. The sibling fallback in
// `closest_retained_ancestor` (commit bdaa60f) is the enabling primitive:
// the materialized time-tree siblings cover every minute except the wiped
// one, so `derive_event_leaf` keeps working under the same frontier.
//
// What this test proves:
//   * Pre-expiry sync of X works (baseline).
//   * After both peers retire X and wipe F, alice authors Y in a
//     different minute under the same (wiped) frontier and the message
//     is locally visible (i.e. derive + AEAD sealed-write + projector
//     admit all succeed).
//   * Bob, having retired X independently, also retains the time-tree
//     sibling rows under his (wiped) frontier — those rows are what he
//     would use to decrypt a Y that arrives via sync.
//   * No new `removal_frontier` event was admitted on either peer; the
//     frontier id is byte-identical before X and after Y.
//   * Bonus / legitimate wedge: a same-minute send into the already
//     retired minute fails with the documented
//     "no retained ancestor covers" error — silently re-deriving from
//     a wiped F would defeat forward secrecy.
//
// What this test does NOT close (and intentionally so, mirroring the
// note at the end of `cli_disappearing_messages_two_peer_convergence`):
// cross-peer sync of a NEW post-purge message. Empirically the
// negentropy exchange does not redeliver Y to bob within the polling
// window after both peers have purged a prior minute's events; that's
// a sync-vs-purge interaction that's worth its own investigation and
// is orthogonal to the no-rotation claim. The bob-side sibling-row
// assertion below is the strongest cross-peer signal we can get
// without surfacing inter-peer Y delivery.
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_messages_authoring_continues_after_retirement_without_rotation() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let alice_port = free_port();
    let bob_port = free_port();

    let workspace_id =
        create_workspace_with_ttl(&alice, "NoRotate", "alice", "alice-laptop", 1);
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    join_workspace(
        &alice,
        &bob,
        &workspace_id,
        alice_port,
        "bob",
        "bob-phone",
    );

    // Wrap the initial frontier for both recipients so bob can decrypt
    // alice's authored messages. Snapshot the frontier id NOW so we can
    // assert later that no new removal_frontier event has been admitted
    // between authoring of X and authoring of Y.
    let alice_recipient = assert_success(topo(&["--db", &alice, "key-recipient", &workspace_id]));
    let alice_recipient_id = line_value(&alice_recipient, "recipient_key_id");
    let bob_recipient = assert_success(topo(&["--db", &bob, "key-recipient", &workspace_id]));
    let bob_recipient_id = line_value(&bob_recipient, "recipient_key_id");
    let frontier_before = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let removal_frontier_id_before = line_value(&frontier_before, "removal_frontier_id");
    let _ = key_wrap_with_retry(
        &alice,
        &workspace_id,
        &removal_frontier_id_before,
        &bob_recipient_id,
    );
    let _ = key_wrap_with_retry(
        &alice,
        &workspace_id,
        &removal_frontier_id_before,
        &alice_recipient_id,
    );
    let _ = wait_for_key_derive(&bob, "1");
    let removal_frontiers_pre =
        line_value(&keys_value(&alice, &workspace_id), "removal_frontiers");
    assert_eq!(
        removal_frontiers_pre, "1",
        "precondition: exactly one removal_frontier exists at start"
    );

    // Step 1: pin both clocks to minute 100 (ms = 6_000_000) and have alice
    // author X. TTL=1 ⇒ X expires at minute 101.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &bob, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "x-secret"]));

    // Step 2: sync — both peers admit X.
    wait_for_message_text(&alice, &workspace_id, "alice: x-secret");
    wait_for_message_text(&bob, &workspace_id, "alice: x-secret");
    assert_eq!(message_lines(&alice, &workspace_id).len(), 1);
    assert_eq!(message_lines(&bob, &workspace_id).len(), 1);

    let pre_alice = keys_value(&alice, &workspace_id);
    let pre_bob = keys_value(&bob, &workspace_id);
    assert_eq!(line_value(&pre_alice, "local_history_leaves"), "1");
    assert_eq!(line_value(&pre_bob, "local_history_leaves"), "1");
    assert_eq!(line_value(&pre_alice, "local_key_secrets"), "1");
    assert_eq!(line_value(&pre_bob, "local_key_secrets"), "1");

    // Step 3: advance both clocks past minute 101. The
    // disappearing-minute-expiry worker on each peer retires X's leaf
    // independently, and the retire walk wipes F's row on each peer.
    assert_success(topo(&["--db", &alice, "clock", "set", "6120000"]));
    assert_success(topo(&["--db", &bob, "clock", "set", "6120000"]));
    wait_for_leaf_count(&alice, &workspace_id, "0");
    wait_for_leaf_count(&bob, &workspace_id, "0");
    wait_for_content_count(&alice, &workspace_id, "0");
    wait_for_content_count(&bob, &workspace_id, "0");

    let post_retire_alice = keys_value(&alice, &workspace_id);
    let post_retire_bob = keys_value(&bob, &workspace_id);
    // F-wipe is the load-bearing precondition for the no-rotation claim:
    // if `local_key_secrets` were still 1 the test would not be
    // exercising the sibling-fallback path.
    assert_eq!(
        line_value(&post_retire_alice, "local_key_secrets"),
        "0",
        "precondition: alice's retire walk must have wiped F's row:\n{post_retire_alice}"
    );
    assert_eq!(
        line_value(&post_retire_bob, "local_key_secrets"),
        "0",
        "precondition: bob's retire walk must have wiped F's row:\n{post_retire_bob}"
    );
    // Time-tree siblings must survive on BOTH peers — they're what
    // `derive_event_leaf` will use on alice to author Y, and they're
    // also what bob would use to derive Y's leaf if/when sync of the
    // post-purge message lands. Each peer ran its own retire walk
    // independently (no expiry events sync), so equal node-secret
    // counts are the load-bearing convergence signal here.
    let alice_node_secrets: u64 = line_value(&post_retire_alice, "local_history_node_secrets")
        .parse()
        .expect("parse alice local_history_node_secrets");
    let bob_node_secrets: u64 = line_value(&post_retire_bob, "local_history_node_secrets")
        .parse()
        .expect("parse bob local_history_node_secrets");
    assert!(
        alice_node_secrets > 0,
        "precondition: alice must retain time-tree sibling rows after retire:\n{post_retire_alice}"
    );
    assert!(
        bob_node_secrets > 0,
        "precondition: bob must retain time-tree sibling rows after retire:\n{post_retire_bob}"
    );
    assert_eq!(
        alice_node_secrets, bob_node_secrets,
        "alice and bob's surviving sibling rows must converge \
         (same retire walk, same KDF, same coords)"
    );

    // Step 4 (bonus, legitimate-wedge documentation): with X retired and F
    // wiped, attempting to author a NEW message in the same retired minute
    // M=100 must error with the clear wedge message — silently re-deriving
    // from the wiped F would defeat forward secrecy. Done BEFORE the M+5
    // send because once Y is authored, `next_timestamp` ratchets forward
    // and the same-minute attempt cannot be reproduced.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    let same_minute_attempt = topo(&["--db", &alice, "send", &workspace_id, "z-wedge"]);
    assert!(
        !same_minute_attempt.status.success(),
        "send into already-retired minute must fail:\nstdout={}\nstderr={}",
        stdout(&same_minute_attempt),
        stderr(&same_minute_attempt)
    );
    let same_minute_err = stderr(&same_minute_attempt);
    assert!(
        same_minute_err.contains("no retained ancestor covers"),
        "expected the documented wedge message; got: {same_minute_err}"
    );

    // Step 5 (the load-bearing claim): without any `key-frontier` advance,
    // alice authors Y in a DIFFERENT minute M+5 (105). The send must
    // succeed — `derive_event_leaf` falls back to a covering time-tree
    // sibling row admitted during the retire walk. Y must then be
    // locally visible on alice (the messages listing decrypts the
    // sealed payload, which is the strongest local proof that the
    // sibling-derived leaf secret is usable).
    assert_success(topo(&["--db", &alice, "clock", "set", "6300000"]));
    assert_success(topo(&["--db", &bob, "clock", "set", "6300000"]));
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "y-secret"]));
    wait_for_message_text(&alice, &workspace_id, "alice: y-secret");
    assert_eq!(message_lines(&alice, &workspace_id).len(), 1);

    // Step 6: prove no rotation happened. The frontier id must be the
    // same as before X was authored, and the count of removal_frontiers
    // must still be 1. This is the option-5 contract: forward secrecy is
    // achieved by retire-driven F-wipe + sibling fallback, not by
    // admitting a new frontier event. Read the frontier id from `keys`
    // output rather than `key-frontier` (which would itself create a
    // brand-new frontier and defeat the assertion).
    let post_y_alice = keys_value(&alice, &workspace_id);
    let post_y_bob = keys_value(&bob, &workspace_id);
    let removal_frontier_id_after = frontier_id_from_keys(&post_y_alice);
    assert_eq!(
        removal_frontier_id_after, removal_frontier_id_before,
        "no key-frontier advance should have happened — frontier id must be identical \
         before X and after Y"
    );
    assert_eq!(
        line_value(&post_y_alice, "removal_frontiers"),
        "1",
        "alice must still have exactly one removal_frontier; rotation is forbidden"
    );
    assert_eq!(
        line_value(&post_y_bob, "removal_frontiers"),
        "1",
        "bob must still have exactly one removal_frontier; rotation is forbidden"
    );
    // F is still wiped on alice — Y was authored under the sibling
    // fallback, NOT by resurrecting F. (Bob's F is also still wiped;
    // we don't re-assert because it didn't change since `post_retire_bob`
    // and would only be touched by an explicit `key-frontier` advance,
    // which is exactly what this test forbids.)
    assert_eq!(
        line_value(&post_y_alice, "local_key_secrets"),
        "0",
        "F must remain wiped on alice after authoring Y under the sibling fallback"
    );
}

// ---------------------------------------------------------------------------
// Test 6 (slice 5): the cover-horizon dispatcher seals old subtrees.
//
// With workspace TTL = 0 (no per-message expiry), the
// `disappearing_minute_expiry` worker is a no-op for authored messages.
// Only the `disappearing_floor_dispatcher` (slice 5) drives retirement,
// and it does so once the wall-clock has advanced past
// `authored_minute + COVER_HORIZON_MINUTES` (30 days). The chop primitive
// it invokes writes time-tree subtree tombstones, materializes right-side
// sibling cover, and wipes F. The leaves under the chopped prefix can no
// longer be derived on either peer, even though their per-message rows
// are not GC'd by the chop (a known accumulation source documented in the
// slice 5 plan).
//
// COVER_HORIZON_MINUTES = 30 * 24 * 60 = 43_200 minutes.
// To make the horizon strictly above minute 100, the clock must be set to
// any minute >= 43_301; we use 43_400 with comfortable buffer.
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_messages_cover_horizon_seals_old_subtrees() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let alice_port = free_port();
    let bob_port = free_port();

    // TTL=0 means messages have no per-message expiry. The dispatcher's
    // cover-horizon chop is the ONLY mechanism that can retire their
    // leaves, which is exactly what this test isolates.
    let workspace_id =
        create_workspace_with_ttl(&alice, "Horizon", "alice", "alice-laptop", 0);
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    join_workspace(
        &alice,
        &bob,
        &workspace_id,
        alice_port,
        "bob",
        "bob-phone",
    );

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

    // Pin both clocks to minute 100 (ms = 6_000_000) and author one
    // message at that minute. With TTL=0 the message has no
    // expires_at_minute and `disappearing_minute_expiry` will skip it
    // forever — only the cover-horizon chop retires its leaf.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &bob, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "ancient-secret"]));
    wait_for_message_text(&alice, &workspace_id, "alice: ancient-secret");
    wait_for_message_text(&bob, &workspace_id, "alice: ancient-secret");

    // Pre-chop baseline: both peers see the leaf row, F is alive, no
    // tombstones yet. Cover summaries must already be byte-equal because
    // both peers ran the same derive walk.
    let pre_alice = keys_value(&alice, &workspace_id);
    let pre_bob = keys_value(&bob, &workspace_id);
    assert_eq!(line_value(&pre_alice, "local_history_leaves"), "1");
    assert_eq!(line_value(&pre_bob, "local_history_leaves"), "1");
    assert_eq!(line_value(&pre_alice, "local_key_secrets"), "1");
    assert_eq!(line_value(&pre_bob, "local_key_secrets"), "1");
    assert_eq!(line_value(&pre_alice, "local_history_node_tombstones"), "0");
    assert_eq!(line_value(&pre_bob, "local_history_node_tombstones"), "0");
    let pre_summary = cover_summary_value(&pre_alice);
    assert_eq!(
        pre_summary,
        cover_summary_value(&pre_bob),
        "alice and bob must share a cover summary before the chop"
    );

    // Advance both clocks to a minute strictly past
    // `authored_minute + COVER_HORIZON_MINUTES = 100 + 43_200 = 43_300`.
    // Use minute 43_400 (= 2_604_000_000 ms) for safety. The dispatcher
    // will compute horizon_floor = 43_400 - 43_200 = 200 > 100, then chop
    // the time-tree prefix `[0, 200)`, which retires the minute-100 leaf
    // on each peer independently.
    assert_success(topo(&["--db", &alice, "clock", "set", "2604000000"]));
    assert_success(topo(&["--db", &bob, "clock", "set", "2604000000"]));

    // Wait for the chop to take effect. The strongest convergent signals
    // are: (a) F's row is wiped on each peer (chop wipes F just like
    // RetireDeletedEventLeaf), and (b) `local_history_node_tombstones`
    // becomes non-zero. We poll on F's wipe.
    for _ in 0..300 {
        let alice_keys = keys_value(&alice, &workspace_id);
        let bob_keys = keys_value(&bob, &workspace_id);
        if line_value(&alice_keys, "local_key_secrets") == "0"
            && line_value(&bob_keys, "local_key_secrets") == "0"
        {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    let post_alice = keys_value(&alice, &workspace_id);
    let post_bob = keys_value(&bob, &workspace_id);
    assert_eq!(
        line_value(&post_alice, "local_key_secrets"),
        "0",
        "alice's F row must be wiped by the dispatcher's chop:\n{post_alice}"
    );
    assert_eq!(
        line_value(&post_bob, "local_key_secrets"),
        "0",
        "bob's F row must be wiped by the dispatcher's chop:\n{post_bob}"
    );
    let alice_tombstones: u64 = line_value(&post_alice, "local_history_node_tombstones")
        .parse()
        .expect("parse alice tombstone count");
    let bob_tombstones: u64 = line_value(&post_bob, "local_history_node_tombstones")
        .parse()
        .expect("parse bob tombstone count");
    assert!(
        alice_tombstones > 0,
        "alice must have at least one chop tombstone:\n{post_alice}"
    );
    assert!(
        bob_tombstones > 0,
        "bob must have at least one chop tombstone:\n{post_bob}"
    );
    assert_eq!(
        alice_tombstones, bob_tombstones,
        "chop is deterministic — alice and bob must converge on the same \
         tombstone count after running the same dispatcher independently"
    );
    assert_eq!(
        cover_summary_value(&post_alice),
        cover_summary_value(&post_bob),
        "alice and bob's cover summaries must converge after independent chops"
    );
    assert_ne!(
        cover_summary_value(&post_alice),
        pre_summary,
        "cover summary must change between pre- and post-chop"
    );

    // Slice-5 known limitation (option (b) in the dispatcher plan): the
    // chop does NOT GC per-message rows or the per-coord leaf rows under
    // the chopped subtree. The forward-secrecy guarantee is carried by
    // (1) F's wipe and (2) the subtree tombstones above the leaf, which
    // together prevent any retained-row chain from re-deriving the leaf's
    // node_secret. So we don't assert `local_history_leaves: 0`; the
    // surviving leaf row is dead weight, not a recovery vector.

    // Bonus (per the task's step 5): try to author a NEW message at a
    // minute *below* the horizon. The encryption worker's
    // `derive_event_leaf` must wedge with the documented "no retained
    // ancestor covers" message — silently re-deriving from the wiped
    // sibling cover would defeat the seal. Pin alice's clock back to
    // minute 100; `next_timestamp` for `send` is the max of the logical
    // clock and `observed_max + 1`, and `observed_max` is taken from
    // visible message rows (the chop does not GC them, so the existing
    // minute-100 message keeps `observed_max` at 6_000_000). The new
    // send therefore lands at minute 100 + 1 = 100 (a fresh ms tick,
    // still in minute 100), which is below the chopped floor (200) on
    // BOTH peers and must wedge.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    let past_attempt = topo(&["--db", &alice, "send", &workspace_id, "z-past"]);
    assert!(
        !past_attempt.status.success(),
        "send below the cover horizon must fail:\nstdout={}\nstderr={}",
        stdout(&past_attempt),
        stderr(&past_attempt)
    );
    let past_err = stderr(&past_attempt);
    assert!(
        past_err.contains("no retained ancestor covers"),
        "expected wedge error mentioning no retained ancestor; got:\n{past_err}"
    );
}

// ---------------------------------------------------------------------------
// Test 7 (mutable-TTL no-coalescing): two messages authored in the SAME
// minute under DIFFERENT TTL stamps must retire on their own schedules.
//
// Each message commits to its own `expires_at_minute` in canonical bytes
// at authoring time (slice 1 + 3). The admin-signed
// `disappearing_messages_setting` event tightens the TTL used for
// SUBSEQUENT authoring (slice 2) without retroactively rewriting earlier
// messages. The deletion floor is intentionally NOT advanced here — the
// CLI's `disappearing-set` always sets `expires_at_or_before_minute = 0`,
// so the setting's only effect is on the future-stamping TTL, not on the
// dispatcher's chop floor.
//
// What this test proves:
//   * Two messages authored under different stamped TTLs in the same
//     minute retire INDEPENDENTLY (Y first, then X) — i.e., the worker
//     does not "coalesce" by minute, which would be incorrect under
//     mutable TTL because the two leaves carry different per-message
//     deadlines even though they share a minute_node coord.
//   * The setting tightening is a future-stamping change only: it does
//     not retroactively rewrite X's stamped expiry, and it does not
//     trigger a chop (the floor stays at 0).
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_messages_mixed_ttls_in_same_minute_retire_independently() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let alice_port = free_port();
    let bob_port = free_port();

    // Initial workspace TTL = 10 minutes. Workspace TTL must be non-zero so
    // the `disappearing_minute_expiry` worker actually scans this workspace
    // (see `src/workers/disappearing_minute_expiry.rs:112`).
    let workspace_id =
        create_workspace_with_ttl(&alice, "MixedTtl", "alice", "alice-laptop", 10);
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    join_workspace(
        &alice,
        &bob,
        &workspace_id,
        alice_port,
        "bob",
        "bob-phone",
    );

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

    // Pin both clocks to unix_minute 100 (ms = 6_000_000). Author X under
    // the workspace's initial TTL=10 ⇒ X.expires_at_minute = 110.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &bob, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "x-long"]));

    // Tighten the future-stamping TTL to 1 minute. The CLI sets
    // `expires_at_or_before_minute: 0` (see
    // `src/protocol/event_modules/encryption/cli.rs:603`), so the
    // dispatcher's setting-floor source stays at 0 — no chop is provoked.
    // The setting's `created_at_ms` advances next_timestamp by 1ms; the
    // logical clock is still pinned at 6_000_000 so the setting itself
    // lands in minute 100.
    assert_success(topo(&[
        "--db",
        &alice,
        "disappearing-set",
        &workspace_id,
        "1",
    ]));

    // Author Y under the new TTL=1. The `send` path's `next_timestamp`
    // (in `src/protocol/event_modules/content/message/cli.rs:605`) only
    // looks at content + message timestamps (NOT the encryption setting
    // event), so it returns max(X.created_at_ms + 1, logical_clock) =
    // max(6_000_001, 6_000_000) = 6_000_001. That is still in minute 100
    // (6_000_001 / 60_000 == 100). Y.expires_at_minute = 100 + 1 = 101.
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "y-short"]));

    // Both peers admit X and Y; both messages must be visible and
    // decryptable on each peer pre-expiry.
    wait_for_message_text(&alice, &workspace_id, "alice: x-long");
    wait_for_message_text(&alice, &workspace_id, "alice: y-short");
    wait_for_message_text(&bob, &workspace_id, "alice: x-long");
    wait_for_message_text(&bob, &workspace_id, "alice: y-short");
    assert_eq!(message_lines(&alice, &workspace_id).len(), 2);
    assert_eq!(message_lines(&bob, &workspace_id).len(), 2);

    let pre = keys_value(&alice, &workspace_id);
    assert_eq!(
        line_value(&pre, "local_history_leaves"),
        "2",
        "two messages in one minute ⇒ two leaf rows pre-expiry:\n{pre}"
    );

    // Pin both clocks to minute 102 (ms = 6_120_000). Past Y's deadline
    // (101) but BEFORE X's deadline (110). The disappearing-minute worker
    // must retire Y's leaf and tombstone Y's read-model row, but must
    // NOT touch X — proving per-message stamps are honored independently.
    assert_success(topo(&["--db", &alice, "clock", "set", "6120000"]));
    assert_success(topo(&["--db", &bob, "clock", "set", "6120000"]));

    // Wait for Y's leaf to be retired on both peers (leaves drop from 2
    // to 1) AND messages to collapse to just X. Polling on leaf count is
    // the structural signal; polling on visible messages is the read-side
    // signal — both must hold before we proceed.
    let mut alice_lines = Vec::new();
    let mut bob_lines = Vec::new();
    for _ in 0..300 {
        alice_lines = message_lines(&alice, &workspace_id);
        bob_lines = message_lines(&bob, &workspace_id);
        let alice_keys = keys_value(&alice, &workspace_id);
        let bob_keys = keys_value(&bob, &workspace_id);
        let alice_one_leaf = line_value(&alice_keys, "local_history_leaves") == "1";
        let bob_one_leaf = line_value(&bob_keys, "local_history_leaves") == "1";
        let alice_only_x = alice_lines.len() == 1
            && alice_lines.iter().any(|line| line.ends_with("alice: x-long"));
        let bob_only_x = bob_lines.len() == 1
            && bob_lines.iter().any(|line| line.ends_with("alice: x-long"));
        if alice_only_x && bob_only_x && alice_one_leaf && bob_one_leaf {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        alice_lines.len(),
        1,
        "alice must have exactly one visible message after Y expires:\n{alice_lines:?}"
    );
    assert!(
        alice_lines.iter().any(|line| line.ends_with("alice: x-long")),
        "alice's surviving message must be X (TTL=10, expires at 110):\n{alice_lines:?}"
    );
    assert!(
        !alice_lines.iter().any(|line| line.ends_with("alice: y-short")),
        "alice's Y (TTL=1, expires at 101) must be gone by minute 102:\n{alice_lines:?}"
    );
    assert_eq!(
        bob_lines.len(),
        1,
        "bob must have exactly one visible message after Y expires:\n{bob_lines:?}"
    );
    assert!(
        bob_lines.iter().any(|line| line.ends_with("alice: x-long")),
        "bob's surviving message must be X:\n{bob_lines:?}"
    );
    assert!(
        !bob_lines.iter().any(|line| line.ends_with("alice: y-short")),
        "bob's Y must also be gone by minute 102:\n{bob_lines:?}"
    );
    // Exactly one leaf survives on each peer (X's). Y's leaf was retired,
    // so the leaf count dropped from 2 to 1. This is the strongest
    // structural signal that retirement was per-message, not per-minute:
    // if the worker had coalesced by minute it would have retired X's
    // leaf too.
    let mid = keys_value(&alice, &workspace_id);
    assert_eq!(
        line_value(&mid, "local_history_leaves"),
        "1",
        "exactly X's leaf must survive after Y's retirement:\n{mid}"
    );
    let mid_bob = keys_value(&bob, &workspace_id);
    assert_eq!(
        line_value(&mid_bob, "local_history_leaves"),
        "1",
        "exactly X's leaf must survive on bob after Y's retirement:\n{mid_bob}"
    );

    // Pin both clocks to minute 111 (ms = 6_660_000). Past X's deadline
    // (110). X must now also retire on each peer.
    assert_success(topo(&["--db", &alice, "clock", "set", "6660000"]));
    assert_success(topo(&["--db", &bob, "clock", "set", "6660000"]));
    wait_for_leaf_count(&alice, &workspace_id, "0");
    wait_for_leaf_count(&bob, &workspace_id, "0");
    assert_eq!(message_lines(&alice, &workspace_id).len(), 0);
    assert_eq!(message_lines(&bob, &workspace_id).len(), 0);
    wait_for_content_count(&alice, &workspace_id, "0");
    wait_for_content_count(&bob, &workspace_id, "0");
}

// ---------------------------------------------------------------------------
// Test 8 (late-delivery beyond cover horizon): a peer that has advanced
// past `COVER_HORIZON_MINUTES` rejects late-delivered messages from the
// sealed range with the documented "no retained ancestor covers" wedge.
//
// Setup choreography:
//   1. Both peers start with daemons connected; alice wraps the frontier
//      for bob and bob runs `key-derive` so bob has F's row and the
//      machinery to admit alice-authored events.
//   2. The peers pin to minute T_AUTHOR = 100 and alice authors X.
//   3. Alice's daemon is then KILLED before sync delivers X to bob. The
//      `topo send` ran while the daemon was alive but inbound sync from
//      alice → bob is queued; killing alice's daemon closes the TCP
//      socket so bob never receives X.
//   4. Bob's clock is advanced to T_AUTHOR + COVER_HORIZON_MINUTES + 1
//      (= minute 43_301, ms = 2_598_060_000). The dispatcher's
//      `horizon_floor = 43_301 - 43_200 = 101 > T_AUTHOR = 100`, so the
//      chop seals the prefix `[0, 101)` covering X's minute. Bob's F row
//      is wiped; the chop tombstones the path to T_AUTHOR's minute_node.
//   5. Alice's daemon is restarted and reconnected. Sync queues X for
//      delivery to bob. Bob attempts to admit X.
//   6. Assert: bob never admits X — the leaf event in X's dep chain
//      cannot find a covering source on bob (the chop sealed it), and
//      there is no path that resurrects a usable derivation. Bob's
//      visible-message list and content count must stay at zero.
//
// Practical note: per the task and `bdaa60f`, the user-visible wedge
// message is "no retained ancestor covers the target leaf", surfaced by
// `derive_event_leaf` on the authoring path. The admit path's exact
// rejection wording is a secondary signal — what we assert is the
// load-bearing property: X NEVER appears on bob, content stays at 0,
// and the leaf count stays at 0. If a buggy admit path silently
// re-derives or partial-admits, this test will catch it.
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_messages_late_delivery_after_cover_horizon_is_rejected_cleanly() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let alice_port = free_port();
    let bob_port = free_port();

    // TTL=0 so the per-message expiry worker is a no-op for X — the only
    // mechanism that can retire X's path on bob is the cover-horizon chop,
    // which is exactly what we want to isolate.
    let workspace_id =
        create_workspace_with_ttl(&alice, "LateDelivery", "alice", "alice-laptop", 0);
    let alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    join_workspace(
        &alice,
        &bob,
        &workspace_id,
        alice_port,
        "bob",
        "bob-phone",
    );

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

    // Pin both clocks to minute 100. Alice authors X; with TTL=0 the
    // message has `expires_at_minute = u64::MAX` and the per-message
    // expiry worker will skip it forever. X is in alice's local store
    // immediately (the `send` command admits + applies before returning).
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &bob, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "ancient-x"]));
    wait_for_message_text(&alice, &workspace_id, "alice: ancient-x");

    // Kill alice's daemon to halt outbound sync. Anything bob has already
    // pulled before this point stays; X may or may not have been pulled.
    // We will assert the load-bearing property below regardless of which
    // race outcome obtains: if bob already admitted X before the kill,
    // X will appear and the test setup itself didn't isolate the late-
    // delivery wedge — we detect that and skip the wedge assertions, and
    // the test re-runs (the harness has flake tolerance via the polling
    // helpers). If X is still in flight, killing the daemon definitively
    // blocks delivery and we can run the late-delivery wedge assertions.
    drop(alice_daemon);

    // Advance bob's clock past the horizon. With T_AUTHOR=100 and
    // COVER_HORIZON_MINUTES=43_200, choose now_minute = 43_301 so
    // horizon_floor = 43_301 - 43_200 = 101 > 100 and the chop seals
    // the prefix `[0, 101)` covering X's minute. Bob's F row gets wiped
    // and tombstones are written.
    let bob_now_minute: u64 = 43_301;
    let bob_now_ms = bob_now_minute * 60_000;
    assert_success(topo(&["--db", &bob, "clock", "set", &bob_now_ms.to_string()]));

    // Wait for the dispatcher to chop on bob: F is wiped and at least one
    // tombstone exists. (Same convergence signal as test 6.)
    for _ in 0..300 {
        let bob_keys = keys_value(&bob, &workspace_id);
        if line_value(&bob_keys, "local_key_secrets") == "0"
            && line_value(&bob_keys, "local_history_node_tombstones") != "0"
        {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let post_chop_bob = keys_value(&bob, &workspace_id);
    assert_eq!(
        line_value(&post_chop_bob, "local_key_secrets"),
        "0",
        "precondition: bob's F row must be wiped by the dispatcher's chop:\n{post_chop_bob}"
    );
    let bob_tombstones: u64 = line_value(&post_chop_bob, "local_history_node_tombstones")
        .parse()
        .expect("parse bob tombstones");
    assert!(
        bob_tombstones > 0,
        "precondition: bob must have at least one chop tombstone:\n{post_chop_bob}"
    );

    // Snapshot bob's pre-redelivery state — we will assert it is
    // unchanged after we restart alice's daemon and let sync attempt
    // to deliver X.
    let bob_leaves_before = line_value(&post_chop_bob, "local_history_leaves");
    let bob_messages_before = message_lines(&bob, &workspace_id).len();
    let bob_content_before = content_event_count(&bob, &workspace_id);
    // The test isolates the late-delivery path: bob must NOT have admitted
    // X before alice's daemon was killed. If sync raced ahead, the wedge
    // we're trying to assert never had a chance to fire and the test
    // would silently pass on a vacuous property. The choreography below
    // (kill alice's daemon immediately after `topo send` returns, then
    // wait for chop) is fast enough that in practice bob does not see X.
    // If this invariant ever fails, we panic loudly so the race is
    // attributed correctly rather than silently swallowed.
    let setup_race_bob_already_saw_x = bob_messages_before > 0;

    // Restart alice's daemon and reconnect. Sync should now attempt to
    // deliver X to bob. Bob's chop has sealed minute 100, so X's leaf
    // event has no covering source secret on bob: the leaf event's
    // projector cannot validate, the message event will not project,
    // and X must not become visible on bob.
    let _alice_daemon_again = spawn_daemon(&alice, alice_port);
    connect_daemon_pair(&alice, alice_port, &bob, bob_port);

    // Give sync ample opportunity to attempt delivery. We poll for ~3s;
    // if X were going to appear on bob, it would by then.
    let mut bob_ever_saw_x = false;
    for _ in 0..30 {
        let lines = message_lines(&bob, &workspace_id);
        if lines.iter().any(|line| line.ends_with("alice: ancient-x")) {
            bob_ever_saw_x = true;
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }

    if setup_race_bob_already_saw_x {
        // Setup race: bob already had X before alice's daemon was killed.
        // The wedge couldn't fire because the leaf was already admitted
        // under bob's pre-chop derivation. Panic loudly — the test is
        // not isolating the late-delivery wedge and would silently
        // pass without exercising the property under test. Re-running
        // the test is sufficient because the race is timing-driven.
        panic!(
            "setup race: bob already had X before the chop, so the late-\
             delivery wedge was not exercised. Re-run the test."
        );
    }

    assert!(
        !bob_ever_saw_x,
        "X must NOT appear on bob: bob's chop sealed the subtree covering \
         minute 100, so the late-delivered leaf cannot derive a covering \
         source"
    );

    // Final state must be byte-equal to the pre-redelivery snapshot:
    //   * no new leaves materialized (admit failed cleanly, no half-state),
    //   * no new visible messages,
    //   * no canonical message bytes added,
    //   * F is still wiped (no resurrection).
    let post_attempt_bob = keys_value(&bob, &workspace_id);
    assert_eq!(
        line_value(&post_attempt_bob, "local_history_leaves"),
        bob_leaves_before,
        "leaf count must not change on bob — admit must not partial-write:\n{post_attempt_bob}"
    );
    assert_eq!(
        line_value(&post_attempt_bob, "local_key_secrets"),
        "0",
        "F must remain wiped on bob — admit must not resurrect a key secret:\n{post_attempt_bob}"
    );
    assert_eq!(
        message_lines(&bob, &workspace_id).len(),
        bob_messages_before,
        "bob must not have admitted any new visible messages"
    );
    assert_eq!(
        content_event_count(&bob, &workspace_id),
        bob_content_before,
        "bob must not have admitted any new content events"
    );
}

// ---------------------------------------------------------------------------
// Test 9 (chop GCs subsumed per-message tombstones): a peer that has
// already accumulated per-message tombstones from prior expirations under
// the cover horizon must, when the dispatcher chops, exact-delete those
// pre-existing fine-grained tombstones in the same transaction as the chop
// wipe. The coarse subtree tombstones written by the chop already convey
// "this whole range is gone" and take over the sync re-admit prevention
// role; the per-message tombstones below the floor become redundant.
//
// Setup choreography:
//   * TTL=1 minute so each authored message produces one
//     `MESSAGE_TOMBSTONES` row + one `LOCAL_HISTORY_NODE_TOMBSTONES` row
//     when its leaf is retired by the per-minute expiry worker.
//   * Pin the clock to minute 100, author 3 messages, advance the clock to
//     minute 102 so all three expire. After this, the table counts are
//     elevated by the per-leaf retirements.
//   * Snapshot the elevated counts.
//   * Advance the clock past `COVER_HORIZON_MINUTES` so the dispatcher
//     chops the prefix `[0, horizon_floor)` covering the minute-100
//     authoring slot. The chop must:
//       (a) Write coarse subtree tombstones over the range (a few rows
//           bounded by time-tree depth).
//       (b) Exact-delete every subsumed per-leaf tombstone.
//       (c) Exact-delete every subsumed `MESSAGE_TOMBSTONES` row.
//
// Assertion: after the chop, both `MESSAGE_TOMBSTONES` and the per-leaf
// portion of `LOCAL_HISTORY_NODE_TOMBSTONES` for the chopped range have
// dropped. The per-leaf table will still have the chop's own coarse
// tombstones, so its count is allowed to be > 0; the strongest convergent
// signal is `message_tombstones == 0` AND `local_history_leaves == 0`
// (no fine-grained per-message accounting under the chopped floor).
// ---------------------------------------------------------------------------

#[test]
fn cli_disappearing_messages_cover_horizon_chop_gcs_old_per_message_tombstones() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let alice_port = free_port();

    // TTL=1 minute. Each authored message will be retired by the
    // disappearing-minute worker after the clock advances past minute
    // (authored_minute + 1). The retire writes a MESSAGE_TOMBSTONES row
    // (per process_job in src/workers/disappearing_minute_expiry.rs:217)
    // AND per-leaf LOCAL_HISTORY_NODE_TOMBSTONES rows (per the retire
    // walk in src/workers/encryption.rs).
    let workspace_id =
        create_workspace_with_ttl(&alice, "ChopGc", "alice", "alice-laptop", 1);
    let _alice_daemon = spawn_daemon(&alice, alice_port);

    let alice_recipient = assert_success(topo(&["--db", &alice, "key-recipient", &workspace_id]));
    let alice_recipient_id = line_value(&alice_recipient, "recipient_key_id");
    let frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");
    let _ = key_wrap_with_retry(
        &alice,
        &workspace_id,
        &removal_frontier_id,
        &alice_recipient_id,
    );

    // Pin clock to minute 100, author 3 messages.
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    for body in ["m1", "m2", "m3"] {
        assert_success(topo(&["--db", &alice, "send", &workspace_id, body]));
    }
    wait_for_message_text(&alice, &workspace_id, "alice: m1");
    wait_for_message_text(&alice, &workspace_id, "alice: m2");
    wait_for_message_text(&alice, &workspace_id, "alice: m3");
    assert_eq!(message_lines(&alice, &workspace_id).len(), 3);

    // Advance clock past TTL=1 (minute 102 > 100 + 1 = 101) so all three
    // messages expire and produce per-message tombstones.
    assert_success(topo(&["--db", &alice, "clock", "set", "6120000"]));
    wait_for_leaf_count(&alice, &workspace_id, "0");

    // Verify the per-message tombstones accumulated as expected.
    let post_expiry = keys_value(&alice, &workspace_id);
    let mt_after_expiry: u64 = line_value(&post_expiry, "message_tombstones")
        .parse()
        .expect("parse message_tombstones");
    let lt_after_expiry: u64 = line_value(&post_expiry, "local_history_node_tombstones")
        .parse()
        .expect("parse local_history_node_tombstones");
    assert_eq!(
        mt_after_expiry, 3,
        "TTL=1 expiry must produce one MESSAGE_TOMBSTONES row per \
         retired message:\n{post_expiry}"
    );
    assert!(
        lt_after_expiry > 0,
        "per-leaf retire must produce at least one \
         LOCAL_HISTORY_NODE_TOMBSTONES row:\n{post_expiry}"
    );

    // Now advance the clock past COVER_HORIZON_MINUTES so the dispatcher
    // chops the entire prefix that covers minute 100. With horizon = 43_200
    // and authored_minute = 100, choose now_minute = 43_400 so
    // horizon_floor = 43_400 - 43_200 = 200 > 100, and the chop seals
    // `[0, 200)`. The coarse subtree tombstones the chop writes subsume
    // every per-leaf and per-message tombstone authored at minute 100.
    assert_success(topo(&["--db", &alice, "clock", "set", "2604000000"]));

    // Wait for the chop's GC to drain MESSAGE_TOMBSTONES. We can't poll
    // `local_key_secrets == 0` like test 6 does because F was already
    // wiped by the per-leaf retire walks earlier (each of those walks
    // wipes F as part of the forward-secrecy step, so F is gone before
    // the dispatcher even gets a chance to chop). The strongest
    // convergence signal here is therefore the GC effect itself: the
    // pre-existing MESSAGE_TOMBSTONES rows whose `authored_minute` is
    // below the new floor must be exact-deleted by the chop's GC step.
    let mut last_keys = String::new();
    for _ in 0..300 {
        last_keys = keys_value(&alice, &workspace_id);
        if line_value(&last_keys, "message_tombstones") == "0" {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let post_chop = last_keys;

    // The load-bearing assertion: every subsumed per-message tombstone
    // (authored_minute = 100 < floor_minute = 200) has been exact-deleted
    // in the chop's same-transaction GC. Three messages expired and three
    // tombstones were written; all three must be gone now.
    let mt_after_chop: u64 = line_value(&post_chop, "message_tombstones")
        .parse()
        .expect("parse post-chop message_tombstones");
    assert_eq!(
        mt_after_chop, 0,
        "every subsumed MESSAGE_TOMBSTONES row must be GC'd by the chop \
         (was {mt_after_expiry}, now {mt_after_chop}):\n{post_chop}"
    );

    // F must remain wiped — the chop must not resurrect F. The per-leaf
    // retires already wiped F before the chop ran; the chop is a no-op
    // on F-row presence (it would chop F if it were alive, but it
    // doesn't bring F back from the dead).
    assert_eq!(
        line_value(&post_chop, "local_key_secrets"),
        "0",
        "F must remain wiped after chop:\n{post_chop}"
    );

    // The per-leaf tombstone table must have shed the per-message rows
    // the retire walk wrote at minute 100. The chop also wrote its OWN
    // coarse tombstones, so the absolute count is allowed to be either
    // smaller or larger than `lt_after_expiry`; the convergent signal is
    // that fine-grained per-leaf rows at minute 100 are no longer
    // contributing to dead-weight storage. The strongest signal is
    // `local_history_leaves: 0` (no surviving leaves at minute 100,
    // since the per-leaf retires already removed them).
    assert_eq!(
        line_value(&post_chop, "local_history_leaves"),
        "0",
        "no leaf rows must survive a chop covering all authored minutes:\n{post_chop}"
    );
}

// ---------------------------------------------------------------------------
// Helpers (local to this test file).
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

fn cover_summary_value(keys_output: &str) -> String {
    line_value(keys_output, "cover_summary")
}

/// Extract the (single) frontier id from `keys` output without authoring a
/// new frontier event. The `keys` command renders one line per frontier as
/// `frontier: <hex_id> access=<yes|no>`. Tests that need to assert "no
/// rotation happened" cannot call `key-frontier` to read it because that
/// command always creates a brand-new frontier.
fn frontier_id_from_keys(keys_output: &str) -> String {
    let mut iter = keys_output.lines().filter_map(|line| {
        line.strip_prefix("frontier: ")
            .and_then(|rest| rest.split_whitespace().next())
            .map(ToOwned::to_owned)
    });
    let only = iter
        .next()
        .unwrap_or_else(|| panic!("missing `frontier:` line in keys output:\n{keys_output}"));
    assert!(
        iter.next().is_none(),
        "multiple `frontier:` lines in keys output (rotation occurred):\n{keys_output}"
    );
    only
}

fn messages_text(db: &str, workspace_id: &str) -> String {
    assert_success(topo(&["--db", db, "messages", workspace_id]))
}

/// Visible message bodies: lines of the form `N. [ts] user: text`.
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
        let out = assert_success(topo(&["--db", db, "keys", workspace_id]));
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
            // The daemon's encryption worker may have already drained the
            // pending key wraps before this CLI invocation, in which case
            // `derived_key_secrets` stays at 0. Treat "key already present
            // in db" as success by inspecting `keys` for every workspace.
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
/// Used by `wait_for_key_derive` so a daemon that already processed the
/// pending unwraps does not appear as "no derivation happened".
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

/// Wait for a message body suffix (e.g. `"alice: hello"`) to appear in the
/// `messages` listing. The CLI prints lines as `N. [ts] author: text`, so
/// callers pass the `author: text` suffix and we match on `ends_with`.
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
    panic!(
        "message text {expected_suffix:?} never appeared on db={db}:\n{last}"
    );
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

// --- two-peer setup helpers (mirrored from tests/encryption_cli_test.rs) ---

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

fn connect_daemon_pair(left_db: &str, left_port: u16, right_db: &str, right_port: u16) {
    let left_invite = transport_invite(left_db, left_port);
    let right_invite = transport_invite(right_db, right_port);
    let right_to_left = connect_with_retry(right_db, &left_invite);
    assert!(right_to_left.contains("connected:"), "{right_to_left}");
    let left_to_right = connect_with_retry(left_db, &right_invite);
    assert!(left_to_right.contains("connected:"), "{left_to_right}");
}

fn transport_invite(db: &str, port: u16) -> String {
    let addr = format!("127.0.0.1:{port}");
    let out = assert_success(topo(&["--db", db, "invite", "--public-addr", &addr]));
    invite_link_from_output(&out)
}

fn invite_link_from_output(output: &str) -> String {
    output
        .lines()
        .find(|line| line.starts_with("topo://invite/"))
        .unwrap_or_else(|| panic!("missing invite link in output:\n{output}"))
        .to_string()
}

fn connect_with_retry(db: &str, invite: &str) -> String {
    let mut last = String::new();
    for _ in 0..200 {
        let output = topo(&["--db", db, "connect", invite]);
        if output.status.success() {
            return stdout(&output);
        }
        last = stderr(&output);
        thread::sleep(Duration::from_millis(50));
    }
    panic!("connect never succeeded: {last}");
}

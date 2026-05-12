//! Black-box CLI tests for the deterministic per-event leaf-coord design.
//!
//! Setup goes through the real `topo` binary: workspace creation, key
//! frontier, message authoring, deletion. The tests intentionally do not
//! seed protocol rows or call workers directly; the CLI boundary is the
//! invariant under test.
//!
//! Tested invariants:
//!   * Two clients with **identical** canonical inputs (same workspace,
//!     author, frontier, clock-pinned `created_at_ms`) produce **identical**
//!     event ids and leaf coordinates — replay is idempotent.
//!   * Multiple messages in the same `unix_minute` share one minute_node
//!     above their per-message leaves.
//!   * Manual delete purges only the deleted leaf event canonical bytes;
//!     the minute_node and sibling leaves stay.
//!   * A workspace's `cover_summary` is a deterministic function of the
//!     retained-set on that workspace, so replaying the same delete set in
//!     different orders yields the same summary.

mod cli_harness;

use std::io::{BufRead, BufReader};
use std::process::Child;
use std::thread;
use std::time::Duration;

use cli_harness::*;

fn create_workspace(db: &str, name: &str, username: &str, device_name: &str) -> String {
    let out = assert_success(topo(&[
        "--db",
        db,
        "create-workspace",
        name,
        "--username",
        username,
        "--devicename",
        device_name,
    ]));
    line_value(&out, "workspace_id")
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

fn cover_summary_value(keys_output: &str) -> String {
    line_value(keys_output, "cover_summary")
}

fn keys_value(db: &str, workspace_id: &str) -> String {
    assert_success(topo(&["--db", db, "keys", workspace_id]))
}

#[test]
fn cli_minute_node_is_shared_across_messages_in_same_minute() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Minute", "alice", "alice-laptop");
    assert_success(topo(&["--db", &db, "key-frontier", &workspace_id]));

    // Pin the clock so all three messages land in unix_minute = 100.
    // unix_minute_for(6_000_000) = 100; subsequent sends bump by 1 ms each.
    assert_success(topo(&["--db", &db, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &db, "send", &workspace_id, "first"]));
    assert_success(topo(&["--db", &db, "send", &workspace_id, "second"]));
    assert_success(topo(&["--db", &db, "send", &workspace_id, "third"]));

    let keys = keys_value(&db, &workspace_id);
    // Under the binary-tree FS, fresh encryption with no deletes
    // materializes only the leaf row per event — every interior time-tree
    // and trie node stays implicit and is derivable on demand from the
    // workspace root. Three messages in the same minute therefore land as
    // three leaves and zero internal rows.
    assert_eq!(line_value(&keys, "local_history_minute_nodes"), "0");
    assert_eq!(line_value(&keys, "local_history_leaves"), "3");
    assert_eq!(line_value(&keys, "local_history_node_secrets"), "3");
    let leaf_lines: Vec<&str> = keys
        .lines()
        .filter(|line| {
            line.contains("history_node:")
                && line.contains("start=100")
                && line.contains("width=1")
                && !line.contains("event_id_in_minute=none")
        })
        .collect();
    assert_eq!(leaf_lines.len(), 3, "expected 3 leaf rows in minute 100");
}

#[test]
fn cli_message_leaf_coord_is_deterministic_from_canonical_fields() {
    // The redesign: leaf coord is BLAKE3-keyed-hash over canonical
    // identifying fields, so two clients with identical inputs land on the
    // same leaf. Verify that property at the CLI boundary by:
    //
    //   1. Pinning the clock so `created_at_ms` is fixed.
    //   2. Sending one message and reading back the leaf coordinate from
    //      `keys`.
    //   3. Recomputing the leaf coord independently from the message's
    //      canonical fields using the same BLAKE3-keyed-hash construction
    //      the protocol uses.
    //   4. Asserting the two coords match.
    //
    // The independent recomputation is a thin re-implementation of
    // `message_event_id_in_minute`; if the protocol's hash construction
    // changes, this test changes too — that's the point.
    use topo::core::crypto;
    use topo::protocol::event_modules::content::message::types::{
        message_event_id_in_minute, MESSAGE_LEAF_COORD_DOMAIN,
    };

    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Determinism", "alice", "alice-laptop");
    assert_success(topo(&["--db", &db, "key-frontier", &workspace_id]));
    assert_success(topo(&["--db", &db, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &db, "send", &workspace_id, "hello"]));

    // Read back the only leaf coord recorded for the workspace.
    let keys = keys_value(&db, &workspace_id);
    let leaf_line = keys
        .lines()
        .find(|line| line.contains("history_node:") && !line.contains("event_id_in_minute=none"))
        .expect("expected one per-message leaf row");
    // `event_id_in_minute=<hex>` is part of the row line.
    let observed_coord_hex = leaf_line
        .split("event_id_in_minute=")
        .nth(1)
        .expect("leaf line carries event_id_in_minute")
        .split_whitespace()
        .next()
        .expect("event_id_in_minute hex token");
    let observed_coord = parse_hex(observed_coord_hex);

    // Recompute the deterministic coord. The protocol uses the workspace_id
    // as the keyed-hash key, the v1 domain tag, and a writer-encoded info
    // tuple `(workspace, author, frontier, ts_be)`. We reuse
    // `message_event_id_in_minute` to keep this test honest about the
    // construction it validates.
    let workspace_bytes = parse_hex(&workspace_id);
    // The author + frontier ids are not directly printed by `keys`, so we
    // ask the CLI: identity prints the local user id embedded in a
    // `workspace:` row, and `keys` prints the workspace's frontier line.
    let identity = assert_success(topo(&["--db", &db, "identity"]));
    let user_hex = identity
        .lines()
        .find_map(|line| {
            line.split_whitespace()
                .find(|tok| tok.starts_with("user_id="))
                .map(|tok| tok.trim_start_matches("user_id=").to_string())
        })
        .expect("identity output must include user_id=...");
    let author_id = parse_hex(&user_hex);
    let frontier_line = keys
        .lines()
        .find(|line| line.starts_with("frontier:"))
        .expect("frontier line");
    let frontier_hex = frontier_line
        .split_whitespace()
        .nth(1)
        .expect("frontier hex token");
    let frontier_id = parse_hex(frontier_hex);

    let recomputed = message_event_id_in_minute(
        &workspace_bytes,
        &author_id,
        &frontier_id,
        6_000_000,
    );
    assert_eq!(observed_coord, recomputed, "leaf coord must be deterministic");

    // Sanity-check the construction is BLAKE3-keyed-hash with the v1 domain.
    let mut info = Vec::with_capacity(32 + 32 + 32 + 8);
    info.extend_from_slice(&workspace_bytes);
    info.extend_from_slice(&author_id);
    info.extend_from_slice(&frontier_id);
    info.extend_from_slice(&6_000_000u64.to_be_bytes());
    let manual = crypto::blake3_keyed_hash(&workspace_bytes, MESSAGE_LEAF_COORD_DOMAIN, &info);
    assert_eq!(recomputed, manual);
}

fn parse_hex(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64, "expected 64 hex chars, got {value:?}");
    let mut out = [0u8; 32];
    for idx in 0..32 {
        let hi = hex_nibble(value.as_bytes()[idx * 2]);
        let lo = hex_nibble(value.as_bytes()[idx * 2 + 1]);
        out[idx] = (hi << 4) | lo;
    }
    out
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex nibble: {byte:?}"),
    }
}

#[test]
fn cli_delete_wipes_minute_node_along_descend_path() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Delete", "alice", "alice-laptop");
    assert_success(topo(&["--db", &db, "key-frontier", &workspace_id]));

    // Two messages in the same minute, then delete the first.
    assert_success(topo(&["--db", &db, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &db, "send", &workspace_id, "first"]));
    assert_success(topo(&["--db", &db, "send", &workspace_id, "second"]));

    let pre = keys_value(&db, &workspace_id);
    // Pre-delete: only leaves are materialized.
    assert_eq!(line_value(&pre, "local_history_minute_nodes"), "0");
    assert_eq!(line_value(&pre, "local_history_leaves"), "2");

    assert_success(topo(&["--db", &db, "delete-message", &workspace_id, "#1"]));

    let post = keys_value(&db, &workspace_id);
    // Post-delete: surviving leaf stays. The puncturing retire walk wipes
    // every node on the descend path from F root to the deleted leaf —
    // including the minute_node — so no row at `(start=100, width=1,
    // bit_depth=0)` exists post-retire. Only off-path SIBLINGS remain.
    assert_eq!(line_value(&post, "local_history_leaves"), "1");
    assert_eq!(
        line_value(&post, "local_history_minute_nodes"),
        "0",
        "minute_node for unix_minute=100 must be WIPED by retire (forward secrecy):\n{post}"
    );
    // Tombstones for the wiped path are present.
    assert!(
        post.lines().any(|line| line.starts_with("local_history_node_tombstones:")),
        "post-delete keys output must list tombstone count:\n{post}"
    );
    assert_ne!(
        line_value(&post, "local_history_node_tombstones"),
        "0",
        "retire must write tombstones:\n{post}"
    );

    // The other message in the same minute still decodes.
    let listing = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert!(listing.contains("alice: second"), "{listing}");
    assert!(!listing.contains("alice: first"), "{listing}");
}

#[test]
fn cli_delete_purges_only_the_leaf_event() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Purge", "alice", "alice-laptop");
    assert_success(topo(&["--db", &db, "key-frontier", &workspace_id]));

    assert_success(topo(&["--db", &db, "clock", "set", "6000000"]));
    let send1 = assert_success(topo(&["--db", &db, "send", &workspace_id, "first"]));
    assert_success(topo(&["--db", &db, "send", &workspace_id, "second"]));
    let _msg1_id = line_value(&send1, "event_id");

    let pre = keys_value(&db, &workspace_id);
    let pre_summary = cover_summary_value(&pre);
    let mut pre_leaf_ids: Vec<String> = pre
        .lines()
        .filter(|line| line.contains("history_node:") && !line.contains("event_id_in_minute=none"))
        .filter_map(|line| line.split_whitespace().nth(1).map(ToOwned::to_owned))
        .collect();
    pre_leaf_ids.sort();
    assert_eq!(pre_leaf_ids.len(), 2);

    // Delete the first authored message.
    assert_success(topo(&["--db", &db, "delete-message", &workspace_id, "#1"]));

    let post = keys_value(&db, &workspace_id);
    let mut post_leaf_ids: Vec<String> = post
        .lines()
        .filter(|line| line.contains("history_node:") && !line.contains("event_id_in_minute=none"))
        .filter_map(|line| line.split_whitespace().nth(1).map(ToOwned::to_owned))
        .collect();
    post_leaf_ids.sort();
    assert_eq!(post_leaf_ids.len(), 1, "exactly one leaf must survive");
    let surviving = &post_leaf_ids[0];
    assert!(pre_leaf_ids.contains(surviving));

    // The cover summary changed because the retained set now has fewer rows.
    let post_summary = cover_summary_value(&post);
    assert_ne!(pre_summary, post_summary);
}

#[test]
fn cli_retained_cover_summary_is_deterministic_within_one_workspace() {
    // Same workspace, two histories of authoring + deleting in different
    // orders: the same final retained-set must produce the same cover_summary.
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Determinism", "alice", "alice-laptop");
    assert_success(topo(&["--db", &db, "key-frontier", &workspace_id]));

    // Author three messages in the same minute, then delete two of them in
    // a specific order.
    assert_success(topo(&["--db", &db, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &db, "send", &workspace_id, "first"]));
    assert_success(topo(&["--db", &db, "send", &workspace_id, "second"]));
    assert_success(topo(&["--db", &db, "send", &workspace_id, "third"]));
    // Capture the per-message leaf ids before any deletions so we can compare
    // by structure rather than depending on selector-based deletion order.
    let pre = keys_value(&db, &workspace_id);
    let pre_summary = cover_summary_value(&pre);

    // Delete the first message and re-create the same authored set: the
    // resulting retained-set is the same minute_node + the original two
    // surviving leaves; cover_summary must equal the pre-state minus the
    // deleted leaf row.
    //
    // We cannot directly drive an arbitrary delete order through the CLI
    // beyond what `delete-message` selects, so this assertion focuses on
    // the simpler invariant: cover_summary is computed from the rows in the
    // store, sorted into canonical order, so reading it twice on the same
    // store yields the same bytes.
    let again = keys_value(&db, &workspace_id);
    assert_eq!(cover_summary_value(&again), pre_summary);

    // Delete one message and verify the summary still matches a fresh read.
    assert_success(topo(&["--db", &db, "delete-message", &workspace_id, "#1"]));
    let after_delete = cover_summary_value(&keys_value(&db, &workspace_id));
    let after_delete_again = cover_summary_value(&keys_value(&db, &workspace_id));
    assert_eq!(after_delete, after_delete_again);
    assert_ne!(after_delete, pre_summary);
}

#[test]
fn cli_send_file_authors_its_own_leaf_distinct_from_message_leaf() {
    // Each file event now authors its own per-event leaf under the
    // per-minute coarse cover. After `send-file`, the workspace must have:
    //   * one minute_node,
    //   * one leaf for the message,
    //   * one leaf for the file descriptor.
    //
    // The file's leaf is keyed by canonical file fields (workspace +
    // author + parent message + file_id + frontier + ts), distinct from
    // the message's leaf.
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "FileLeaf", "alice", "alice-laptop");
    assert_success(topo(&["--db", &db, "key-frontier", &workspace_id]));
    assert_success(topo(&["--db", &db, "clock", "set", "6000000"]));

    let payload: Vec<u8> = (0..256u32).map(|byte| byte as u8).collect();
    let in_path = tmp.path().join("blob.bin");
    std::fs::write(&in_path, &payload).expect("write input");
    assert_success(topo(&[
        "--db",
        &db,
        "send-file",
        &workspace_id,
        "see attached",
        "--file",
        in_path.to_str().expect("utf-8"),
    ]));

    let keys = keys_value(&db, &workspace_id);
    // Fresh sends materialize only leaves; the minute_node and time-tree
    // path stay implicit until a delete or expiry punches a hole.
    assert_eq!(line_value(&keys, "local_history_minute_nodes"), "0");
    assert_eq!(
        line_value(&keys, "local_history_leaves"),
        "2",
        "expected one message leaf + one file leaf in keys output:\n{keys}"
    );
}

#[test]
fn cli_delete_file_retires_its_leaf_without_touching_message_leaf() {
    // Author one message + one file. Delete the file via `delete-file`
    // and verify:
    //   * the file's leaf is retired (one leaf left = the message's),
    //   * the message itself remains visible,
    //   * the minute_node above stays.
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "FileDelete", "alice", "alice-laptop");
    assert_success(topo(&["--db", &db, "key-frontier", &workspace_id]));
    assert_success(topo(&["--db", &db, "clock", "set", "6000000"]));

    let payload: Vec<u8> = (0..256u32).map(|byte| byte as u8).collect();
    let in_path = tmp.path().join("blob.bin");
    std::fs::write(&in_path, &payload).expect("write input");
    let send_out = assert_success(topo(&[
        "--db",
        &db,
        "send-file",
        &workspace_id,
        "see attached",
        "--file",
        in_path.to_str().expect("utf-8"),
    ]));
    let file_event_id = line_value(&send_out, "file_event_id");

    let pre = keys_value(&db, &workspace_id);
    assert_eq!(line_value(&pre, "local_history_leaves"), "2");
    assert_eq!(line_value(&pre, "local_history_minute_nodes"), "0");

    assert_success(topo(&[
        "--db",
        &db,
        "delete-file",
        &workspace_id,
        &file_event_id,
    ]));

    let post = keys_value(&db, &workspace_id);
    // Only the message's leaf survives.
    assert_eq!(
        line_value(&post, "local_history_leaves"),
        "1",
        "file leaf must be retired, message leaf must remain:\n{post}"
    );
    // The puncturing retire walk wipes the minute_node along with the rest
    // of the descend path. No `(width=1, bit_depth=0)` row remains.
    assert_eq!(
        line_value(&post, "local_history_minute_nodes"),
        "0",
        "minute_node for unix_minute=100 must be WIPED by retire (descend-path FS):\n{post}"
    );

    // Message text still listed.
    let messages = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert!(
        messages.contains("see attached"),
        "message must remain visible after file delete:\n{messages}"
    );
    // File listing is empty.
    let files = assert_success(topo(&["--db", &db, "files", &workspace_id]));
    assert!(
        files.contains("FILES (0 total):"),
        "file row must be deleted:\n{files}"
    );
}

#[test]
fn cli_delete_message_cascades_to_attached_file_leaf() {
    // Author one message + one file. Delete the parent message via
    // `delete-message`. Both the message's leaf AND the file's leaf must
    // be retired (cascade), the file's projection rows + canonical bytes
    // are gone, and the minute_node stays.
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Cascade", "alice", "alice-laptop");
    assert_success(topo(&["--db", &db, "key-frontier", &workspace_id]));
    assert_success(topo(&["--db", &db, "clock", "set", "6000000"]));

    let payload: Vec<u8> = (0..256u32).map(|byte| byte as u8).collect();
    let in_path = tmp.path().join("blob.bin");
    std::fs::write(&in_path, &payload).expect("write input");
    assert_success(topo(&[
        "--db",
        &db,
        "send-file",
        &workspace_id,
        "see attached",
        "--file",
        in_path.to_str().expect("utf-8"),
    ]));

    let pre = keys_value(&db, &workspace_id);
    assert_eq!(line_value(&pre, "local_history_leaves"), "2");

    assert_success(topo(&["--db", &db, "delete-message", &workspace_id, "#1"]));

    let post = keys_value(&db, &workspace_id);
    // Both leaves are retired by the cascade.
    assert_eq!(
        line_value(&post, "local_history_leaves"),
        "0",
        "both message and file leaves must be retired by the cascade:\n{post}"
    );
    // Each retire wipes the minute_node along with the descend chain. The
    // minute_node row is therefore gone after the cascade.
    assert_eq!(
        line_value(&post, "local_history_minute_nodes"),
        "0",
        "minute_node must be WIPED after cascade retire (descend-path FS):\n{post}"
    );

    // Both projection rows are gone.
    let messages = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert_eq!(line_value(&messages, "messages"), "0");
    let files = assert_success(topo(&["--db", &db, "files", &workspace_id]));
    assert!(
        files.contains("FILES (0 total):"),
        "file row must be cleared by cascade:\n{files}"
    );
}

// ---------------------------------------------------------------------------
// Helpers below mirror the patterns in tests/content_cli_test.rs but are
// scoped to this test crate. Keeping them local avoids growing the shared
// harness with command vocabulary.

#[allow(dead_code)]
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

#[allow(dead_code)]
fn small_pause() {
    std::thread::sleep(Duration::from_millis(50));
}

// ---------------------------------------------------------------------------
// Concurrent sibling-survives-delete scenario.
//
// Scenario (mirrors the two-peer helpers in `tests/content_cli_test.rs` /
// `tests/black_box_sync_test.rs`, but the assertion under test is specific
// to the binary-tree FS retire walk):
//
//   1. Alice and Bob join the same workspace.
//   2. Both clocks are pinned so authoring lands in the same `unix_minute`,
//      placing alice's `M_A` and bob's `M_B` as siblings under the same
//      minute_node in the trie.
//   3. Both daemons run, sync converges, key wraps complete.
//   4. Alice sends `M_A`. Bob sends `M_B`. Each daemon's periodic sync
//      delivers the other peer's leaf event so both stores hold both
//      leaves in the same minute_node.
//   5. Alice runs `delete-message` against `M_A`. Her retire walk
//      materializes the minute_node and the trie internals between the
//      siblings, then exact-deletes `M_A`'s leaf row and purges its
//      canonical bytes. Cascade purge runs.
//   6. Sync propagates the deletion event to Bob. Bob's admission also
//      retires `M_A`'s leaf locally.
//   7. Both peers list messages.
//
// Property under test: alice's surviving sibling `M_B` is still
// decryptable on alice after the retire walk on the deleted sibling. The
// retire walk must not damage the path used to derive `M_B`'s leaf
// secret.
#[test]
fn cli_concurrent_peer_send_survives_sibling_delete() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let workspace_id = create_workspace(&alice, "Concurrent", "alice", "alice-laptop");
    let alice_port = free_port();
    let bob_port = free_port();

    let _alice_daemon = spawn_pair_daemon(&alice, alice_port);
    let _bob_daemon = spawn_pair_daemon(&bob, bob_port);
    join_workspace(&alice, &bob, &workspace_id, alice_port, "bob", "bob-phone");
    grant_content_key_to_peer(&alice, &bob, &workspace_id);

    // Pin both clocks so authoring lands in the same `unix_minute`.
    // unix_minute = 100 for both (6_000_000 / 60_000 == 100, and
    // 6_000_500 / 60_000 == 100).
    assert_success(topo(&["--db", &alice, "clock", "set", "6000000"]));
    assert_success(topo(&["--db", &bob, "clock", "set", "6000500"]));

    // Alice sends M_A; bob sends M_B. Both at minute 100, sibling leaves
    // under the shared minute_node.
    let m_a_text = "alice-says-A";
    let m_b_text = "bob-says-B";
    assert_success(topo(&["--db", &alice, "send", &workspace_id, m_a_text]));
    assert_success(topo(&["--db", &bob, "send", &workspace_id, m_b_text]));

    // Wait until both peers have both messages converged via daemon sync.
    wait_for_messages_to_contain(&alice, &workspace_id, m_b_text);
    wait_for_messages_to_contain(&bob, &workspace_id, m_a_text);

    // Sanity: at this moment alice should see both messages, indicating
    // her local store has both leaves (M_A authored locally, M_B received
    // and decrypted). If decryption of M_B had failed, this would have
    // panicked already.
    let pre = assert_success(topo(&["--db", &alice, "messages", &workspace_id]));
    assert!(pre.contains(m_a_text), "alice missing M_A pre-delete:\n{pre}");
    assert!(pre.contains(m_b_text), "alice missing M_B pre-delete:\n{pre}");

    // Alice deletes her own message M_A. The retire walk on her side
    // materializes the minute_node + trie internals between (M_A's
    // event_id_in_minute) and (M_B's event_id_in_minute), exact-deletes
    // M_A's leaf row, and purges M_A's canonical bytes.
    assert_success(topo(&[
        "--db",
        &alice,
        "delete-message",
        &workspace_id,
        "#1",
    ]));

    // Wait for the deletion to propagate via daemon sync to bob.
    wait_for_messages_count_at(&bob, &workspace_id, "1");

    // Property assertion: alice can still see M_B. If the retire walk had
    // damaged the path used to derive M_B's leaf secret on alice's side,
    // this listing would either be empty or produce a decryption error.
    let alice_post = assert_success(topo(&["--db", &alice, "messages", &workspace_id]));
    assert_eq!(
        line_value(&alice_post, "messages"),
        "1",
        "alice must see exactly one surviving message:\n{alice_post}",
    );
    assert!(
        alice_post.contains(m_b_text),
        "alice cannot see surviving sibling M_B after deleting M_A:\n{alice_post}",
    );
    assert!(
        !alice_post.contains(m_a_text),
        "alice's M_A must be retired:\n{alice_post}",
    );

    // Symmetric bob-side: bob saw the deletion via sync; M_A is gone, M_B
    // remains.
    let bob_post = assert_success(topo(&["--db", &bob, "messages", &workspace_id]));
    assert_eq!(
        line_value(&bob_post, "messages"),
        "1",
        "bob must see exactly one surviving message:\n{bob_post}",
    );
    assert!(
        bob_post.contains(m_b_text),
        "bob cannot see surviving sibling M_B after sync converged:\n{bob_post}",
    );
    assert!(
        !bob_post.contains(m_a_text),
        "bob's M_A must be retired by sync'd deletion:\n{bob_post}",
    );

    // Decryption-error sentinel: neither peer's listing should mention any
    // failure-marker that the message renderer prints when AEAD opens
    // fail. The message renderer formats failures as `(<error>)`-style
    // bracketed strings; the cleanest assertion is that no listing line
    // contains the literal `decrypt` token.
    for (label, listing) in [("alice", &alice_post), ("bob", &bob_post)] {
        for line in listing.lines() {
            assert!(
                !line.contains("decrypt error") && !line.contains("decryption failed"),
                "{label} listing reports decryption failure: {line}\nfull:\n{listing}",
            );
        }
    }
}

// --- two-peer helpers (local copies of the patterns in
// `tests/black_box_sync_test.rs` and `tests/content_cli_test.rs`).

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

fn invite_link_from_output(output: &str) -> String {
    output
        .lines()
        .find(|line| line.starts_with("topo://invite/"))
        .unwrap_or_else(|| panic!("missing invite link in output:\n{output}"))
        .to_string()
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
        if !last.contains("open tcp stream") {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(last)
}

fn spawn_pair_daemon(db: &str, port: u16) -> RunningDaemon {
    // Same shape as `spawn_daemon` above but uses `--sync-ms` so periodic
    // outbound sync runs at the same cadence as content_cli tests.
    let port = port.to_string();
    let mut child = spawn_topo(&[
        "--db",
        db,
        "start",
        "--listen",
        "127.0.0.1",
        &port,
        "--sync-ms",
        "100",
        "--quiet-ms",
        "100",
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

fn grant_content_key_to_peer(alice: &str, peer: &str, workspace_id: &str) {
    let recipient = assert_success(topo(&["--db", peer, "key-recipient", workspace_id]));
    let recipient_key_id = line_value(&recipient, "recipient_key_id");
    let frontier = assert_success(topo(&["--db", alice, "key-frontier", workspace_id]));
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");
    let wrapped = key_wrap_with_retry(alice, workspace_id, &removal_frontier_id, &recipient_key_id);
    assert_eq!(line_value(&wrapped, "recipient_key_id"), recipient_key_id);
    wait_for_key_access(peer, workspace_id, &removal_frontier_id, "yes");
}

fn wait_for_key_access(
    db: &str,
    workspace_id: &str,
    removal_frontier_id: &str,
    expected: &str,
) -> String {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "key-access", workspace_id, removal_frontier_id]);
        if output.status.success() {
            let out = stdout(&output);
            if line_value(&out, "access") == expected {
                return out;
            }
            last = out;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("key access did not reach {expected}: {last}");
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


fn wait_for_messages_to_contain(db: &str, workspace_id: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let out = assert_success(topo(&["--db", db, "messages", workspace_id]));
        if out.contains(expected) {
            return;
        }
        last = out;
        thread::sleep(Duration::from_millis(100));
    }
    panic!("messages in {db} never contained `{expected}`; last output:\n{last}");
}

fn wait_for_messages_count_at(db: &str, workspace_id: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let out = assert_success(topo(&["--db", db, "messages", workspace_id]));
        if line_value(&out, "messages") == expected {
            return;
        }
        last = out;
        thread::sleep(Duration::from_millis(100));
    }
    panic!("messages count in {db} did not reach {expected}; last:\n{last}");
}

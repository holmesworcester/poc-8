//! Black-box CLI tests for content events.
//!
//! Setup deliberately goes through the real `topo` binary: workspace creation,
//! invite listening, invite acceptance, connection learning, sync, and content
//! commands. These tests must not install identity graphs or content rows by
//! importing protocol/store internals.

mod cli_harness;

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::process::Child;
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use cli_harness::*;

#[test]
fn cli_send_then_messages_lists_authored_messages() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Content", "alice", "alice-laptop");
    assert_success(topo(&["--db", &db, "key-frontier", &workspace_id]));

    let send1 = assert_success(topo(&["--db", &db, "send", &workspace_id, "first message"]));
    assert!(send1.contains("text: first message"), "{send1}");

    let send2 = assert_success(topo(&[
        "--db",
        &db,
        "send",
        &workspace_id,
        "second message",
    ]));
    assert!(send2.contains("text: second message"), "{send2}");

    let listing = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert_eq!(line_value(&listing, "messages"), "2");
    assert!(listing.contains("alice: first message"), "{listing}");
    assert!(listing.contains("alice: second message"), "{listing}");
}

#[test]
fn cli_react_appears_in_messages_listing() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Content", "alice", "alice-laptop");
    assert_success(topo(&["--db", &db, "key-frontier", &workspace_id]));

    assert_success(topo(&["--db", &db, "send", &workspace_id, "hello"]));
    let react = assert_success(topo(&["--db", &db, "react", &workspace_id, "#1", "+1"]));
    assert!(react.contains("emoji: +1"), "{react}");

    let listing = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert!(listing.contains("reactions: +1"), "{listing}");
}

#[test]
fn cli_delete_message_purges_target_from_listing() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Content", "alice", "alice-laptop");
    assert_success(topo(&["--db", &db, "key-frontier", &workspace_id]));

    assert_success(topo(&["--db", &db, "send", &workspace_id, "regret"]));
    assert_success(topo(&["--db", &db, "react", &workspace_id, "#1", "ack"]));

    let before = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert!(!before.contains("(deleted)"), "{before}");

    let deleted = assert_success(topo(&["--db", &db, "delete-message", &workspace_id, "#1"]));
    assert!(deleted.contains("event_id:"), "{deleted}");

    let after = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert_eq!(line_value(&after, "messages"), "0");
    assert!(!after.contains("(deleted)"), "{after}");
    assert!(!after.contains("regret"), "{after}");
}

#[test]
fn cli_send_file_then_save_file_round_trips_bytes_through_real_binary() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Content", "alice", "alice-laptop");
    assert_success(topo(&["--db", &db, "key-frontier", &workspace_id]));

    let payload: Vec<u8> = (0..8192u32).map(|byte| byte as u8).collect();
    let in_path = tmp.path().join("input.bin");
    fs::write(&in_path, &payload).expect("write input");

    let sent = assert_success(topo(&[
        "--db",
        &db,
        "send-file",
        &workspace_id,
        "see attached",
        "--file",
        in_path.to_str().expect("path utf-8"),
    ]));
    assert!(sent.contains("filename: input.bin"), "{sent}");
    assert_eq!(line_value(&sent, "blob_bytes"), "8192");
    let file_event_id = line_value(&sent, "file_event_id");

    let files = assert_success(topo(&["--db", &db, "files", &workspace_id]));
    assert_eq!(line_value(&files, "files"), "1");
    assert!(files.contains("input.bin"), "{files}");

    let messages = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert!(
        messages.contains("see attached") && messages.contains("file: input.bin"),
        "{messages}"
    );

    let out_path = tmp.path().join("out.bin");
    let saved = assert_success(topo(&[
        "--db",
        &db,
        "save-file",
        &workspace_id,
        "#1",
        out_path.to_str().expect("path utf-8"),
    ]));
    assert_eq!(line_value(&saved, "filename"), "input.bin");
    assert_eq!(line_value(&saved, "bytes_written"), "8192");

    let read_back = fs::read(&out_path).expect("read output");
    assert_eq!(read_back, payload);

    assert_success(topo(&["--db", &db, "delete-message", &workspace_id, "#1"]));
    let messages_after_delete = assert_success(topo(&["--db", &db, "messages", &workspace_id]));
    assert_eq!(line_value(&messages_after_delete, "messages"), "0");
    let files_after_delete = assert_success(topo(&["--db", &db, "files", &workspace_id]));
    assert_eq!(line_value(&files_after_delete, "files"), "0");

    let hidden_save = topo(&[
        "--db",
        &db,
        "save-file",
        &workspace_id,
        &file_event_id,
        out_path.to_str().expect("path utf-8"),
    ]);
    assert!(
        !hidden_save.status.success(),
        "deleted parent message must hide direct file saves\nstdout={}\nstderr={}",
        stdout(&hidden_save),
        stderr(&hidden_save)
    );
}

#[test]
fn cli_messages_and_reactions_sync_between_two_peers() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let workspace_id = create_workspace(&alice, "Shared", "alice", "alice-laptop");
    let invite_port = free_port();
    let alice_port = free_port();
    let bob_port = free_port();

    join_workspace(&alice, &bob, &workspace_id, invite_port, "bob", "bob-phone");
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    connect_daemon_pair(&alice, alice_port, &bob, bob_port);
    grant_content_key_to_peer(&alice, &bob, &workspace_id);

    assert_success(topo(&["--db", &alice, "send", &workspace_id, "from alice"]));
    assert_success(topo(&[
        "--db",
        &alice,
        "react",
        &workspace_id,
        "#1",
        "seen",
    ]));

    wait_for_messages_count(&bob, &workspace_id, "1");
    wait_for_messages_contains(&bob, &workspace_id, "reactions: seen");
    let bob_listing = assert_success(topo(&["--db", &bob, "messages", &workspace_id]));
    assert_eq!(line_value(&bob_listing, "messages"), "1");
    assert!(bob_listing.contains("alice: from alice"), "{bob_listing}");
    assert!(bob_listing.contains("reactions: seen"), "{bob_listing}");
}

#[test]
fn cli_send_file_syncs_bytes_to_peer_for_save() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let workspace_id = create_workspace(&alice, "Files", "alice", "alice-laptop");
    let invite_port = free_port();
    let alice_port = free_port();
    let bob_port = free_port();

    join_workspace(&alice, &bob, &workspace_id, invite_port, "bob", "bob-phone");
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    connect_daemon_pair(&alice, alice_port, &bob, bob_port);
    grant_content_key_to_peer(&alice, &bob, &workspace_id);

    let payload: Vec<u8> = (0..4096u32).map(|byte| byte as u8).collect();
    let in_path = tmp.path().join("payload.bin");
    fs::write(&in_path, &payload).expect("write input");

    assert_success(topo(&[
        "--db",
        &alice,
        "send-file",
        &workspace_id,
        "see attached",
        "--file",
        in_path.to_str().expect("path"),
    ]));

    wait_for_files_count(&bob, &workspace_id, "1");
    let listing = assert_success(topo(&["--db", &bob, "files", &workspace_id]));
    assert_eq!(line_value(&listing, "files"), "1");
    let out_path = tmp.path().join("out.bin");
    let saved = wait_for_save_file(&bob, &workspace_id, "#1", out_path.to_str().expect("path"));
    assert_eq!(line_value(&saved, "filename"), "payload.bin");
    let read_back = fs::read(&out_path).expect("read output");
    assert_eq!(read_back, payload);
}

#[test]
fn cli_deleted_message_key_is_unrecoverable_after_path_tombstone() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&db, "Content", "alice", "alice-laptop");
    assert_success(topo(&["--db", &db, "key-frontier", &workspace_id]));

    let send = assert_success(topo(&["--db", &db, "send", &workspace_id, "secret note"]));
    let message_id_hex = line_value(&send, "event_id");

    // Read out the leaf id and intermediate id from `keys`. The keys command
    // lists every history node row keyed by frontier; we must capture both
    // ids before deletion so we can prove they are gone afterwards.
    let keys_before = assert_success(topo(&["--db", &db, "keys", &workspace_id]));
    let history_nodes_before: Vec<&str> = keys_before
        .lines()
        .filter(|line| line.starts_with("history_node:"))
        .collect();
    assert_eq!(
        history_nodes_before.len(),
        2,
        "expected leaf and intermediate path-node before deletion: {keys_before}"
    );
    let leaf_id_hex = node_id_from_keys_line(&history_nodes_before, 1, "width=1")
        .expect("leaf id from keys before delete");
    let intermediate_id_hex = node_id_from_keys_line(&history_nodes_before, 2, "width=2")
        .expect("intermediate id from keys before delete");

    let leaf_id = decode_hex_id(&leaf_id_hex);
    let intermediate_id = decode_hex_id(&intermediate_id_hex);
    let message_id = decode_hex_id(&message_id_hex);

    // The leaf event must currently sit in event_modules.events with its
    // plaintext node_secret. If it does not, the rest of this test is
    // vacuous, so assert it explicitly first.
    assert!(
        event_id_present(&db, &leaf_id),
        "leaf event must exist before deletion"
    );
    assert!(
        event_id_present(&db, &intermediate_id),
        "intermediate event must exist before deletion"
    );

    let deleted = assert_success(topo(&["--db", &db, "delete-message", &workspace_id, "#1"]));
    assert!(deleted.contains("event_id:"), "{deleted}");

    // (a) ciphertext gone — the message bytes have been purged from
    // event_modules.events by content_purge.
    assert!(
        !event_id_present(&db, &message_id),
        "message ciphertext must be purged from event_modules.events after deletion"
    );
    // (b) leaf gone from event_modules.events — purged by retire_deleted_message_leaf
    assert!(
        !event_id_present(&db, &leaf_id),
        "deleted message leaf must be purged from event_modules.events"
    );
    // (c) every path-node from leaf to root is gone. In this fork the
    // single-level intermediate at width=2 is the only path-node node-event
    // between the leaf and the local_key_secret root. The local_key_secret
    // root is workspace-shared and intentionally retained.
    assert!(
        !event_id_present(&db, &intermediate_id),
        "deleted message intermediate path-node must be purged from event_modules.events"
    );
}

#[test]
fn cli_other_messages_in_frontier_remain_readable_after_one_delete() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let workspace_id = create_workspace(&alice, "Shared", "alice", "alice-laptop");
    let invite_port = free_port();
    let alice_port = free_port();
    let bob_port = free_port();

    join_workspace(&alice, &bob, &workspace_id, invite_port, "bob", "bob-phone");
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    connect_daemon_pair(&alice, alice_port, &bob, bob_port);
    grant_content_key_to_peer(&alice, &bob, &workspace_id);

    assert_success(topo(&["--db", &alice, "send", &workspace_id, "first"]));
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "second"]));

    wait_for_messages_count(&bob, &workspace_id, "2");

    // Delete the first message on alice. Bob's daemon will sync the deletion.
    assert_success(topo(&["--db", &alice, "delete-message", &workspace_id, "#1"]));

    // Bob should eventually see the deletion: 1 message left, "second"
    // remains readable. Wait, then assert.
    wait_for_messages_count(&bob, &workspace_id, "1");
    let bob_listing = assert_success(topo(&["--db", &bob, "messages", &workspace_id]));
    assert_eq!(line_value(&bob_listing, "messages"), "1");
    assert!(
        bob_listing.contains("alice: second"),
        "bob's surviving message must still be decryptable: {bob_listing}",
    );
    assert!(
        !bob_listing.contains("first"),
        "deleted message must not appear in bob's listing: {bob_listing}",
    );
}

#[test]
fn cli_received_message_blocks_until_local_history_node_secret_is_derived() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let workspace_id = create_workspace(&alice, "Blocking", "alice", "alice-laptop");
    let invite_port = free_port();
    let alice_port = free_port();
    let bob_port = free_port();

    join_workspace(&alice, &bob, &workspace_id, invite_port, "bob", "bob-phone");
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    connect_daemon_pair(&alice, alice_port, &bob, bob_port);
    grant_content_key_to_peer(&alice, &bob, &workspace_id);

    // alice sends a message; bob's daemon must auto-derive the per-message
    // leaf and unblock the message before display. The CLI will still show
    // exactly one decrypted message once derivation lands. If derivation
    // never happened on bob, this assertion would time out.
    assert_success(topo(&["--db", &alice, "send", &workspace_id, "blockcheck"]));
    wait_for_messages_contains(&bob, &workspace_id, "alice: blockcheck");

    // Inspect bob's keys to confirm the daemon's encryption_message_leaves
    // worker actually produced a leaf history node row, rather than relying
    // on side-effects of any other admission path.
    let bob_keys = assert_success(topo(&["--db", &bob, "keys", &workspace_id]));
    let history_nodes: Vec<&str> = bob_keys
        .lines()
        .filter(|line| line.starts_with("history_node:"))
        .collect();
    assert!(
        history_nodes.iter().any(|line| line.contains("width=1")),
        "bob must have at least one width=1 leaf node after auto-derivation: {bob_keys}",
    );
    assert!(
        history_nodes.iter().any(|line| line.contains("width=2")),
        "bob must have at least one width=2 intermediate after auto-derivation: {bob_keys}",
    );
}

#[test]
fn cli_receiver_cannot_decrypt_after_path_tombstone_replays_old_event() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let workspace_id = create_workspace(&alice, "Forward", "alice", "alice-laptop");
    let invite_port = free_port();
    let alice_port = free_port();
    let bob_port = free_port();

    join_workspace(&alice, &bob, &workspace_id, invite_port, "bob", "bob-phone");
    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    connect_daemon_pair(&alice, alice_port, &bob, bob_port);
    grant_content_key_to_peer(&alice, &bob, &workspace_id);

    let send = assert_success(topo(&["--db", &alice, "send", &workspace_id, "rewindable"]));
    let message_id_hex = line_value(&send, "event_id");
    let message_id = decode_hex_id(&message_id_hex);

    wait_for_messages_contains(&bob, &workspace_id, "alice: rewindable");
    // Capture bob's pre-delete state. If we replay the message canonical
    // bytes against this snapshot AFTER the tombstone runs, decryption must
    // fail — proving forward secrecy through the HKDF range tree.
    let pre_delete_message_bytes = read_event_canonical_bytes(&bob, &message_id);
    let pre_delete_keys = assert_success(topo(&["--db", &bob, "keys", &workspace_id]));
    let bob_history_nodes: Vec<&str> = pre_delete_keys
        .lines()
        .filter(|line| line.starts_with("history_node:"))
        .collect();
    let bob_intermediate_id_hex = node_id_from_keys_line(&bob_history_nodes, 2, "width=2")
        .expect("bob's intermediate before delete");
    let bob_intermediate_id = decode_hex_id(&bob_intermediate_id_hex);
    assert!(
        event_id_present(&bob, &bob_intermediate_id),
        "bob's intermediate path-node event must be present pre-delete"
    );

    // alice deletes the message; bob's daemon receives the deletion and runs
    // content_purge -> RetireDeletedMessageLeaf.
    assert_success(topo(&["--db", &alice, "delete-message", &workspace_id, "#1"]));
    wait_for_messages_count(&bob, &workspace_id, "0");
    // The retire pass that purges the intermediate's canonical bytes runs in
    // a follow-up worker step after the deletion event projects on bob.
    // Wait until bob's intermediate path-node is gone before asserting,
    // because purge is bounded per-tick by the daemon scheduler.
    wait_for_event_absent(&bob, &bob_intermediate_id);

    // Bob's intermediate and leaf events must be purged from event_modules.events
    // (forward-secrecy property): the parent path-node bytes are gone, so
    // even an attacker holding the captured ciphertext + bob's previous
    // local key state cannot re-derive the leaf node_secret to decrypt the
    // captured ciphertext.
    assert!(
        !event_id_present(&bob, &bob_intermediate_id),
        "bob's intermediate path-node event must be purged after the path tombstone runs"
    );
    // The leaf canonical bytes are also gone from bob's event_modules.events.
    // We check that the captured pre-delete message ciphertext bytes do not
    // appear anywhere in bob's events table any more — the only retained
    // copy was the message envelope, and the deletion projected its purge.
    let bob_payloads = all_event_payloads(&bob);
    for (key, value) in &bob_payloads {
        assert!(
            !contains_subsequence(value, &pre_delete_message_bytes),
            "no row_value should still embed the deleted message canonical bytes (offending row_key={})",
            hex(key),
        );
    }
}

fn node_id_from_keys_line(
    history_nodes: &[&str],
    _expected_count: usize,
    width_marker: &str,
) -> Option<String> {
    history_nodes
        .iter()
        .find(|line| line.contains(width_marker))
        .and_then(|line| {
            // Format: "history_node: <id_hex> frontier=<id_hex> start=<n> width=<n> tombstones=..."
            let after_prefix = line.strip_prefix("history_node: ")?;
            let id = after_prefix.split_whitespace().next()?;
            Some(id.to_string())
        })
}

fn decode_hex_id(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len(), 64, "event ids are 32-byte hex strings");
    let mut out = Vec::with_capacity(32);
    let bytes = hex.as_bytes();
    for chunk in 0..32 {
        let high = decode_hex_nibble(bytes[chunk * 2]);
        let low = decode_hex_nibble(bytes[chunk * 2 + 1]);
        out.push((high << 4) | low);
    }
    out
}

fn decode_hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex digit: {byte}"),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

fn wait_for_event_absent(db: &str, event_id: &[u8]) {
    for _ in 0..300 {
        if !event_id_present(db, event_id) {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "event {} never disappeared from {db} event_modules.events",
        hex(event_id)
    );
}

fn event_id_present(db: &str, event_id: &[u8]) -> bool {
    let conn = rusqlite::Connection::open(db).expect("open db");
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM \"event_modules.events\" WHERE row_key = ?1",
            rusqlite::params![event_id],
            |row| row.get(0),
        )
        .expect("count rows");
    count > 0
}

fn all_event_payloads(db: &str) -> Vec<(Vec<u8>, Vec<u8>)> {
    let conn = rusqlite::Connection::open(db).expect("open db");
    let mut stmt = conn
        .prepare("SELECT row_key, row_value FROM \"event_modules.events\"")
        .expect("prepare");
    stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("query")
        .map(|item| item.expect("row"))
        .collect()
}

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn read_event_canonical_bytes(db: &str, event_id: &[u8]) -> Vec<u8> {
    let conn = rusqlite::Connection::open(db).expect("open db");
    let bytes: Vec<u8> = conn
        .query_row(
            "SELECT row_value FROM \"event_modules.events\" WHERE row_key = ?1",
            rusqlite::params![event_id],
            |row| row.get(0),
        )
        .expect("event row");
    canonical_bytes_from_event_row(&bytes)
}

fn canonical_bytes_from_event_row(value: &[u8]) -> Vec<u8> {
    let mut offset = 0;
    offset += 8; // timestamp
    offset += 8; // body_len
    offset += 1; // first byte of event id
    offset += 1; // scope
    offset += 1; // status
    let has_workspace = value[offset] != 0;
    offset += 1;
    if has_workspace {
        offset += 32;
    }
    value[offset..].to_vec()
}

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

fn join_workspace(
    host: &str,
    joiner: &str,
    workspace_id: &str,
    port: u16,
    username: &str,
    device_name: &str,
) {
    let mut listener = spawn_workspace_invite_listener(host, workspace_id, port, 1);
    let invite = listener.invite_link();
    let accepted = match try_accept_with_identity_retry(joiner, &invite, username, device_name) {
        Ok(output) => output,
        Err(err) => listener.fail("workspace invite accept failed", err),
    };
    assert_eq!(line_value(&accepted, "workspace_id"), workspace_id);
    let host_out = listener.wait_success("workspace invite listener");
    assert!(host_out.contains("accepted_connections: 1"), "{host_out}");
}

struct ListeningInvite {
    child: Child,
    invite_rx: Receiver<Result<String, String>>,
    stdout: JoinHandle<String>,
    stderr: JoinHandle<String>,
}

impl ListeningInvite {
    fn invite_link(&mut self) -> String {
        match self.invite_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(line)) => {
                assert!(
                    line.starts_with("topo://invite/"),
                    "missing invite link in first listener line: {line}"
                );
                thread::sleep(Duration::from_millis(50));
                line
            }
            Ok(Err(err)) => {
                let _ = self.child.kill();
                panic!("listener did not print invite link: {err}");
            }
            Err(err) => {
                let _ = self.child.kill();
                panic!("timed out waiting for invite link: {err}");
            }
        }
    }

    fn wait_success(mut self, label: &str) -> String {
        let status = self.child.wait().expect("wait for listener");
        let stdout = self.stdout.join().expect("join stdout reader");
        let stderr = self.stderr.join().expect("join stderr reader");
        assert!(
            status.success(),
            "{label} failed\nstdout={stdout}\nstderr={stderr}"
        );
        stdout
    }

    fn fail(mut self, label: &str, err: String) -> ! {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let stdout = self.stdout.join().expect("join stdout reader");
        let stderr = self.stderr.join().expect("join stderr reader");
        panic!("{label}: {err}\nlistener stdout:\n{stdout}\nlistener stderr:\n{stderr}");
    }
}

fn spawn_workspace_invite_listener(
    db: &str,
    workspace_id: &str,
    port: u16,
    accept: usize,
) -> ListeningInvite {
    let port = port.to_string();
    let accept = accept.to_string();
    let child = spawn_topo(&[
        "--db",
        db,
        "invite",
        "--workspace",
        workspace_id,
        "--listen",
        "127.0.0.1",
        &port,
        "--accept",
        &accept,
    ]);
    listening_invite_from_child(child)
}

fn listening_invite_from_child(mut child: Child) -> ListeningInvite {
    let stdout = child.stdout.take().expect("listener stdout");
    let stderr = child.stderr.take().expect("listener stderr");
    let (invite_tx, invite_rx) = mpsc::channel();
    let stdout = thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut output = String::new();
        let mut first = String::new();
        match reader.read_line(&mut first) {
            Ok(0) => {
                let _ = invite_tx.send(Err("stdout closed before first line".to_string()));
            }
            Ok(_) => {
                output.push_str(&first);
                let link = first.trim_end_matches(['\r', '\n']).to_string();
                let _ = invite_tx.send(Ok(link));
            }
            Err(err) => {
                let _ = invite_tx.send(Err(err.to_string()));
            }
        }

        let mut rest = String::new();
        if reader.read_to_string(&mut rest).is_ok() {
            output.push_str(&rest);
        }
        output
    });
    let stderr = thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut output = String::new();
        let _ = reader.read_to_string(&mut output);
        output
    });
    ListeningInvite {
        child,
        invite_rx,
        stdout,
        stderr,
    }
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

fn grant_content_key_to_peer(alice: &str, peer: &str, workspace_id: &str) {
    let recipient = assert_success(topo(&["--db", peer, "key-recipient", workspace_id]));
    let recipient_key_id = line_value(&recipient, "recipient_key_id");
    let frontier = assert_success(topo(&["--db", alice, "key-frontier", workspace_id]));
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");
    let wrapped = key_wrap_with_retry(alice, workspace_id, &removal_frontier_id, &recipient_key_id);
    assert_eq!(line_value(&wrapped, "recipient_key_id"), recipient_key_id);
    let derived = wait_for_key_derive(peer, "1");
    assert_eq!(line_value(&derived, "derived_key_secrets"), "1");
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

fn wait_for_key_derive(db: &str, expected: &str) -> String {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "key-derive"]);
        if output.status.success() {
            let out = stdout(&output);
            if line_value(&out, "derived_key_secrets") == expected {
                return out;
            }
            last = out;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("key derive did not reach {expected}: {last}");
}

fn invite_link_from_output(output: &str) -> String {
    output
        .lines()
        .find(|line| line.starts_with("topo://invite/"))
        .unwrap_or_else(|| panic!("missing invite link in output:\n{output}"))
        .to_string()
}

fn wait_for_messages_count(db: &str, workspace_id: &str, expected: &str) {
    wait_for_count(db, "messages", workspace_id, "messages", expected);
}

fn wait_for_files_count(db: &str, workspace_id: &str, expected: &str) {
    wait_for_count(db, "files", workspace_id, "files", expected);
}

fn wait_for_messages_contains(db: &str, workspace_id: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let out = assert_success(topo(&["--db", db, "messages", workspace_id]));
        if out.contains(expected) {
            return;
        }
        last = out;
        thread::sleep(Duration::from_millis(100));
    }
    panic!("messages never contained `{expected}`; last output:\n{last}");
}

fn wait_for_save_file(db: &str, workspace_id: &str, selector: &str, out_path: &str) -> String {
    let mut last = String::new();
    for _ in 0..300 {
        let output = topo(&["--db", db, "save-file", workspace_id, selector, out_path]);
        if output.status.success() {
            return stdout(&output);
        }
        last = stderr(&output);
        thread::sleep(Duration::from_millis(100));
    }
    panic!("save-file never succeeded; last stderr:\n{last}");
}

fn wait_for_count(db: &str, command: &str, workspace_id: &str, key: &str, expected: &str) {
    let mut last = String::new();
    for _ in 0..300 {
        let out = assert_success(topo(&["--db", db, command, workspace_id]));
        if line_value(&out, key) == expected {
            return;
        }
        last = out;
        thread::sleep(Duration::from_millis(100));
    }
    panic!("{command} count did not reach {expected}; last output:\n{last}");
}

//! Black-box CLI tests for encryption key availability.
//!
//! Setup goes through the real `topo` binary: workspace creation, invite
//! listening, invite acceptance, transport connection learning, sync, key
//! publication, wrap creation, and derivation. The tests intentionally do not
//! seed protocol rows or call workers directly; the CLI boundary is the
//! invariant under test.

mod cli_harness;

use std::io::{BufRead, BufReader, Read};
use std::process::Child;
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use cli_harness::*;

#[test]
fn cli_key_wrap_derives_access_only_for_wrapped_recipient() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let carol = temp_db(&tmp, "carol.db");
    let workspace_id = create_workspace(&alice, "Keys", "alice", "alice-laptop");
    let bob_join_port = free_port();
    let carol_join_port = free_port();
    let alice_port = free_port();
    let bob_port = free_port();
    let carol_port = free_port();

    join_workspace(
        &alice,
        &bob,
        &workspace_id,
        bob_join_port,
        "bob",
        "bob-phone",
    );
    join_workspace(
        &alice,
        &carol,
        &workspace_id,
        carol_join_port,
        "carol",
        "carol-tablet",
    );

    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _bob_daemon = spawn_daemon(&bob, bob_port);
    let _carol_daemon = spawn_daemon(&carol, carol_port);
    connect_daemon_pair(&alice, alice_port, &bob, bob_port);
    connect_daemon_pair(&alice, alice_port, &carol, carol_port);

    let bob_recipient = assert_success(topo(&["--db", &bob, "key-recipient", &workspace_id]));
    let bob_recipient_id = line_value(&bob_recipient, "recipient_key_id");
    assert_success(topo(&["--db", &carol, "key-recipient", &workspace_id]));

    let frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");
    assert_eq!(
        line_value(
            &assert_success(topo(&[
                "--db",
                &alice,
                "key-access",
                &workspace_id,
                &removal_frontier_id,
            ])),
            "access",
        ),
        "yes"
    );

    thread::sleep(Duration::from_millis(1200));
    assert_eq!(
        line_value(
            &assert_success(topo(&[
                "--db",
                &bob,
                "key-access",
                &workspace_id,
                &removal_frontier_id,
            ])),
            "access",
        ),
        "no"
    );
    assert_eq!(
        line_value(
            &assert_success(topo(&[
                "--db",
                &carol,
                "key-access",
                &workspace_id,
                &removal_frontier_id,
            ])),
            "access",
        ),
        "no"
    );

    let wrapped = key_wrap_with_retry(
        &alice,
        &workspace_id,
        &removal_frontier_id,
        &bob_recipient_id,
    );
    assert_eq!(line_value(&wrapped, "recipient_key_id"), bob_recipient_id);

    let bob_derive = wait_for_key_derive(&bob, "1");
    assert_eq!(line_value(&bob_derive, "derived_key_secrets"), "1");
    assert_eq!(
        line_value(
            &assert_success(topo(&[
                "--db",
                &bob,
                "key-access",
                &workspace_id,
                &removal_frontier_id,
            ])),
            "access",
        ),
        "yes"
    );

    let carol_derive = assert_success(topo(&["--db", &carol, "key-derive"]));
    assert_eq!(line_value(&carol_derive, "derived_key_secrets"), "0");
    assert_eq!(
        line_value(
            &assert_success(topo(&[
                "--db",
                &carol,
                "key-access",
                &workspace_id,
                &removal_frontier_id,
            ])),
            "access",
        ),
        "no"
    );
}

#[test]
fn cli_invite_server_syncs_but_cannot_be_a_key_recipient() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let server = temp_db(&tmp, "invite-server.db");
    let workspace_id = create_workspace(&alice, "Helper FS", "alice", "alice-laptop");
    let server_join_port = free_port();
    let alice_port = free_port();
    let server_port = free_port();

    join_invite_server(&alice, &server, &workspace_id, server_join_port, "relay");
    let server_identity = assert_success(topo(&["--db", &server, "identity"]));
    assert!(
        server_identity.contains("endpoint_role=invite-server"),
        "{server_identity}"
    );

    let denied = topo(&["--db", &server, "key-recipient", &workspace_id]);
    assert!(
        !denied.status.success(),
        "invite-server recipient key should be invalid\nstdout={}\nstderr={}",
        stdout(&denied),
        stderr(&denied)
    );
    assert!(
        stderr(&denied).contains("local endpoint role cannot receive key wraps"),
        "{}",
        stderr(&denied)
    );

    let _alice_daemon = spawn_daemon(&alice, alice_port);
    let _server_daemon = spawn_daemon(&server, server_port);
    connect_daemon_pair(&alice, alice_port, &server, server_port);
    assert_success(topo(&[
        "--db",
        &alice,
        "generate",
        &workspace_id,
        "2",
        "64",
    ]));
    wait_for_content_count(&server, &workspace_id, "2");

    let frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");
    thread::sleep(Duration::from_millis(1200));
    let server_derive = assert_success(topo(&["--db", &server, "key-derive"]));
    assert_eq!(line_value(&server_derive, "derived_key_secrets"), "0");
    assert_eq!(
        line_value(
            &assert_success(topo(&[
                "--db",
                &server,
                "key-access",
                &workspace_id,
                &removal_frontier_id,
            ])),
            "access",
        ),
        "no"
    );
}

#[test]
fn cli_rotates_recipient_keys_and_tombstones_history_path_nodes() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&alice, "Fs Keys", "alice", "alice-laptop");

    let first_recipient = assert_success(topo(&["--db", &alice, "key-recipient", &workspace_id]));
    let first_recipient_id = line_value(&first_recipient, "recipient_key_id");
    assert_success(topo(&["--db", &alice, "clock", "set", "70000"]));
    let rotated = assert_success(topo(&[
        "--db",
        &alice,
        "key-rotate-recipient",
        &workspace_id,
    ]));
    assert_eq!(line_value(&rotated, "old_active_recipient_keys"), "1");
    assert_eq!(line_value(&rotated, "tombstoned_recipient_keys"), "1");
    let clock = assert_success(topo(&["--db", &alice, "clock"]));
    assert_eq!(line_value(&clock, "logical_time"), "70000");
    assert_eq!(line_value(&clock, "max_event_timestamp"), "70001");

    let keys = assert_success(topo(&["--db", &alice, "keys", &workspace_id]));
    assert_eq!(line_value(&keys, "recipient_keys"), "1");
    assert_eq!(line_value(&keys, "recipient_key_tombstones"), "1");
    // Rotation purges the retired private key alongside the public tombstone.
    assert_eq!(line_value(&keys, "local_recipient_keys"), "1");

    let advanced = assert_success(topo(&["--db", &alice, "clock", "advance", "1000"]));
    assert_eq!(line_value(&advanced, "next_timestamp"), "71000");
    let frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let clock = assert_success(topo(&["--db", &alice, "clock"]));
    assert_eq!(line_value(&clock, "max_event_timestamp"), "71000");
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");
    let local_key_secret_id = line_value(&frontier, "local_key_secret_id");
    let old_wrap = topo(&[
        "--db",
        &alice,
        "key-wrap",
        &workspace_id,
        &removal_frontier_id,
        &first_recipient_id,
    ]);
    assert!(
        !old_wrap.status.success(),
        "old recipient key should have been purged\nstdout={}\nstderr={}",
        stdout(&old_wrap),
        stderr(&old_wrap)
    );
    assert!(
        stderr(&old_wrap).contains("recipient key is missing"),
        "{}",
        stderr(&old_wrap)
    );

    let root_node = assert_success(topo(&[
        "--db",
        &alice,
        "key-node",
        &workspace_id,
        &removal_frontier_id,
        &local_key_secret_id,
        "0",
        "8",
    ]));
    let root_node_id = line_value(&root_node, "local_history_node_secret_id");
    let keys = assert_success(topo(&["--db", &alice, "keys", &workspace_id]));
    assert_eq!(line_value(&keys, "local_history_node_secrets"), "1");
    assert_eq!(line_value(&keys, "local_history_node_tombstones"), "0");

    let sibling = assert_success(topo(&[
        "--db",
        &alice,
        "key-node",
        &workspace_id,
        &removal_frontier_id,
        &root_node_id,
        "4",
        "4",
        &root_node_id,
    ]));
    assert_eq!(line_value(&sibling, "tombstoned_node_id"), root_node_id);
    let keys = assert_success(topo(&["--db", &alice, "keys", &workspace_id]));
    assert_eq!(line_value(&keys, "local_history_node_secrets"), "1");
    assert_eq!(line_value(&keys, "local_history_node_tombstones"), "1");
    assert!(keys.contains("start=4 width=4"), "{keys}");

    let from_retired_root = topo(&[
        "--db",
        &alice,
        "key-node",
        &workspace_id,
        &removal_frontier_id,
        &root_node_id,
        "0",
        "4",
    ]);
    assert!(
        !from_retired_root.status.success(),
        "retired path node should not derive children\nstdout={}\nstderr={}",
        stdout(&from_retired_root),
        stderr(&from_retired_root)
    );
    // After the tombstone, the retired event's canonical bytes are purged
    // entirely from event_modules.events for forward secrecy. `source_secret_material`
    // therefore reports the source as missing instead of tombstoned; both
    // outcomes correctly reject derivation from a retired path node.
    assert!(
        stderr(&from_retired_root).contains("history node source event is missing"),
        "{}",
        stderr(&from_retired_root)
    );
}

#[test]
fn cli_history_node_tombstone_purges_retired_event_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&alice, "Fs Keys", "alice", "alice-laptop");

    assert_success(topo(&["--db", &alice, "key-recipient", &workspace_id]));
    let frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");
    let local_key_secret_id = line_value(&frontier, "local_key_secret_id");

    let root_node = assert_success(topo(&[
        "--db",
        &alice,
        "key-node",
        &workspace_id,
        &removal_frontier_id,
        &local_key_secret_id,
        "0",
        "8",
    ]));
    let root_node_id = line_value(&root_node, "local_history_node_secret_id");
    assert_eq!(line_value(&root_node, "purged_event_bytes"), "0");

    // Snapshot the parent's plaintext node_secret bytes BEFORE the tombstone is
    // applied. The purge happens at the tombstone step; if the production code
    // only exact-deletes the projection row, the secret bytes would remain in
    // event_modules.events. The test must read those secret bytes through the
    // SQLite layer because the public CLI never exposes raw key material.
    let parent_secret = read_history_node_secret_bytes(&alice, &root_node_id);
    assert_eq!(parent_secret.len(), 32);
    assert!(
        parent_secret.iter().any(|byte| *byte != 0),
        "captured parent node secret should not be zero",
    );

    let sibling = assert_success(topo(&[
        "--db",
        &alice,
        "key-node",
        &workspace_id,
        &removal_frontier_id,
        &root_node_id,
        "4",
        "4",
        &root_node_id,
    ]));
    assert_eq!(line_value(&sibling, "tombstoned_node_id"), root_node_id);
    assert_eq!(line_value(&sibling, "purged_event_bytes"), "1");

    let keys = assert_success(topo(&["--db", &alice, "keys", &workspace_id]));
    assert_eq!(line_value(&keys, "local_history_node_secrets"), "1");
    assert_eq!(line_value(&keys, "local_history_node_tombstones"), "1");

    // SQLite-level: the retired root's event id is gone from `event_modules.events`.
    let root_event_id = decode_hex_id(&root_node_id);
    assert!(
        !event_id_present(&alice, &root_event_id),
        "retired history node event id must be absent from event_modules.events",
    );

    // SQLite-level: the parent's plaintext node_secret cannot be recovered from
    // any row_value in event_modules.events.
    let payloads = all_event_payloads(&alice);
    assert!(
        !payloads.is_empty(),
        "events table should still hold other rows"
    );
    for (key, value) in &payloads {
        assert!(
            !contains_subsequence(value, &parent_secret),
            "no row_value should still embed the retired parent's plaintext node_secret (offending row_key={})",
            hex(key),
        );
    }
}

fn read_history_node_secret_bytes(db: &str, hex_id: &str) -> Vec<u8> {
    let event_id = decode_hex_id(hex_id);
    let conn = rusqlite::Connection::open(db).expect("open db");
    let bytes: Vec<u8> = conn
        .query_row(
            "SELECT row_value FROM \"event_modules.events\" WHERE row_key = ?1",
            rusqlite::params![event_id],
            |row| row.get(0),
        )
        .expect("event row");
    // Decode the stored event-row value: timestamp(u64 BE) + body_len(u64 BE)
    // + first_byte_id(1) + scope(1) + status(1) + workspace_present(1)
    // + workspace(32 if present) + canonical_bytes(rest). The canonical bytes
    // start with a 1-byte tag; the local_history_node_secret tag is 145 and
    // the wire layout puts node_secret as the final 32 bytes of canonical
    // bytes (per src/protocol/event_modules/encryption/local_history_node_secret/codec.rs).
    let canonical = canonical_bytes_from_event_row(&bytes);
    assert_eq!(
        canonical.first().copied(),
        Some(145u8),
        "expected local_history_node_secret tag"
    );
    canonical[canonical.len() - 32..].to_vec()
}

fn canonical_bytes_from_event_row(value: &[u8]) -> Vec<u8> {
    // The encoded event-row value layout is timestamp(8) + body_len(8) +
    // first_byte_id(1) + scope(1) + status(1) + has_workspace(1) +
    // workspace_id(32 if has_workspace) + canonical_bytes(rest). This test
    // intentionally re-implements the layout decode rather than reaching into
    // protocol internals: the rules-boundary test forbids those imports from
    // black-box tests on purpose.
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

#[test]
fn cli_rotate_recipient_purges_old_local_private_key_and_wraps() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let workspace_id = create_workspace(&alice, "FS Rotate", "alice", "alice-laptop");

    // Build a complete frontier-with-wrap setup BEFORE rotation. The wrap is
    // addressed to alice's own retired recipient key, so rotation must purge
    // its row, its canonical bytes, the retired private-key row, and the two
    // retired event-store entries.
    let recipient = assert_success(topo(&["--db", &alice, "key-recipient", &workspace_id]));
    let retired_recipient_key_id = line_value(&recipient, "recipient_key_id");
    let retired_local_recipient_key_id = line_value(&recipient, "local_recipient_key_id");

    let frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let removal_frontier_id = line_value(&frontier, "removal_frontier_id");

    let wrapped = assert_success(topo(&[
        "--db",
        &alice,
        "key-wrap",
        &workspace_id,
        &removal_frontier_id,
        &retired_recipient_key_id,
    ]));
    let retired_key_wrap_id = line_value(&wrapped, "key_wrap_id");

    // Sanity: keys WS counts the pre-rotation rows we expect. If these change,
    // the test below is checking the wrong baseline.
    let pre = assert_success(topo(&["--db", &alice, "keys", &workspace_id]));
    assert_eq!(line_value(&pre, "recipient_keys"), "1");
    assert_eq!(line_value(&pre, "recipient_key_tombstones"), "0");
    assert_eq!(line_value(&pre, "local_recipient_keys"), "1");
    assert_eq!(line_value(&pre, "key_wraps"), "1");

    // Pre-rotation SQLite check: the retired event ids are durably present.
    assert!(
        event_row_exists(&alice, &retired_recipient_key_id),
        "expected retired recipient_key event row before rotation",
    );
    assert!(
        event_row_exists(&alice, &retired_local_recipient_key_id),
        "expected retired local_recipient_key event row before rotation",
    );
    assert!(
        event_row_exists(&alice, &retired_key_wrap_id),
        "expected retired key_wrap event row before rotation",
    );

    let rotated = assert_success(topo(&[
        "--db",
        &alice,
        "key-rotate-recipient",
        &workspace_id,
    ]));
    assert_eq!(line_value(&rotated, "old_active_recipient_keys"), "1");
    assert_eq!(line_value(&rotated, "tombstoned_recipient_keys"), "1");
    let new_recipient_key_id = line_value(&rotated, "recipient_key_id");
    let new_local_recipient_key_id = line_value(&rotated, "local_recipient_key_id");
    assert_ne!(new_recipient_key_id, retired_recipient_key_id);
    assert_ne!(new_local_recipient_key_id, retired_local_recipient_key_id);

    // CLI surface: the retired private key is gone, the tombstone semantic
    // record remains, and the retired wrap row was deleted along with it.
    let post = assert_success(topo(&["--db", &alice, "keys", &workspace_id]));
    assert_eq!(line_value(&post, "recipient_keys"), "1");
    assert_eq!(line_value(&post, "recipient_key_tombstones"), "1");
    assert_eq!(line_value(&post, "local_recipient_keys"), "1");
    assert_eq!(line_value(&post, "key_wraps"), "0");

    // SQLite-level: the retired recipient_key, retired local_recipient_key,
    // and retired key_wrap event rows are absent from event_modules.events.
    // Forward secrecy depends on these canonical bytes being unrecoverable.
    assert!(
        !event_row_exists(&alice, &retired_recipient_key_id),
        "retired recipient_key event canonical bytes must be purged",
    );
    assert!(
        !event_row_exists(&alice, &retired_local_recipient_key_id),
        "retired local_recipient_key event canonical bytes must be purged",
    );
    assert!(
        !event_row_exists(&alice, &retired_key_wrap_id),
        "retired key_wrap event canonical bytes must be purged",
    );

    // The new recipient material still works: a new frontier plus wrap targets
    // the new recipient_key_id, so rotation did not break unrelated material.
    let new_frontier = assert_success(topo(&["--db", &alice, "key-frontier", &workspace_id]));
    let new_frontier_id = line_value(&new_frontier, "removal_frontier_id");
    let new_wrap = assert_success(topo(&[
        "--db",
        &alice,
        "key-wrap",
        &workspace_id,
        &new_frontier_id,
        &new_recipient_key_id,
    ]));
    assert_eq!(
        line_value(&new_wrap, "recipient_key_id"),
        new_recipient_key_id
    );
}

fn event_row_exists(db_path: &str, event_id_hex: &str) -> bool {
    event_id_present(db_path, &decode_hex_id(event_id_hex))
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

fn join_invite_server(host: &str, server: &str, workspace_id: &str, port: u16, device_name: &str) {
    let mut listener = spawn_invite_server_listener(host, workspace_id, port, 1);
    let invite = listener.invite_link();
    let accepted = match try_accept_invite_server_with_retry(server, &invite, device_name) {
        Ok(output) => output,
        Err(err) => listener.fail("invite-server accept failed", err),
    };
    assert_eq!(line_value(&accepted, "workspace_id"), workspace_id);
    assert_eq!(line_value(&accepted, "endpoint_role"), "invite-server");
    let host_out = listener.wait_success("invite-server listener");
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

fn spawn_invite_server_listener(
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
        "invite-server",
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

fn try_accept_invite_server_with_retry(
    db: &str,
    invite: &str,
    device_name: &str,
) -> Result<String, String> {
    let mut last = String::new();
    for _ in 0..200 {
        let output = topo(&[
            "--db",
            db,
            "accept-invite-server",
            invite,
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
    panic!("content count did not reach {expected}: {last}");
}

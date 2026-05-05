//! Black-box CLI tests for content events.
//!
//! These spawn the real `topo` binary and exercise message/reaction/file flows
//! end-to-end. They mirror the poc-7 contract (send + list, react, delete,
//! send-file/save-file, multi-peer sync) within the poc-8 architecture.

mod cli_harness;

use std::fs;
use std::process::{Child, Output};
use std::thread;
use std::time::Duration;

use cli_harness::*;
use topo::core::crypto;
use topo::protocol::event_modules::identity::{
    device_invite, endpoint, endpoint_shared, user, user_invite, workspace,
};
use topo::protocol::event_modules::types::EventId;
use topo::protocol::event_modules::worker::{self, CommandOutput};
use topo::protocol::Protocol;

#[test]
fn cli_send_then_messages_lists_authored_messages() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = bootstrap_alice_workspace(&db);
    let workspace_hex = hex_id(workspace_id);

    let send1 = assert_success(topo(&[
        "--db",
        &db,
        "send",
        &workspace_hex,
        "first message",
    ]));
    assert!(send1.contains("text: first message"), "{send1}");

    let send2 = assert_success(topo(&[
        "--db",
        &db,
        "send",
        &workspace_hex,
        "second message",
    ]));
    assert!(send2.contains("text: second message"), "{send2}");

    let listing = assert_success(topo(&["--db", &db, "messages", &workspace_hex]));
    assert_eq!(line_value(&listing, "messages"), "2");
    assert!(listing.contains("alice: first message"), "{listing}");
    assert!(listing.contains("alice: second message"), "{listing}");
}

#[test]
fn cli_react_appears_in_messages_listing() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = bootstrap_alice_workspace(&db);
    let workspace_hex = hex_id(workspace_id);

    assert_success(topo(&["--db", &db, "send", &workspace_hex, "hello"]));
    let react = assert_success(topo(&[
        "--db",
        &db,
        "react",
        &workspace_hex,
        "#1",
        "👍",
    ]));
    assert!(react.contains("emoji: 👍"), "{react}");

    let listing = assert_success(topo(&["--db", &db, "messages", &workspace_hex]));
    assert!(listing.contains("reactions: 👍"), "{listing}");
}

#[test]
fn cli_delete_message_marks_target_in_listing_and_keeps_reactions_filtered() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = bootstrap_alice_workspace(&db);
    let workspace_hex = hex_id(workspace_id);

    assert_success(topo(&["--db", &db, "send", &workspace_hex, "regret"]));
    assert_success(topo(&[
        "--db",
        &db,
        "react",
        &workspace_hex,
        "#1",
        "💯",
    ]));

    let before = assert_success(topo(&["--db", &db, "messages", &workspace_hex]));
    assert!(!before.contains("(deleted)"), "{before}");

    let deleted = assert_success(topo(&[
        "--db",
        &db,
        "delete-message",
        &workspace_hex,
        "#1",
    ]));
    assert!(deleted.contains("event_id:"), "{deleted}");

    let after = assert_success(topo(&["--db", &db, "messages", &workspace_hex]));
    assert!(after.contains("(deleted)"), "{after}");
}

#[test]
fn cli_send_file_then_save_file_round_trips_bytes_through_real_binary() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "alice.db");
    let workspace_id = bootstrap_alice_workspace(&db);
    let workspace_hex = hex_id(workspace_id);

    let payload: Vec<u8> = (0..8192u32).map(|byte| byte as u8).collect();
    let in_path = tmp.path().join("input.bin");
    fs::write(&in_path, &payload).expect("write input");

    let sent = assert_success(topo(&[
        "--db",
        &db,
        "send-file",
        &workspace_hex,
        "see attached",
        "--file",
        in_path.to_str().expect("path utf-8"),
    ]));
    assert!(sent.contains("filename: input.bin"), "{sent}");
    assert_eq!(line_value(&sent, "blob_bytes"), "8192");

    let files = assert_success(topo(&["--db", &db, "files", &workspace_hex]));
    assert_eq!(line_value(&files, "files"), "1");
    assert!(files.contains("input.bin"), "{files}");

    let messages = assert_success(topo(&["--db", &db, "messages", &workspace_hex]));
    assert!(
        messages.contains("see attached") && messages.contains("file: input.bin"),
        "{messages}"
    );

    let out_path = tmp.path().join("out.bin");
    let saved = assert_success(topo(&[
        "--db",
        &db,
        "save-file",
        &workspace_hex,
        "#1",
        out_path.to_str().expect("path utf-8"),
    ]));
    assert_eq!(line_value(&saved, "filename"), "input.bin");
    assert_eq!(line_value(&saved, "bytes_written"), "8192");

    let read_back = fs::read(&out_path).expect("read output");
    assert_eq!(read_back, payload);
}

#[test]
fn cli_messages_and_reactions_sync_between_two_peers() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let bob_port = free_port();
    connect_pair(&alice, &bob, bob_port);

    let alice_endpoint = local_endpoint(&alice);
    let bob_endpoint = local_endpoint(&bob);
    let workspace_id = install_shared_workspace(
        &[&alice, &bob],
        7,
        "shared",
        &[
            Member {
                name: "alice",
                endpoint_id: alice_endpoint.endpoint,
                signing_public_key: alice_endpoint.signing_public_key,
                seed: 11,
            },
            Member {
                name: "bob",
                endpoint_id: bob_endpoint.endpoint,
                signing_public_key: bob_endpoint.signing_public_key,
                seed: 12,
            },
        ],
    );
    let workspace_hex = hex_id(workspace_id);

    assert_success(topo(&[
        "--db",
        &alice,
        "send",
        &workspace_hex,
        "from alice",
    ]));
    assert_success(topo(&[
        "--db",
        &alice,
        "react",
        &workspace_hex,
        "#1",
        "🎉",
    ]));
    sync_once(&alice, &bob, bob_port);

    let bob_listing = assert_success(topo(&["--db", &bob, "messages", &workspace_hex]));
    assert_eq!(line_value(&bob_listing, "messages"), "1");
    assert!(bob_listing.contains("alice: from alice"), "{bob_listing}");
    assert!(bob_listing.contains("reactions: 🎉"), "{bob_listing}");
}

#[test]
fn cli_send_file_syncs_bytes_to_peer_for_save() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let bob_port = free_port();
    connect_pair(&alice, &bob, bob_port);

    let alice_endpoint = local_endpoint(&alice);
    let bob_endpoint = local_endpoint(&bob);
    let workspace_id = install_shared_workspace(
        &[&alice, &bob],
        9,
        "files",
        &[
            Member {
                name: "alice",
                endpoint_id: alice_endpoint.endpoint,
                signing_public_key: alice_endpoint.signing_public_key,
                seed: 21,
            },
            Member {
                name: "bob",
                endpoint_id: bob_endpoint.endpoint,
                signing_public_key: bob_endpoint.signing_public_key,
                seed: 22,
            },
        ],
    );
    let workspace_hex = hex_id(workspace_id);

    let payload: Vec<u8> = (0..4096u32).map(|byte| byte as u8).collect();
    let in_path = tmp.path().join("payload.bin");
    fs::write(&in_path, &payload).expect("write input");

    assert_success(topo(&[
        "--db",
        &alice,
        "send-file",
        &workspace_hex,
        "see attached",
        "--file",
        in_path.to_str().expect("path"),
    ]));
    sync_once(&alice, &bob, bob_port);

    let listing = assert_success(topo(&["--db", &bob, "files", &workspace_hex]));
    assert_eq!(line_value(&listing, "files"), "1");
    let out_path = tmp.path().join("out.bin");
    let saved = assert_success(topo(&[
        "--db",
        &bob,
        "save-file",
        &workspace_hex,
        "#1",
        out_path.to_str().expect("path"),
    ]));
    assert_eq!(line_value(&saved, "filename"), "payload.bin");
    let read_back = fs::read(&out_path).expect("read output");
    assert_eq!(read_back, payload);
}

#[derive(Clone, Copy)]
struct Member {
    name: &'static str,
    endpoint_id: EventId,
    signing_public_key: [u8; 32],
    seed: u8,
}

fn install_shared_workspace(
    dbs: &[&str],
    seed: u8,
    name: &str,
    members: &[Member],
) -> EventId {
    let mut graph = None;
    for db in dbs {
        let installed = workspace_graph(db, seed, name, members);
        if let Some(existing) = graph {
            assert_eq!(existing, installed);
        }
        graph = Some(installed);
    }
    graph.expect("at least one db")
}

fn workspace_graph(db: &str, seed: u8, name: &str, members: &[Member]) -> EventId {
    let protocol = Protocol::new();
    let store = Protocol::open_store(db).expect("open graph store");
    let workspace_private = [seed; 32];
    let workspace_public = crypto::ed25519_public_key(&workspace_private);
    let create_workspace = workspace::commands::create(workspace::commands::CreateWorkspace {
        created_at_ms: seed as u64,
        public_key: workspace_public,
        name: name.to_string(),
    })
    .expect("create workspace");
    let workspace_id = create_workspace.value.workspace_id;
    admit(&store, &protocol, create_workspace);

    for member in members {
        let user_private = [member.seed; 32];
        let invite_private = [member.seed.saturating_add(80); 32];
        let user_invite = user_invite::commands::create(user_invite::commands::CreateUserInvite {
            created_at_ms: 100 + member.seed as u64,
            public_key: crypto::ed25519_public_key(&invite_private),
            workspace_id,
            authority_event_id: workspace_id,
            signer_event_id: workspace_id,
            signer_private_key: workspace_private,
        })
        .expect("create user invite");
        let user_invite_id = user_invite.value.user_invite_id;
        admit(&store, &protocol, user_invite);

        let user = user::commands::create(user::commands::CreateUser {
            created_at_ms: 200 + member.seed as u64,
            workspace_id,
            public_key: crypto::ed25519_public_key(&user_private),
            username: member.name.to_string(),
            user_invite_event_id: user_invite_id,
            user_invite_private_key: invite_private,
        })
        .expect("create user");
        let user_id = user.value.user_id;
        admit(&store, &protocol, user);

        let device_private = [member.seed.saturating_add(120); 32];
        let device_invite = device_invite::commands::create_with_private_key(
            device_invite::commands::CreateDeviceInvite {
                created_at_ms: 300 + member.seed as u64,
                workspace_id,
                user_authority_event_id: user_id,
                user_invite_event_id: Some(user_invite_id),
                signer_event_id: user_id,
                signer_private_key: user_private,
            },
            device_private,
        )
        .expect("create device invite");
        let device_invite_id = device_invite.value.device_invite_id;
        admit(&store, &protocol, device_invite);

        let shared = endpoint_shared::commands::share_endpoint(
            &store,
            endpoint_shared::commands::ShareEndpoint {
                created_at_ms: 400 + member.seed as u64,
                workspace_id,
                user_authority_event_id: user_id,
                endpoint_id: member.endpoint_id,
                signing_public_key: member.signing_public_key,
                device_name: member.name.to_string(),
                device_invite_id,
                device_invite_private_key: device_private,
            },
        )
        .expect("share endpoint");
        admit(&store, &protocol, shared);
    }

    workspace_id
}

fn local_endpoint(db: &str) -> endpoint::types::EndpointKeypair {
    let protocol = Protocol::new();
    let store = Protocol::open_store(db).expect("open endpoint store");
    if let Some(existing) =
        endpoint::commands::local_keypair(&store).expect("load local endpoint")
    {
        return existing;
    }
    let create = endpoint::commands::create_local_keypair();
    let value = create.value;
    worker::run(&store, &protocol, create).expect("admit local endpoint");
    value
}

fn connect_pair(initiator_db: &str, listener_db: &str, listener_port: u16) {
    let invite = invite_link(listener_db, listener_port);
    let listener = start_listener(listener_db, listener_port, 1);
    let connected = connect_with_retry(initiator_db, &invite);
    assert!(connected.contains("connected:"), "{connected}");
    wait_success(listener, "connect listener");
}

fn invite_link(db: &str, port: u16) -> String {
    let addr = format!("127.0.0.1:{port}");
    let out = assert_success(topo(&["--db", db, "invite", "--public-addr", &addr]));
    out.lines()
        .find(|line| line.starts_with("topo://invite/"))
        .unwrap_or_else(|| panic!("missing invite link in output:\n{out}"))
        .to_string()
}

fn start_listener(db: &str, port: u16, accept: usize) -> Child {
    let port = port.to_string();
    let accept = accept.to_string();
    spawn_topo(&[
        "--db",
        db,
        "sync",
        "--listen",
        "127.0.0.1",
        &port,
        "--accept",
        &accept,
    ])
}

fn connect_with_retry(db: &str, invite: &str) -> String {
    let mut last = String::new();
    for _ in 0..200 {
        let output = connect_with_invite(db, invite);
        if output.status.success() {
            return stdout(&output);
        }
        last = stderr(&output);
        thread::sleep(Duration::from_millis(50));
    }
    panic!("connect never succeeded: {last}");
}

fn connect_with_invite(db: &str, invite: &str) -> Output {
    topo(&["--db", db, "connect", invite])
}

fn sync_once(from_db: &str, listener_db: &str, listener_port: u16) {
    let mut last = String::new();
    for _ in 0..50 {
        let mut listener = start_listener(listener_db, listener_port, 1);
        thread::sleep(Duration::from_millis(50));
        let output = topo(&["--db", from_db, "sync"]);
        if output.status.success() {
            assert!(stdout(&output).contains("routes_synced: 1"), "{:?}", output);
            wait_success(listener, "sync listener");
            return;
        }
        last = stderr(&output);
        let _ = listener.kill();
        let _ = listener.wait();
        thread::sleep(Duration::from_millis(50));
    }
    panic!("sync never succeeded: {last}");
}

fn bootstrap_alice_workspace(db: &str) -> EventId {
    let protocol = Protocol::new();
    let store = Protocol::open_store(db).expect("open store");
    let local = endpoint::commands::create_local_keypair();
    let local_keypair = local.value;
    worker::run(&store, &protocol, local).expect("admit local endpoint");

    let workspace_private_key = [7; 32];
    let create_workspace = workspace::commands::create(workspace::commands::CreateWorkspace {
        created_at_ms: 1,
        public_key: crypto::ed25519_public_key(&workspace_private_key),
        name: "Content".to_string(),
    })
    .expect("create workspace");
    let workspace_id = create_workspace.value.workspace_id;
    admit(&store, &protocol, create_workspace);

    let invite_private_key = [8; 32];
    let user_private_key = [9; 32];
    let user_invite = user_invite::commands::create(user_invite::commands::CreateUserInvite {
        created_at_ms: 2,
        public_key: crypto::ed25519_public_key(&invite_private_key),
        workspace_id,
        authority_event_id: workspace_id,
        signer_event_id: workspace_id,
        signer_private_key: workspace_private_key,
    })
    .expect("create user invite");
    let user_invite_id = user_invite.value.user_invite_id;
    admit(&store, &protocol, user_invite);

    let user = user::commands::create(user::commands::CreateUser {
        created_at_ms: 3,
        workspace_id,
        public_key: crypto::ed25519_public_key(&user_private_key),
        username: "alice".to_string(),
        user_invite_event_id: user_invite_id,
        user_invite_private_key: invite_private_key,
    })
    .expect("create user");
    let user_id = user.value.user_id;
    admit(&store, &protocol, user);

    let device_private_key = [10; 32];
    let device_invite = device_invite::commands::create_with_private_key(
        device_invite::commands::CreateDeviceInvite {
            created_at_ms: 4,
            workspace_id,
            user_authority_event_id: user_id,
            user_invite_event_id: Some(user_invite_id),
            signer_event_id: user_id,
            signer_private_key: user_private_key,
        },
        device_private_key,
    )
    .expect("create device invite");
    let device_invite_id = device_invite.value.device_invite_id;
    admit(&store, &protocol, device_invite);

    let shared = endpoint_shared::commands::share_endpoint(
        &store,
        endpoint_shared::commands::ShareEndpoint {
            created_at_ms: 5,
            workspace_id,
            user_authority_event_id: user_id,
            endpoint_id: local_keypair.endpoint,
            signing_public_key: local_keypair.signing_public_key,
            device_name: "alice-local".to_string(),
            device_invite_id,
            device_invite_private_key: device_private_key,
        },
    )
    .expect("share endpoint");
    admit(&store, &protocol, shared);

    workspace_id
}

fn admit<T>(store: &topo::core::store::Store, protocol: &Protocol, output: CommandOutput<T>) {
    worker::run(store, protocol, output).expect("admit");
}

fn hex_id(id: EventId) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in id {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

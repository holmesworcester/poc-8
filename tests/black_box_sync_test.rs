mod cli_harness;

use std::io::{BufRead, BufReader, Read};
use std::net::TcpListener;
use std::process::{Child, Output};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
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

// Invariant: daemons sync cli generated content without manual sync and without scope leaks.
#[test]
fn daemons_sync_cli_generated_content_without_manual_sync_and_without_scope_leaks() {
    let _guard = black_box_guard();
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let alice_port = daemon_port();
    let bob_port = daemon_port();
    ensure_local_endpoint(&alice, alice_port);
    ensure_local_endpoint(&bob, bob_port);

    let alice_endpoint = local_endpoint(&alice);
    let bob_endpoint = local_endpoint(&bob);
    let shared = install_workspace_graph(
        &[&alice, &bob],
        51,
        "alice-bob-a",
        &[
            Member::new("alice-a", alice_endpoint, 61),
            Member::new("bob-a", bob_endpoint, 62),
        ],
    );
    let alice_private = install_workspace_graph(
        &[&alice],
        52,
        "alice-private-b",
        &[Member::new("alice-b", alice_endpoint, 63)],
    );

    let mut alice_daemon = spawn_daemon(&alice, alice_port);
    let mut bob_daemon = spawn_daemon(&bob, bob_port);
    connect_daemons(&bob, &alice, alice_port);
    connect_daemons(&alice, &bob, bob_port);
    wait_for_connection_count(&alice, 2);
    wait_for_connection_count(&bob, 2);

    generate(&alice, shared.workspace_id, 2, 128);
    generate(&alice, alice_private.workspace_id, 2, 128);
    alice_daemon.assert_running();
    bob_daemon.assert_running();

    wait_for_content_count(&bob, shared.workspace_id, 2);
    assert_content_count(&bob, alice_private.workspace_id, 0);
}

// Invariant: second daemon for same db is rejected.
#[test]
fn second_daemon_for_same_db_is_rejected() {
    let _guard = black_box_guard();
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice-single-daemon.db");
    let first_port = daemon_port();
    let second_port = daemon_port();
    let _daemon = spawn_daemon(&alice, first_port);

    let output = topo(&[
        "--db",
        &alice,
        "start",
        "--listen",
        "127.0.0.1",
        &second_port.to_string(),
        "--sync-ms",
        "100",
        "--quiet-ms",
        "100",
    ]);
    assert!(
        !output.status.success(),
        "second daemon unexpectedly started\nstdout={}\nstderr={}",
        stdout(&output),
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("daemon already running"),
        "unexpected second-daemon stderr:\n{}",
        stderr(&output)
    );
}

fn black_box_guard() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .expect("black-box test lock")
}

#[derive(Clone, Copy)]
struct Member {
    name: &'static str,
    endpoint_id: EventId,
    signing_public_key: [u8; 32],
    seed: u8,
}

impl Member {
    fn new(name: &'static str, endpoint: endpoint::types::EndpointKeypair, seed: u8) -> Self {
        Self {
            name,
            endpoint_id: endpoint.endpoint,
            signing_public_key: endpoint.signing_public_key,
            seed,
        }
    }
}

struct WorkspaceGraph {
    workspace_id: EventId,
}

fn install_workspace_graph(
    dbs: &[&str],
    seed: u8,
    name: &str,
    members: &[Member],
) -> WorkspaceGraph {
    let mut graph = None;
    for db in dbs {
        let installed = workspace_graph(db, seed, name, members);
        if let Some(existing) = graph {
            assert_eq!(existing, installed.workspace_id);
        }
        graph = Some(installed.workspace_id);
    }
    WorkspaceGraph {
        workspace_id: graph.expect("at least one db"),
    }
}

fn workspace_graph(db: &str, seed: u8, name: &str, members: &[Member]) -> WorkspaceGraph {
    let protocol = Protocol::new();
    let store = Protocol::open_store(db).expect("open graph store");
    let workspace_private = [seed; 32];
    let workspace_public = crypto::ed25519_public_key(&workspace_private);
    let workspace = workspace::commands::create(workspace::commands::CreateWorkspace {
        created_at_ms: seed as u64,
        public_key: workspace_public,
        name: name.to_string(),
    })
    .expect("create workspace");
    let workspace_id = workspace.value.workspace_id;
    admit(&store, &protocol, workspace);

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

    WorkspaceGraph { workspace_id }
}

fn admit<T>(store: &topo::core::store::Store, protocol: &Protocol, output: CommandOutput<T>) {
    worker::run(store, protocol, output).expect("admit command output");
}

fn local_endpoint(db: &str) -> endpoint::types::EndpointKeypair {
    let store = Protocol::open_store(db).expect("open endpoint store");
    endpoint::commands::local_keypair(&store)
        .expect("load local endpoint")
        .expect("local endpoint exists")
}

struct RunningDaemon {
    child: Option<Child>,
    label: String,
}

impl Drop for RunningDaemon {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.kill();
        match child.wait_with_output() {
            Ok(output) if !output.stderr.is_empty() => {
                eprintln!(
                    "daemon {} stderr:\n{}",
                    self.label,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            _ => {}
        }
        thread::sleep(Duration::from_millis(100));
    }
}

impl RunningDaemon {
    fn assert_running(&mut self) {
        let child = self.child.as_mut().expect("daemon child present");
        match child.try_wait().expect("check daemon status") {
            None => {}
            Some(status) => {
                let mut stderr = String::new();
                if let Some(mut pipe) = child.stderr.take() {
                    let _ = pipe.read_to_string(&mut stderr);
                }
                panic!(
                    "daemon {} exited early with {status}\nstderr:\n{stderr}",
                    self.label
                );
            }
        }
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
        "--sync-ms",
        "100",
        "--quiet-ms",
        "100",
    ]);
    let stdout = child.stdout.take().expect("daemon stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read daemon line");
    assert!(
        line.starts_with("listening: "),
        "daemon did not report listening: {line}"
    );
    RunningDaemon {
        child: Some(child),
        label: format!("{db}:{port}"),
    }
}

fn ensure_local_endpoint(db: &str, port: u16) {
    let _ = invite(db, port);
}

fn connect_daemons(initiator_db: &str, listener_db: &str, listener_port: u16) {
    let invite = invite(listener_db, listener_port);
    let connected = connect_with_retry(initiator_db, &invite);
    assert!(connected.contains("connection requested:"));
}

fn daemon_port() -> u16 {
    static NEXT_PORT: AtomicU16 = AtomicU16::new(41000);
    loop {
        let port = NEXT_PORT.fetch_add(1, Ordering::Relaxed);
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

fn invite(db: &str, port: u16) -> String {
    let addr = format!("127.0.0.1:{port}");
    let out = assert_success(topo(&["--db", db, "invite", "--public-addr", &addr]));
    out.lines()
        .find(|line| line.starts_with("topo://invite/"))
        .unwrap_or_else(|| panic!("missing invite link in output:\n{out}"))
        .to_string()
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

fn generate(db: &str, workspace_id: EventId, count: usize, size: usize) -> String {
    let workspace = hex_id(workspace_id);
    let count = count.to_string();
    let size = size.to_string();
    assert_success(topo(&["--db", db, "generate", &workspace, &count, &size]))
}

fn assert_content_count(db: &str, workspace_id: EventId, expected: usize) {
    let workspace = hex_id(workspace_id);
    let out = assert_success(topo(&["--db", db, "content-count", &workspace]));
    assert_eq!(
        line_value(&out, "content_events"),
        expected.to_string(),
        "content-count output:\n{out}"
    );
}

fn wait_for_connection_count(db: &str, expected: usize) {
    let mut last = String::new();
    for _ in 0..100 {
        let out = assert_success(topo(&["--db", db, "count"]));
        if line_value(&out, "connections") == expected.to_string() {
            return;
        }
        last = out;
        thread::sleep(Duration::from_millis(50));
    }
    panic!("connection count did not reach {expected}; last output:\n{last}");
}

fn wait_for_content_count(db: &str, workspace_id: EventId, expected: usize) {
    let workspace = hex_id(workspace_id);
    let mut last = String::new();
    for _ in 0..300 {
        let out = assert_success(topo(&["--db", db, "content-count", &workspace]));
        if line_value(&out, "content_events") == expected.to_string() {
            return;
        }
        last = out;
        thread::sleep(Duration::from_millis(100));
    }
    let status = assert_success(topo(&["--db", db, "count"]));
    panic!("content count did not reach {expected}; last output:\n{last}\nstatus:\n{status}");
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

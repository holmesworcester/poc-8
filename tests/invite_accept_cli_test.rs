mod cli_harness;

use std::io::{BufRead, BufReader, Read};
use std::process::Child;
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use cli_harness::*;

#[test]
fn invite_listens_and_accept_connects_two_cli_processes() {
    let tmp = tempfile::tempdir().unwrap();
    let host = temp_db(&tmp, "host.db");
    let joiner = temp_db(&tmp, "joiner.db");
    let port = free_port();

    let mut listener = spawn_invite_listener(&host, port, 1);
    let invite = listener.invite_link();
    let accepted = accept_with_retry(&joiner, &invite);
    assert!(accepted.contains("connected:"), "{accepted}");

    let host_out = listener.wait_success("single invite listener");
    assert!(host_out.contains("accepted_connections: 1"), "{host_out}");
    assert_eq!(connection_count(&host), 1);
    assert_eq!(connection_count(&joiner), 1);
    assert_eq!(connection_event_count(&host), 1);
    assert_eq!(connection_event_count(&joiner), 1);
}

#[test]
fn invite_listens_for_two_separate_accepting_cli_processes() {
    let tmp = tempfile::tempdir().unwrap();
    let host = temp_db(&tmp, "host.db");
    let joiner_a = temp_db(&tmp, "joiner-a.db");
    let joiner_b = temp_db(&tmp, "joiner-b.db");
    let port = free_port();

    let mut listener = spawn_invite_listener(&host, port, 2);
    let invite = listener.invite_link();

    let accepted_a = accept_with_retry(&joiner_a, &invite);
    assert!(accepted_a.contains("connected:"), "{accepted_a}");
    let accepted_b = accept_with_retry(&joiner_b, &invite);
    assert!(accepted_b.contains("connected:"), "{accepted_b}");

    let host_out = listener.wait_success("two-accept invite listener");
    assert!(host_out.contains("accepted_connections: 2"), "{host_out}");
    assert_eq!(connection_count(&host), 2);
    assert_eq!(connection_count(&joiner_a), 1);
    assert_eq!(connection_count(&joiner_b), 1);
    assert_eq!(connection_event_count(&host), 2);
    assert_eq!(connection_event_count(&joiner_a), 1);
    assert_eq!(connection_event_count(&joiner_b), 1);
}

#[test]
fn workspace_invite_accept_builds_identity_graph_over_two_cli_processes() {
    let tmp = tempfile::tempdir().unwrap();
    let host = temp_db(&tmp, "host.db");
    let joiner = temp_db(&tmp, "joiner.db");
    let port = free_port();

    let created = assert_success(topo(&[
        "--db",
        &host,
        "create-workspace",
        "Alpha",
        "--username",
        "alice",
        "--devicename",
        "alice-laptop",
    ]));
    let workspace_id = line_value(&created, "workspace_id");

    let mut listener = spawn_workspace_invite_listener(&host, &workspace_id, port, 1);
    let invite = listener.invite_link();
    let accepted = match try_accept_with_identity_retry(&joiner, &invite, "bob", "bob-phone") {
        Ok(output) => output,
        Err(err) => {
            listener.fail("bob accept failed", err);
        }
    };
    assert!(accepted.contains("connected:"), "{accepted}");
    assert_eq!(line_value(&accepted, "workspace_id"), workspace_id);

    let host_out = listener.wait_success("workspace invite listener");
    assert!(host_out.contains("accepted_connections: 1"), "{host_out}");

    let workspaces = assert_success(topo(&["--db", &joiner, "workspaces"]));
    assert!(workspaces.contains("Alpha"), "{workspaces}");
    assert!(workspaces.contains(&workspace_id), "{workspaces}");

    let users = assert_success(topo(&["--db", &joiner, "users", &workspace_id]));
    assert!(users.contains("alice"), "{users}");
    assert!(users.contains("bob"), "{users}");

    let host_users = assert_success(topo(&["--db", &host, "users", &workspace_id]));
    assert!(host_users.contains("alice"), "{host_users}");
    assert!(host_users.contains("bob"), "{host_users}");

    let duplicate = topo(&[
        "--db",
        &joiner,
        "accept",
        &invite,
        "--username",
        "bob-again",
        "--devicename",
        "bob-second",
    ]);
    assert!(
        !duplicate.status.success(),
        "duplicate join unexpectedly succeeded:\n{}",
        stdout(&duplicate)
    );
    assert!(
        stderr(&duplicate).contains("endpoint is already joined to workspace"),
        "{}",
        stderr(&duplicate)
    );
}

#[test]
fn workspace_invite_is_multi_use_for_two_accepting_users() {
    let tmp = tempfile::tempdir().unwrap();
    let host = temp_db(&tmp, "host.db");
    let bob = temp_db(&tmp, "bob.db");
    let carol = temp_db(&tmp, "carol.db");
    let port = free_port();

    let created = assert_success(topo(&[
        "--db",
        &host,
        "create-workspace",
        "Alpha",
        "--username",
        "alice",
        "--devicename",
        "alice-laptop",
    ]));
    let workspace_id = line_value(&created, "workspace_id");

    let mut listener = spawn_workspace_invite_listener(&host, &workspace_id, port, 2);
    let invite = listener.invite_link();
    let accepted_bob = match try_accept_with_identity_retry(&bob, &invite, "bob", "bob-phone") {
        Ok(output) => output,
        Err(err) => {
            listener.fail("bob accept failed", err);
        }
    };
    assert_eq!(line_value(&accepted_bob, "workspace_id"), workspace_id);
    thread::sleep(Duration::from_millis(50));
    let accepted_carol =
        match try_accept_with_identity_retry(&carol, &invite, "carol", "carol-phone") {
            Ok(output) => output,
            Err(err) => {
                listener.fail("carol accept failed", err);
            }
        };
    assert_eq!(line_value(&accepted_carol, "workspace_id"), workspace_id);

    let host_out = listener.wait_success("multi-use workspace invite listener");
    assert!(host_out.contains("accepted_connections: 2"), "{host_out}");

    let bob_users = assert_success(topo(&["--db", &bob, "users", &workspace_id]));
    assert!(bob_users.contains("alice"), "{bob_users}");
    assert!(bob_users.contains("bob"), "{bob_users}");

    let carol_users = assert_success(topo(&["--db", &carol, "users", &workspace_id]));
    assert!(carol_users.contains("alice"), "{carol_users}");
    assert!(carol_users.contains("carol"), "{carol_users}");

    let host_users = assert_success(topo(&["--db", &host, "users", &workspace_id]));
    assert!(host_users.contains("alice"), "{host_users}");
    assert!(host_users.contains("bob"), "{host_users}");
    assert!(host_users.contains("carol"), "{host_users}");
}

#[test]
fn workspace_invite_reuse_inducts_three_users() {
    let tmp = tempfile::tempdir().unwrap();
    let host = temp_db(&tmp, "host.db");
    let bob = temp_db(&tmp, "bob.db");
    let carol = temp_db(&tmp, "carol.db");
    let dave = temp_db(&tmp, "dave.db");
    let port = free_port();

    let created = create_workspace(&host, "Alpha", "alice", "alice-laptop");
    let workspace_id = line_value(&created, "workspace_id");

    let mut listener = spawn_workspace_invite_listener(&host, &workspace_id, port, 3);
    let invite = listener.invite_link();
    for (db, username, device_name) in [
        (&bob, "bob", "bob-phone"),
        (&carol, "carol", "carol-phone"),
        (&dave, "dave", "dave-phone"),
    ] {
        let accepted = match try_accept_with_identity_retry(db, &invite, username, device_name) {
            Ok(output) => output,
            Err(err) => listener.fail("reused workspace invite accept failed", err),
        };
        assert_eq!(line_value(&accepted, "workspace_id"), workspace_id);
    }

    let host_out = listener.wait_success("three-use workspace invite listener");
    assert!(host_out.contains("accepted_connections: 3"), "{host_out}");

    let host_users = assert_success(topo(&["--db", &host, "users", &workspace_id]));
    assert_contains_all(&host_users, &["alice", "bob", "carol", "dave"]);
    let dave_users = assert_success(topo(&["--db", &dave, "users", &workspace_id]));
    assert_contains_all(&dave_users, &["alice", "bob", "carol", "dave"]);
}

#[test]
fn workspace_invites_mix_reuse_and_fresh_creation() {
    let tmp = tempfile::tempdir().unwrap();
    let host = temp_db(&tmp, "host.db");
    let bob = temp_db(&tmp, "bob.db");
    let carol = temp_db(&tmp, "carol.db");
    let dave = temp_db(&tmp, "dave.db");
    let old_port = free_port();
    let fresh_port = free_port();

    let created = create_workspace(&host, "Alpha", "alice", "alice-laptop");
    let workspace_id = line_value(&created, "workspace_id");

    let mut old_listener = spawn_workspace_invite_listener(&host, &workspace_id, old_port, 2);
    let old_invite = old_listener.invite_link();
    let accepted_bob = match try_accept_with_identity_retry(&bob, &old_invite, "bob", "bob-phone") {
        Ok(output) => output,
        Err(err) => old_listener.fail("old invite bob accept failed", err),
    };
    assert_eq!(line_value(&accepted_bob, "workspace_id"), workspace_id);

    let mut fresh_listener = spawn_workspace_invite_listener(&host, &workspace_id, fresh_port, 1);
    let fresh_invite = fresh_listener.invite_link();
    let accepted_carol =
        match try_accept_with_identity_retry(&carol, &fresh_invite, "carol", "carol-phone") {
            Ok(output) => output,
            Err(err) => fresh_listener.fail("fresh invite carol accept failed", err),
        };
    assert_eq!(line_value(&accepted_carol, "workspace_id"), workspace_id);
    let fresh_out = fresh_listener.wait_success("fresh workspace invite listener");
    assert!(fresh_out.contains("accepted_connections: 1"), "{fresh_out}");

    let accepted_dave =
        match try_accept_with_identity_retry(&dave, &old_invite, "dave", "dave-phone") {
            Ok(output) => output,
            Err(err) => old_listener.fail("old invite dave accept failed", err),
        };
    assert_eq!(line_value(&accepted_dave, "workspace_id"), workspace_id);
    let old_out = old_listener.wait_success("reused workspace invite listener");
    assert!(old_out.contains("accepted_connections: 2"), "{old_out}");

    let host_users = assert_success(topo(&["--db", &host, "users", &workspace_id]));
    assert_contains_all(&host_users, &["alice", "bob", "carol", "dave"]);
}

#[test]
fn device_link_accept_links_second_device_over_two_cli_processes() {
    let tmp = tempfile::tempdir().unwrap();
    let host = temp_db(&tmp, "host.db");
    let phone = temp_db(&tmp, "phone.db");
    let port = free_port();

    let created = assert_success(topo(&[
        "--db",
        &host,
        "create-workspace",
        "Alpha",
        "--username",
        "alice",
        "--devicename",
        "alice-laptop",
    ]));
    let workspace_id = line_value(&created, "workspace_id");
    let user_id = line_value(&created, "user_id");

    let mut listener = spawn_device_link_listener(&host, &workspace_id, port, 1);
    let link = listener.invite_link();
    let accepted = match try_accept_link_with_retry(&phone, &link, "alice-phone") {
        Ok(output) => output,
        Err(err) => {
            listener.fail("device link accept failed", err);
        }
    };
    assert!(accepted.contains("connected:"), "{accepted}");
    assert_eq!(line_value(&accepted, "workspace_id"), workspace_id);

    let host_out = listener.wait_success("device link listener");
    assert!(host_out.contains("accepted_connections: 1"), "{host_out}");

    let identity = assert_success(topo(&["--db", &phone, "identity"]));
    assert!(identity.contains(&workspace_id), "{identity}");
    assert!(
        identity.contains(&format!("user_id={user_id}")),
        "{identity}"
    );

    let host_users = assert_success(topo(&["--db", &host, "users", &workspace_id]));
    assert!(host_users.contains("alice"), "{host_users}");
    assert!(host_users.contains(&user_id), "{host_users}");

    let host_peers = assert_success(topo(&["--db", &host, "peers", &workspace_id]));
    assert!(host_peers.contains("alice-laptop"), "{host_peers}");
    assert!(host_peers.contains("alice-phone"), "{host_peers}");
    assert!(
        host_peers.contains(&format!("user_id={user_id}")),
        "{host_peers}"
    );

    let duplicate = topo(&[
        "--db",
        &phone,
        "accept-link",
        &link,
        "--devicename",
        "alice-phone-again",
    ]);
    assert!(
        !duplicate.status.success(),
        "duplicate link unexpectedly succeeded:\n{}",
        stdout(&duplicate)
    );
    assert!(
        stderr(&duplicate).contains("endpoint is already joined to workspace"),
        "{}",
        stderr(&duplicate)
    );
}

#[test]
fn device_links_mix_reuse_and_fresh_creation() {
    let tmp = tempfile::tempdir().unwrap();
    let phone = temp_db(&tmp, "phone.db");
    let laptop = temp_db(&tmp, "laptop.db");
    let tablet = temp_db(&tmp, "tablet.db");
    let desktop = temp_db(&tmp, "desktop.db");
    let old_port = free_port();
    let fresh_port = free_port();

    let created = create_workspace(&phone, "Alpha", "alice", "alice-phone");
    let workspace_id = line_value(&created, "workspace_id");
    let user_id = line_value(&created, "user_id");

    let mut old_listener = spawn_device_link_listener(&phone, &workspace_id, old_port, 2);
    let old_link = old_listener.invite_link();
    let accepted_laptop = match try_accept_link_with_retry(&laptop, &old_link, "alice-laptop") {
        Ok(output) => output,
        Err(err) => old_listener.fail("old device link laptop accept failed", err),
    };
    assert_eq!(line_value(&accepted_laptop, "workspace_id"), workspace_id);

    let mut fresh_listener = spawn_device_link_listener(&laptop, &workspace_id, fresh_port, 1);
    let fresh_link = fresh_listener.invite_link();
    let accepted_tablet = match try_accept_link_with_retry(&tablet, &fresh_link, "alice-tablet") {
        Ok(output) => output,
        Err(err) => fresh_listener.fail("fresh device link tablet accept failed", err),
    };
    assert_eq!(line_value(&accepted_tablet, "workspace_id"), workspace_id);
    let fresh_out = fresh_listener.wait_success("fresh device link listener");
    assert!(fresh_out.contains("accepted_connections: 1"), "{fresh_out}");

    let accepted_desktop = match try_accept_link_with_retry(&desktop, &old_link, "alice-desktop") {
        Ok(output) => output,
        Err(err) => old_listener.fail("old device link desktop accept failed", err),
    };
    assert_eq!(line_value(&accepted_desktop, "workspace_id"), workspace_id);
    let old_out = old_listener.wait_success("reused device link listener");
    assert!(old_out.contains("accepted_connections: 2"), "{old_out}");

    let phone_peers = assert_success(topo(&["--db", &phone, "peers", &workspace_id]));
    assert_contains_all(
        &phone_peers,
        &["alice-phone", "alice-laptop", "alice-desktop"],
    );
    assert!(
        phone_peers.contains(&format!("user_id={user_id}")),
        "{phone_peers}"
    );

    let laptop_peers = assert_success(topo(&["--db", &laptop, "peers", &workspace_id]));
    assert_contains_all(
        &laptop_peers,
        &["alice-phone", "alice-laptop", "alice-tablet"],
    );
    assert!(
        laptop_peers.contains(&format!("user_id={user_id}")),
        "{laptop_peers}"
    );
}

#[test]
fn admin_grant_requires_admin_and_promoted_user_can_invite() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let carol = temp_db(&tmp, "carol.db");
    let alice_invite_port = free_port();
    let alice_route_port = free_port();
    let bob_route_port = free_port();
    let bob_invite_port = free_port();

    let created = create_workspace(&alice, "Alpha", "alice", "alice-laptop");
    let workspace_id = line_value(&created, "workspace_id");
    let alice_user_id = line_value(&created, "user_id");

    let mut alice_listener =
        spawn_workspace_invite_listener(&alice, &workspace_id, alice_invite_port, 1);
    let alice_invite = alice_listener.invite_link();
    let accepted_bob = match try_accept_with_identity_retry(&bob, &alice_invite, "bob", "bob-phone")
    {
        Ok(output) => output,
        Err(err) => alice_listener.fail("bob accept failed", err),
    };
    assert_eq!(line_value(&accepted_bob, "workspace_id"), workspace_id);
    let alice_out = alice_listener.wait_success("alice workspace invite listener");
    assert!(alice_out.contains("accepted_connections: 1"), "{alice_out}");

    let non_admin_grant = topo(&["--db", &bob, "grant-admin", &workspace_id, &alice_user_id]);
    assert!(
        !non_admin_grant.status.success(),
        "non-admin grant unexpectedly succeeded:\n{}",
        stdout(&non_admin_grant)
    );
    assert!(
        stderr(&non_admin_grant).contains("local user is not an admin"),
        "{}",
        stderr(&non_admin_grant)
    );

    let bob_user_id = user_id_by_name(&alice, &workspace_id, "bob");
    let grant = assert_success(topo(&[
        "--db",
        &alice,
        "grant-admin",
        &workspace_id,
        &bob_user_id,
    ]));
    assert!(grant.contains("admin_id:"), "{grant}");

    connect_pair(&alice, &bob, bob_route_port);
    connect_pair(&bob, &alice, alice_route_port);
    let _sync = sync_daemons(&alice, alice_route_port, &bob, bob_route_port);
    wait_until_invite_can_be_created(&bob, &workspace_id, bob_invite_port);

    let mut bob_listener = spawn_workspace_invite_listener(&bob, &workspace_id, bob_invite_port, 1);
    let bob_invite = bob_listener.invite_link();
    let accepted_carol =
        match try_accept_with_identity_retry(&carol, &bob_invite, "carol", "carol-phone") {
            Ok(output) => output,
            Err(err) => bob_listener.fail("carol accept failed", err),
        };
    assert_eq!(line_value(&accepted_carol, "workspace_id"), workspace_id);
    let bob_out = bob_listener.wait_success("bob admin workspace invite listener");
    assert!(bob_out.contains("accepted_connections: 1"), "{bob_out}");

    let bob_users = assert_success(topo(&["--db", &bob, "users", &workspace_id]));
    assert_contains_all(&bob_users, &["alice", "bob", "carol"]);
}

#[test]
fn same_endpoint_can_join_multiple_workspaces_but_not_same_workspace_twice() {
    let tmp = tempfile::tempdir().unwrap();
    let host = temp_db(&tmp, "host.db");
    let joiner = temp_db(&tmp, "joiner.db");
    let alpha_port = free_port();
    let beta_port = free_port();
    let duplicate_port = free_port();

    let alpha = create_workspace(&host, "Alpha", "alice-alpha", "alice-alpha-laptop");
    let alpha_id = line_value(&alpha, "workspace_id");
    let mut alpha_listener = spawn_workspace_invite_listener(&host, &alpha_id, alpha_port, 1);
    let alpha_invite = alpha_listener.invite_link();
    let accepted_alpha = match try_accept_with_identity_retry(
        &joiner,
        &alpha_invite,
        "bob-alpha",
        "bob-alpha-phone",
    ) {
        Ok(output) => output,
        Err(err) => alpha_listener.fail("alpha accept failed", err),
    };
    assert_eq!(line_value(&accepted_alpha, "workspace_id"), alpha_id);
    let alpha_out = alpha_listener.wait_success("alpha invite listener");
    assert!(alpha_out.contains("accepted_connections: 1"), "{alpha_out}");

    let beta = create_workspace(&host, "Beta", "alice-beta", "alice-beta-laptop");
    let beta_id = line_value(&beta, "workspace_id");
    let mut beta_listener = spawn_workspace_invite_listener(&host, &beta_id, beta_port, 1);
    let beta_invite = beta_listener.invite_link();
    let accepted_beta =
        match try_accept_with_identity_retry(&joiner, &beta_invite, "bob-beta", "bob-beta-phone") {
            Ok(output) => output,
            Err(err) => beta_listener.fail("beta accept failed", err),
        };
    assert_eq!(line_value(&accepted_beta, "workspace_id"), beta_id);
    let beta_out = beta_listener.wait_success("beta invite listener");
    assert!(beta_out.contains("accepted_connections: 1"), "{beta_out}");

    let workspaces = assert_success(topo(&["--db", &joiner, "workspaces"]));
    assert_contains_all(&workspaces, &["Alpha", "Beta", &alpha_id, &beta_id]);
    let alpha_users = assert_success(topo(&["--db", &joiner, "users", &alpha_id]));
    assert_contains_all(&alpha_users, &["alice-alpha", "bob-alpha"]);
    assert!(!alpha_users.contains("bob-beta"), "{alpha_users}");
    let beta_users = assert_success(topo(&["--db", &joiner, "users", &beta_id]));
    assert_contains_all(&beta_users, &["alice-beta", "bob-beta"]);
    assert!(!beta_users.contains("bob-alpha"), "{beta_users}");

    let duplicate_invite = workspace_invite_link(&host, &alpha_id, duplicate_port);
    let duplicate = topo(&[
        "--db",
        &joiner,
        "accept",
        &duplicate_invite,
        "--username",
        "bob-alpha-again",
        "--devicename",
        "bob-alpha-second",
    ]);
    assert!(
        !duplicate.status.success(),
        "same endpoint joined same workspace twice through a distinct invite:\n{}",
        stdout(&duplicate)
    );
    assert!(
        stderr(&duplicate).contains("endpoint is already joined to workspace"),
        "{}",
        stderr(&duplicate)
    );
}

#[test]
fn forged_workspace_invite_does_not_authorize_or_exfiltrate_events() {
    let tmp = tempfile::tempdir().unwrap();
    let attacker = temp_db(&tmp, "attacker.db");
    let victim = temp_db(&tmp, "victim.db");
    let attacker_port = free_port();

    let victim_created = create_workspace(&victim, "Victim", "victim", "victim-laptop");
    let victim_workspace_id = line_value(&victim_created, "workspace_id");
    let generated = assert_success(topo(&[
        "--db",
        &victim,
        "generate",
        &victim_workspace_id,
        "2",
        "128",
    ]));
    assert!(generated.contains("generated_events: 2"), "{generated}");

    let attacker_created = create_workspace(&attacker, "Attacker", "attacker", "attacker-laptop");
    let attacker_workspace_id = line_value(&attacker_created, "workspace_id");
    let mut listener =
        spawn_workspace_invite_listener(&attacker, &attacker_workspace_id, attacker_port, 1);
    let attacker_invite = listener.invite_link();
    let forged_invite = replace_invite_workspace(&attacker_invite, &victim_workspace_id);

    let accept = topo(&[
        "--db",
        &victim,
        "accept",
        &forged_invite,
        "--username",
        "victim-forged",
        "--devicename",
        "forged-device",
    ]);
    listener.stop();
    assert!(
        !accept.status.success(),
        "forged workspace invite unexpectedly succeeded:\n{}",
        stdout(&accept)
    );

    let attacker_content = assert_success(topo(&[
        "--db",
        &attacker,
        "content-count",
        &victim_workspace_id,
    ]));
    assert_eq!(line_value(&attacker_content, "content_events"), "0");
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

    fn stop(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = self.stdout.join();
        let _ = self.stderr.join();
    }
}

fn spawn_invite_listener(db: &str, port: u16, accept: usize) -> ListeningInvite {
    let port = port.to_string();
    let accept = accept.to_string();
    let child = spawn_topo(&[
        "--db",
        db,
        "invite",
        "--listen",
        "127.0.0.1",
        &port,
        "--accept",
        &accept,
    ]);
    listening_invite_from_child(child)
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

fn spawn_device_link_listener(
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
        "link",
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

fn accept_with_retry(db: &str, invite: &str) -> String {
    let mut last = String::new();
    for _ in 0..200 {
        let output = topo(&["--db", db, "accept", invite]);
        if output.status.success() {
            return stdout(&output);
        }
        last = stderr(&output);
        if !last.contains("open tcp stream") {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("accept never succeeded: {last}");
}

fn connect_pair(initiator_db: &str, listener_db: &str, listener_port: u16) {
    let mut listener = spawn_invite_listener(listener_db, listener_port, 1);
    let invite = listener.invite_link();
    let connected = accept_with_retry(initiator_db, &invite);
    assert!(connected.contains("connected:"), "{connected}");
    let out = listener.wait_success("transport invite listener");
    assert!(out.contains("accepted_connections: 1"), "{out}");
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

fn sync_daemons(
    from_db: &str,
    from_port: u16,
    listener_db: &str,
    listener_port: u16,
) -> (RunningDaemon, RunningDaemon) {
    (
        spawn_daemon(listener_db, listener_port),
        spawn_daemon(from_db, from_port),
    )
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

fn wait_until_invite_can_be_created(db: &str, workspace_id: &str, port: u16) {
    let addr = format!("127.0.0.1:{port}");
    let mut last = String::new();
    thread::sleep(Duration::from_millis(1000));
    for _ in 0..200 {
        let output = topo(&[
            "--db",
            db,
            "invite",
            "--workspace",
            workspace_id,
            "--public-addr",
            &addr,
        ]);
        if output.status.success() {
            return;
        }
        last = stderr(&output);
        thread::sleep(Duration::from_millis(100));
    }
    panic!("workspace invite never became available: {last}");
}

fn create_workspace(db: &str, name: &str, username: &str, device_name: &str) -> String {
    assert_success(topo(&[
        "--db",
        db,
        "create-workspace",
        name,
        "--username",
        username,
        "--devicename",
        device_name,
    ]))
}

fn workspace_invite_link(db: &str, workspace_id: &str, port: u16) -> String {
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

fn try_accept_link_with_retry(db: &str, invite: &str, device_name: &str) -> Result<String, String> {
    let mut last = String::new();
    for _ in 0..200 {
        let output = topo(&[
            "--db",
            db,
            "accept-link",
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

fn connection_count(db: &str) -> usize {
    count_value(db, "connections")
}

fn connection_event_count(db: &str) -> usize {
    count_value(db, "connection_events")
}

fn user_id_by_name(db: &str, workspace_id: &str, username: &str) -> String {
    let users = assert_success(topo(&["--db", db, "users", workspace_id]));
    users
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let id = parts.next()?;
            let name = parts.next()?;
            (name == username).then(|| id.to_string())
        })
        .next()
        .unwrap_or_else(|| panic!("missing user {username} in users output:\n{users}"))
}

fn replace_invite_workspace(invite: &str, workspace_id: &str) -> String {
    let mut replaced = false;
    let parts = invite
        .split('/')
        .map(|part| {
            if part.starts_with("WORKSPACE.") {
                replaced = true;
                format!("WORKSPACE.{workspace_id}")
            } else {
                part.to_string()
            }
        })
        .collect::<Vec<_>>();
    assert!(replaced, "invite missing WORKSPACE part: {invite}");
    parts.join("/")
}

fn assert_contains_all(text: &str, needles: &[&str]) {
    for needle in needles {
        assert!(text.contains(needle), "missing {needle:?} in:\n{text}");
    }
}

fn count_value(db: &str, key: &str) -> usize {
    let out = assert_success(topo(&["--db", db, "count"]));
    line_value(&out, key).parse().expect("parse count value")
}

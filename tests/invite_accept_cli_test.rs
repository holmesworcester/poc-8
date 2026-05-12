//! Black-box CLI tests for invite acceptance and bootstrap connection setup.
//!
//! These tests exercise process boundaries: listener startup, invite-link
//! parsing, accept/connect, and the resulting operator output. They do not seed
//! protocol rows or call workers directly, because the invariant under test is
//! that a fresh CLI process can bootstrap through the same public path an
//! operator would use.

mod cli_harness;

use std::io::{BufRead, BufReader};
use std::process::{Child, Output};
use std::thread;
use std::time::{Duration, Instant};

use cli_harness::*;

#[test]
fn invite_daemons_accept_and_connect_two_cli_processes() {
    let tmp = tempfile::tempdir().unwrap();
    let host = temp_db(&tmp, "host.db");
    let joiner = temp_db(&tmp, "joiner.db");
    let host_port = free_port();
    let joiner_port = free_port();

    let _host_daemon = spawn_daemon(&host, host_port);
    let _joiner_daemon = spawn_daemon(&joiner, joiner_port);
    let invite = transport_invite_link(&host, host_port);
    let accepted = accept_with_retry(&joiner, &invite);
    assert!(accepted.contains("connected:"), "{accepted}");

    wait_for_connection_count(&host, 1);
    assert_eq!(connection_count(&host), 1);
    assert_eq!(connection_count(&joiner), 1);
    assert_eq!(connection_event_count(&host), 2);
    assert_eq!(connection_event_count(&joiner), 2);
}

#[test]
fn invite_daemons_accept_two_separate_cli_processes() {
    let tmp = tempfile::tempdir().unwrap();
    let host = temp_db(&tmp, "host.db");
    let joiner_a = temp_db(&tmp, "joiner-a.db");
    let joiner_b = temp_db(&tmp, "joiner-b.db");
    let port = free_port();
    let joiner_a_port = free_port();
    let joiner_b_port = free_port();

    let _host_daemon = spawn_daemon(&host, port);
    let _joiner_a_daemon = spawn_daemon(&joiner_a, joiner_a_port);
    let _joiner_b_daemon = spawn_daemon(&joiner_b, joiner_b_port);
    let invite = transport_invite_link(&host, port);

    let accepted_a = accept_with_retry(&joiner_a, &invite);
    assert!(accepted_a.contains("connected:"), "{accepted_a}");
    let accepted_b = accept_with_retry(&joiner_b, &invite);
    assert!(accepted_b.contains("connected:"), "{accepted_b}");

    wait_for_connection_count(&host, 2);
    assert_eq!(connection_count(&host), 2);
    assert_eq!(connection_count(&joiner_a), 1);
    assert_eq!(connection_count(&joiner_b), 1);
    assert_eq!(connection_event_count(&host), 4);
    assert_eq!(connection_event_count(&joiner_a), 2);
    assert_eq!(connection_event_count(&joiner_b), 2);
}

#[test]
fn workspace_invite_accept_builds_identity_graph_over_two_cli_processes() {
    let tmp = tempfile::tempdir().unwrap();
    let host = temp_db(&tmp, "host.db");
    let joiner = temp_db(&tmp, "joiner.db");
    let host_port = free_port();
    let joiner_port = free_port();

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

    let _host_daemon = spawn_daemon(&host, host_port);
    let _joiner_daemon = spawn_daemon(&joiner, joiner_port);
    let invite = workspace_invite_link(&host, &workspace_id, host_port);
    let accepted = match try_accept_with_identity_retry(&joiner, &invite, "bob", "bob-phone") {
        Ok(output) => output,
        Err(err) => panic!("bob accept failed: {err}"),
    };
    assert!(accepted.contains("connected:"), "{accepted}");
    assert_eq!(line_value(&accepted, "workspace_id"), workspace_id);

    wait_for_workspaces_containing(&joiner, &["Alpha", &workspace_id]);
    wait_for_users_containing(&joiner, &workspace_id, &["alice", "bob"]);
    wait_for_users_containing(&host, &workspace_id, &["alice", "bob"]);
    assert_eq!(
        invite_accepted_count(&joiner),
        1,
        "acceptor should persist one local invite_accepted provenance row"
    );
    assert_eq!(
        invite_accepted_count(&host),
        0,
        "invite creator stores invite_secret authority, not invite_accepted provenance"
    );

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
fn workspace_invite_accept_against_start_daemon_eventually_joins_over_normal_connection() {
    // Invariant: accept records durable local intent and the daemons converge
    // through ordinary connection sync. The accept stream does not carry a
    // special invite-owner ancestry response.
    let tmp = tempfile::tempdir().unwrap();
    let host = temp_db(&tmp, "host.db");
    let joiner = temp_db(&tmp, "joiner.db");
    let host_port = free_port();
    let joiner_port = free_port();

    let created = create_workspace(&host, "Alpha", "alice", "alice-laptop");
    let workspace_id = line_value(&created, "workspace_id");
    let invite = workspace_invite_link(&host, &workspace_id, host_port);
    let _host_daemon = spawn_daemon(&host, host_port);
    let _joiner_daemon = spawn_daemon(&joiner, joiner_port);

    let accepted = try_accept_with_identity_timeout(
        &joiner,
        &invite,
        "bob",
        "bob-phone",
        Duration::from_secs(10),
    )
    .expect("accept against daemon");
    assert!(accepted.contains("connected:"), "{accepted}");
    assert_eq!(line_value(&accepted, "workspace_id"), workspace_id);

    wait_for_users_containing(&joiner, &workspace_id, &["alice", "bob"]);
    wait_for_users_containing(&host, &workspace_id, &["alice", "bob"]);
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

    let _host_daemon = spawn_daemon(&host, port);
    let _bob_daemon = spawn_daemon(&bob, free_port());
    let _carol_daemon = spawn_daemon(&carol, free_port());
    let invite = workspace_invite_link(&host, &workspace_id, port);
    let accepted_bob = match try_accept_with_identity_retry(&bob, &invite, "bob", "bob-phone") {
        Ok(output) => output,
        Err(err) => panic!("bob accept failed: {err}"),
    };
    assert_eq!(line_value(&accepted_bob, "workspace_id"), workspace_id);
    thread::sleep(Duration::from_millis(50));
    let accepted_carol =
        match try_accept_with_identity_retry(&carol, &invite, "carol", "carol-phone") {
            Ok(output) => output,
            Err(err) => panic!("carol accept failed: {err}"),
        };
    assert_eq!(line_value(&accepted_carol, "workspace_id"), workspace_id);

    wait_for_users_containing(&bob, &workspace_id, &["alice", "bob"]);
    wait_for_users_containing(&carol, &workspace_id, &["alice", "carol"]);
    wait_for_users_containing(&host, &workspace_id, &["alice", "bob", "carol"]);
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

    let _host_daemon = spawn_daemon(&host, port);
    let _bob_daemon = spawn_daemon(&bob, free_port());
    let _carol_daemon = spawn_daemon(&carol, free_port());
    let _dave_daemon = spawn_daemon(&dave, free_port());
    let invite = workspace_invite_link(&host, &workspace_id, port);
    for (db, username, device_name) in [
        (&bob, "bob", "bob-phone"),
        (&carol, "carol", "carol-phone"),
        (&dave, "dave", "dave-phone"),
    ] {
        let accepted = match try_accept_with_identity_retry(db, &invite, username, device_name) {
            Ok(output) => output,
            Err(err) => panic!("reused workspace invite accept failed: {err}"),
        };
        assert_eq!(line_value(&accepted, "workspace_id"), workspace_id);
    }

    wait_for_users_containing(&host, &workspace_id, &["alice", "bob", "carol", "dave"]);
    wait_for_users_containing(&dave, &workspace_id, &["alice", "dave"]);
}

#[test]
fn workspace_invites_mix_reuse_and_fresh_creation() {
    let tmp = tempfile::tempdir().unwrap();
    let host = temp_db(&tmp, "host.db");
    let bob = temp_db(&tmp, "bob.db");
    let carol = temp_db(&tmp, "carol.db");
    let dave = temp_db(&tmp, "dave.db");
    let port = free_port();

    let created = create_workspace(&host, "Alpha", "alice", "alice-laptop");
    let workspace_id = line_value(&created, "workspace_id");

    let _host_daemon = spawn_daemon(&host, port);
    let _bob_daemon = spawn_daemon(&bob, free_port());
    let _carol_daemon = spawn_daemon(&carol, free_port());
    let _dave_daemon = spawn_daemon(&dave, free_port());
    let old_invite = workspace_invite_link(&host, &workspace_id, port);
    let accepted_bob = match try_accept_with_identity_retry(&bob, &old_invite, "bob", "bob-phone") {
        Ok(output) => output,
        Err(err) => panic!("old invite bob accept failed: {err}"),
    };
    assert_eq!(line_value(&accepted_bob, "workspace_id"), workspace_id);

    let fresh_invite = workspace_invite_link(&host, &workspace_id, port);
    let accepted_carol =
        match try_accept_with_identity_retry(&carol, &fresh_invite, "carol", "carol-phone") {
            Ok(output) => output,
            Err(err) => panic!("fresh invite carol accept failed: {err}"),
        };
    assert_eq!(line_value(&accepted_carol, "workspace_id"), workspace_id);

    let accepted_dave =
        match try_accept_with_identity_retry(&dave, &old_invite, "dave", "dave-phone") {
            Ok(output) => output,
            Err(err) => panic!("old invite dave accept failed: {err}"),
        };
    assert_eq!(line_value(&accepted_dave, "workspace_id"), workspace_id);

    wait_for_users_containing(&host, &workspace_id, &["alice", "bob", "carol", "dave"]);
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

    let _host_daemon = spawn_daemon(&host, port);
    let _phone_daemon = spawn_daemon(&phone, free_port());
    let link = device_link_for_addr(&host, &workspace_id, port);
    let accepted = match try_accept_link_with_retry(&phone, &link, "alice-phone") {
        Ok(output) => output,
        Err(err) => panic!("device link accept failed: {err}"),
    };
    assert!(accepted.contains("connected:"), "{accepted}");
    assert_eq!(line_value(&accepted, "workspace_id"), workspace_id);

    wait_for_identity_containing(&phone, &[&workspace_id, &format!("user_id={user_id}")]);
    wait_for_users_containing(&host, &workspace_id, &["alice", &user_id]);
    wait_for_peers_containing(
        &host,
        &workspace_id,
        &["alice-laptop", "alice-phone", &format!("user_id={user_id}")],
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

    let _phone_daemon = spawn_daemon(&phone, old_port);
    let _laptop_daemon = spawn_daemon(&laptop, fresh_port);
    let _tablet_daemon = spawn_daemon(&tablet, free_port());
    let _desktop_daemon = spawn_daemon(&desktop, free_port());

    let old_link = device_link_for_addr(&phone, &workspace_id, old_port);
    let accepted_laptop = match try_accept_link_with_retry(&laptop, &old_link, "alice-laptop") {
        Ok(output) => output,
        Err(err) => panic!("old device link laptop accept failed: {err}"),
    };
    assert_eq!(line_value(&accepted_laptop, "workspace_id"), workspace_id);
    wait_for_identity_containing(&laptop, &[&workspace_id, &format!("user_id={user_id}")]);

    let fresh_link = device_link_for_addr(&laptop, &workspace_id, fresh_port);
    let accepted_tablet = match try_accept_link_with_retry(&tablet, &fresh_link, "alice-tablet") {
        Ok(output) => output,
        Err(err) => panic!("fresh device link tablet accept failed: {err}"),
    };
    assert_eq!(line_value(&accepted_tablet, "workspace_id"), workspace_id);

    let accepted_desktop = match try_accept_link_with_retry(&desktop, &old_link, "alice-desktop") {
        Ok(output) => output,
        Err(err) => panic!("old device link desktop accept failed: {err}"),
    };
    assert_eq!(line_value(&accepted_desktop, "workspace_id"), workspace_id);

    wait_for_peers_containing(
        &phone,
        &workspace_id,
        &["alice-phone", "alice-laptop", "alice-desktop"],
    );
    wait_for_peers_containing(&phone, &workspace_id, &[&format!("user_id={user_id}")]);

    wait_for_peers_containing(
        &laptop,
        &workspace_id,
        &["alice-phone", "alice-laptop", "alice-tablet"],
    );
    wait_for_peers_containing(&laptop, &workspace_id, &[&format!("user_id={user_id}")]);
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

    let created = create_workspace(&alice, "Alpha", "alice", "alice-laptop");
    let workspace_id = line_value(&created, "workspace_id");
    let alice_user_id = line_value(&created, "user_id");

    let _alice_daemon = spawn_daemon(&alice, alice_invite_port);
    let _bob_daemon = spawn_daemon(&bob, bob_route_port);
    let alice_invite = workspace_invite_link(&alice, &workspace_id, alice_invite_port);
    let accepted_bob = match try_accept_with_identity_retry(&bob, &alice_invite, "bob", "bob-phone")
    {
        Ok(output) => output,
        Err(err) => panic!("bob accept failed: {err}"),
    };
    assert_eq!(line_value(&accepted_bob, "workspace_id"), workspace_id);
    wait_for_users_containing(&bob, &workspace_id, &["alice", "bob"]);
    wait_for_local_workspace_join(&bob, &workspace_id);
    wait_for_users_containing(&alice, &workspace_id, &["alice", "bob"]);

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

    let _ = alice_route_port;
    wait_until_invite_can_be_created(&bob, &workspace_id, bob_route_port);

    let bob_invite = workspace_invite_link(&bob, &workspace_id, bob_route_port);
    let _carol_daemon = spawn_daemon(&carol, free_port());
    let accepted_carol =
        match try_accept_with_identity_retry(&carol, &bob_invite, "carol", "carol-phone") {
            Ok(output) => output,
            Err(err) => panic!("carol accept failed: {err}"),
        };
    assert_eq!(line_value(&accepted_carol, "workspace_id"), workspace_id);

    wait_for_users_containing(&bob, &workspace_id, &["alice", "bob", "carol"]);
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
    let _host_daemon = spawn_daemon(&host, alpha_port);
    let _joiner_daemon = spawn_daemon(&joiner, free_port());
    let alpha_invite = workspace_invite_link(&host, &alpha_id, alpha_port);
    let accepted_alpha = match try_accept_with_identity_retry(
        &joiner,
        &alpha_invite,
        "bob-alpha",
        "bob-alpha-phone",
    ) {
        Ok(output) => output,
        Err(err) => panic!("alpha accept failed: {err}"),
    };
    assert_eq!(line_value(&accepted_alpha, "workspace_id"), alpha_id);
    wait_for_workspaces_containing(&joiner, &["Alpha", &alpha_id]);

    let beta = create_workspace(&host, "Beta", "alice-beta", "alice-beta-laptop");
    let beta_id = line_value(&beta, "workspace_id");
    let beta_invite = workspace_invite_link(&host, &beta_id, alpha_port);
    let accepted_beta =
        match try_accept_with_identity_retry(&joiner, &beta_invite, "bob-beta", "bob-beta-phone") {
            Ok(output) => output,
            Err(err) => panic!("beta accept failed: {err}"),
        };
    assert_eq!(line_value(&accepted_beta, "workspace_id"), beta_id);
    let _ = beta_port;
    wait_for_workspaces_containing(&joiner, &["Alpha", "Beta", &alpha_id, &beta_id]);

    wait_for_users_containing(&joiner, &alpha_id, &["alice-alpha", "bob-alpha"]);
    let alpha_users = assert_success(topo(&["--db", &joiner, "users", &alpha_id]));
    assert!(!alpha_users.contains("bob-beta"), "{alpha_users}");
    wait_for_users_containing(&joiner, &beta_id, &["alice-beta", "bob-beta"]);
    let beta_users = assert_success(topo(&["--db", &joiner, "users", &beta_id]));
    assert!(!beta_users.contains("bob-alpha"), "{beta_users}");

    let duplicate_invite = workspace_invite_link(&host, &alpha_id, alpha_port);
    let _ = duplicate_port;
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
    let _attacker_daemon = spawn_daemon(&attacker, attacker_port);
    let attacker_invite = workspace_invite_link(&attacker, &attacker_workspace_id, attacker_port);
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

fn transport_invite_link(db: &str, port: u16) -> String {
    let addr = format!("127.0.0.1:{port}");
    let out = assert_success(topo(&["--db", db, "invite", "--public-addr", &addr]));
    invite_link_from_output(&out)
}

fn device_link_for_addr(db: &str, workspace_id: &str, port: u16) -> String {
    let addr = format!("127.0.0.1:{port}");
    let out = assert_success(topo(&[
        "--db",
        db,
        "link",
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
        if !last.contains("open tcp stream") && !last.contains("user invite was not received") {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(last)
}

fn try_accept_with_identity_timeout(
    db: &str,
    invite: &str,
    username: &str,
    device_name: &str,
    timeout: Duration,
) -> Result<String, String> {
    let start = Instant::now();
    let mut last = String::new();
    while start.elapsed() < timeout {
        let output = topo_with_timeout(
            &[
                "--db",
                db,
                "accept",
                invite,
                "--username",
                username,
                "--devicename",
                device_name,
            ],
            Duration::from_secs(3),
        )?;
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

fn topo_with_timeout(args: &[&str], timeout: Duration) -> Result<Output, String> {
    let mut child = spawn_topo(args);
    let start = Instant::now();
    loop {
        if child
            .try_wait()
            .map_err(|err| format!("poll topo child: {err}"))?
            .is_some()
        {
            return child
                .wait_with_output()
                .map_err(|err| format!("wait topo child: {err}"));
        }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let output = child
                .wait_with_output()
                .map_err(|err| format!("wait killed topo child: {err}"))?;
            return Err(format!(
                "topo command timed out\nstdout={}\nstderr={}",
                stdout(&output),
                stderr(&output)
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
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
        if !last.contains("open tcp stream") && !last.contains("device invite was not received") {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err(last)
}

fn wait_for_users_containing(db: &str, workspace_id: &str, users: &[&str]) {
    let start = Instant::now();
    let mut last = String::new();
    while start.elapsed() < Duration::from_secs(10) {
        let output = topo(&["--db", db, "users", workspace_id]);
        if output.status.success() {
            let text = stdout(&output);
            if users.iter().all(|user| text.contains(user)) {
                return;
            }
            last = text;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("users never contained {users:?}:\n{last}");
}

fn wait_for_workspaces_containing(db: &str, values: &[&str]) {
    let start = Instant::now();
    let mut last = String::new();
    while start.elapsed() < Duration::from_secs(10) {
        let output = topo(&["--db", db, "workspaces"]);
        if output.status.success() {
            let text = stdout(&output);
            if values.iter().all(|value| text.contains(value)) {
                return;
            }
            last = text;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("workspaces never contained {values:?}:\n{last}");
}

fn wait_for_identity_containing(db: &str, values: &[&str]) {
    let start = Instant::now();
    let mut last = String::new();
    while start.elapsed() < Duration::from_secs(10) {
        let output = topo(&["--db", db, "identity"]);
        if output.status.success() {
            let text = stdout(&output);
            if values.iter().all(|value| text.contains(value)) {
                return;
            }
            last = text;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("identity never contained {values:?}:\n{last}");
}

fn wait_for_local_workspace_join(db: &str, workspace_id: &str) {
    let start = Instant::now();
    let mut last = String::new();
    while start.elapsed() < Duration::from_secs(10) {
        let output = topo(&["--db", db, "key-recipient", workspace_id]);
        if output.status.success() {
            return;
        }
        last = stderr(&output);
        thread::sleep(Duration::from_millis(50));
    }
    panic!("local endpoint never joined workspace {workspace_id}: {last}");
}

fn wait_for_peers_containing(db: &str, workspace_id: &str, values: &[&str]) {
    let start = Instant::now();
    let mut last = String::new();
    while start.elapsed() < Duration::from_secs(10) {
        let output = topo(&["--db", db, "peers", workspace_id]);
        if output.status.success() {
            let text = stdout(&output);
            if values.iter().all(|value| text.contains(value)) {
                return;
            }
            last = text;
        } else {
            last = stderr(&output);
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("peers never contained {values:?}:\n{last}");
}

fn connection_count(db: &str) -> usize {
    count_value(db, "connections")
}

fn wait_for_connection_count(db: &str, expected: usize) {
    for _ in 0..100 {
        if connection_count(db) == expected {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "connection count never reached {expected}; current {}",
        connection_count(db)
    );
}

fn connection_event_count(db: &str) -> usize {
    count_value(db, "connection_events")
}

fn invite_accepted_count(db: &str) -> usize {
    count_value(db, "invite_accepted")
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

fn count_value(db: &str, key: &str) -> usize {
    let out = assert_success(topo(&["--db", db, "count"]));
    line_value(&out, key).parse().expect("parse count value")
}

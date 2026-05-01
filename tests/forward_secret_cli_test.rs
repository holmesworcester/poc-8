use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_topo")
}

struct Daemon {
    child: Child,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn temp_db() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db").to_string_lossy().to_string();
    (dir, db)
}

fn start_daemon(db: &str) -> Daemon {
    let mut child = Command::new(bin())
        .arg("--db")
        .arg(db)
        .arg("start")
        .arg("--bind")
        .arg("127.0.0.1:0")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start topo daemon");
    let deadline = Instant::now() + Duration::from_millis(500);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("poll daemon") {
            panic!("daemon exited during startup: {status}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Daemon { child }
}

fn topo_cmd(db: &str, args: &[&str]) -> Output {
    Command::new(bin())
        .arg("--db")
        .arg(db)
        .args(args)
        .output()
        .expect("run topo command")
}

fn assert_success(output: Output, label: &str) -> String {
    if !output.status.success() {
        panic!(
            "{label} failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8(output.stdout).expect("stdout utf8")
}

fn run(db: &str, args: &[&str]) -> String {
    assert_success(topo_cmd(db, args), &args.join(" "))
}

fn field(stdout: &str, name: &str) -> String {
    stdout
        .split_whitespace()
        .find_map(|token| token.strip_prefix(&format!("{name}=")))
        .unwrap_or_else(|| panic!("missing {name}= in output:\n{stdout}"))
        .to_string()
}

fn create_workspace(db: &str) {
    run(db, &["create-workspace", "fs-cli"]);
}

#[test]
fn forward_secret_cli_purges_old_pubkey_and_deleted_message_is_unrecoverable() {
    let (_dir, db) = temp_db();
    let _daemon = start_daemon(&db);
    create_workspace(&db);

    let alice = field(&run(&db, &["fs", "recipient", "alice"]), "recipient_id");
    let old_pubkey = field(
        &run(&db, &["fs", "pubkey", &alice, "alice-v1"]),
        "pubkey_id",
    );
    let epoch = field(&run(&db, &["fs", "epoch", "root-v1"]), "epoch_id");
    let message_out = run(&db, &["fs", "message", &epoch, "msg-1"]);
    let coord = field(&message_out, "coord_event_id");
    let minute = field(&message_out, "unix_minute");

    let expand = run(&db, &["fs", "expand"]);
    assert!(
        expand.contains("emitted_wraps=1"),
        "expected initial wrap:\n{expand}"
    );

    let local_key = run(&db, &["fs", "private-key", &old_pubkey, "alice-v1"]);
    assert!(
        local_key.contains("local_material=present"),
        "expected private key install:\n{local_key}"
    );

    let expand = run(&db, &["fs", "expand"]);
    assert!(
        expand.contains("emitted_receipts=1"),
        "expected receipt after private key install:\n{expand}"
    );

    let new_pubkey = field(
        &run(
            &db,
            &["fs", "pubkey", &alice, "alice-v2", "--prev", &old_pubkey],
        ),
        "pubkey_id",
    );
    let expand = run(&db, &["fs", "expand"]);
    assert!(
        expand.contains(&format!("purged_pubkey_id={old_pubkey}")),
        "expected old pubkey purge after tombstone+receipt:\n{expand}"
    );

    let keys = run(&db, &["fs", "keys"]);
    assert!(
        keys.contains(&format!(
            "pubkey_id={old_pubkey} recipient_id={alice} status=tombstoned local_material=purged"
        )),
        "old key should be tombstoned and locally purged:\n{keys}"
    );
    assert!(
        keys.contains(&format!(
            "pubkey_id={new_pubkey} recipient_id={alice} status=active local_material=absent"
        )),
        "new key should remain active:\n{keys}"
    );

    run(&db, &["fs", "delete", &epoch, &coord, &minute]);
    let compromised_old = run(&db, &["fs", "private-key", &old_pubkey, "alice-v1"]);
    assert!(
        compromised_old.contains("local_material=purged skipped=true"),
        "post-purge compromise should not restore old key material:\n{compromised_old}"
    );

    let recoverable = run(&db, &["fs", "recoverable", &epoch, &coord, &minute]);
    assert!(
        recoverable.contains("recoverable=no"),
        "deleted message should be unrecoverable from live local key material:\n{recoverable}"
    );
}

#[test]
fn forward_secret_cli_partitioned_join_gets_wrap_but_removed_recipient_does_not() {
    let (_dir, db) = temp_db();
    let _daemon = start_daemon(&db);
    create_workspace(&db);

    let alice = field(&run(&db, &["fs", "recipient", "alice"]), "recipient_id");
    let alice_pubkey = field(
        &run(&db, &["fs", "pubkey", &alice, "alice-v1"]),
        "pubkey_id",
    );
    let bob = field(&run(&db, &["fs", "recipient", "bob"]), "recipient_id");
    let bob_pubkey = field(&run(&db, &["fs", "pubkey", &bob, "bob-v1"]), "pubkey_id");

    let epoch = field(
        &run(&db, &["fs", "epoch", "root-v1", "--remove-recipient", &bob]),
        "epoch_id",
    );
    let expand = run(&db, &["fs", "expand"]);
    assert!(
        expand.contains("emitted_wraps=1"),
        "only alice should receive initial epoch wrap:\n{expand}"
    );
    let wraps = run(&db, &["fs", "wraps"]);
    assert!(
        wraps.contains(&format!("epoch_id={epoch} pubkey_id={alice_pubkey}")),
        "alice should have a wrap:\n{wraps}"
    );
    assert!(
        !wraps.contains(&bob_pubkey),
        "removed bob must not receive a wrap:\n{wraps}"
    );

    let cara = field(&run(&db, &["fs", "recipient", "cara"]), "recipient_id");
    let cara_pubkey = field(&run(&db, &["fs", "pubkey", &cara, "cara-v1"]), "pubkey_id");
    let expand = run(&db, &["fs", "expand"]);
    assert!(
        expand.contains("emitted_wraps=1"),
        "late unknown join should deterministically get a wrap:\n{expand}"
    );
    let wraps = run(&db, &["fs", "wraps"]);
    assert!(
        wraps.contains(&format!("epoch_id={epoch} pubkey_id={cara_pubkey}")),
        "late joining cara should have a wrap:\n{wraps}"
    );
    assert!(
        !wraps.contains(&bob_pubkey),
        "removed bob must stay excluded after later joins:\n{wraps}"
    );
}

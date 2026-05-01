mod cli_harness;

use cli_harness::*;
use std::time::Instant;

#[test]
fn sync_perf_reports_message_rate_for_generated_events() {
    let tmp = tempfile::tempdir().unwrap();
    let alice_db = temp_db(&tmp, "alice.db");
    let bob_db = temp_db(&tmp, "bob.db");
    let count = 1_000usize;

    create_workspace(&alice_db, "perf");
    sync_from(&bob_db, &alice_db);

    let generated = assert_success(topo(
        &alice_db,
        &[
            "generate",
            "--count",
            &count.to_string(),
            "--prefix",
            "perf",
        ],
    ));
    assert!(generated.contains("generated_messages: 1000"));

    let start = Instant::now();
    let sync = assert_success(topo(&bob_db, &["sync-from", &alice_db]));
    let elapsed = start.elapsed();

    assert!(sync.contains("imported_events: 1000"), "{sync}");
    assert!(sync.contains("projected_events: 1000"), "{sync}");

    let messages = assert_success(topo(&bob_db, &["messages"]));
    assert!(messages.contains("MESSAGES (1000):"));
    assert!(messages.contains("perf 000000"));
    assert!(messages.contains("perf 000999"));

    let duplicate_sync = assert_success(topo(&bob_db, &["sync-from", &alice_db]));
    assert!(
        duplicate_sync.contains("imported_events: 0"),
        "{duplicate_sync}"
    );
    assert!(
        duplicate_sync.contains("projected_events: 0"),
        "{duplicate_sync}"
    );

    let seconds = elapsed.as_secs_f64().max(0.000_001);
    let messages_per_second = count as f64 / seconds;
    eprintln!(
        "sync_perf messages: count={count} elapsed_ms={} rate={messages_per_second:.0} messages/s",
        elapsed.as_millis()
    );
    assert!(messages_per_second.is_finite() && messages_per_second > 0.0);
}

#[test]
fn sync_perf_reports_file_throughput_for_file_event() {
    let tmp = tempfile::tempdir().unwrap();
    let alice_db = temp_db(&tmp, "alice.db");
    let bob_db = temp_db(&tmp, "bob.db");
    let file_path = tmp.path().join("payload.bin");
    let byte_len = 4 * 1024 * 1024usize;
    let bytes = (0..byte_len)
        .map(|idx| ((idx * 31 + 17) % 251) as u8)
        .collect::<Vec<_>>();
    let expected_hash = blake3::hash(&bytes).to_hex().to_string();
    std::fs::write(&file_path, &bytes).unwrap();

    create_workspace(&alice_db, "files");
    sync_from(&bob_db, &alice_db);

    let sent = assert_success(topo(&alice_db, &["send-file", file_path.to_str().unwrap()]));
    assert!(sent.contains("file: payload.bin"));
    assert!(sent.contains(&expected_hash));

    let start = Instant::now();
    let sync = assert_success(topo(&bob_db, &["sync-from", &alice_db]));
    let elapsed = start.elapsed();

    assert!(sync.contains("imported_events: 1"), "{sync}");
    assert!(sync.contains("projected_events: 1"), "{sync}");

    let files = assert_success(topo(&bob_db, &["files"]));
    assert!(files.contains("FILES (1):"));
    assert!(files.contains("payload.bin"));
    assert!(files.contains("4194304 bytes"));
    assert!(files.contains(&expected_hash));

    let out_path = tmp.path().join("synced-payload.bin");
    let saved = assert_success(topo(
        &bob_db,
        &["save-file", "1", "--out", out_path.to_str().unwrap()],
    ));
    assert!(saved.contains("file: payload.bin"));
    assert_eq!(std::fs::read(out_path).unwrap(), bytes);

    let duplicate_sync = assert_success(topo(&bob_db, &["sync-from", &alice_db]));
    assert!(
        duplicate_sync.contains("imported_events: 0"),
        "{duplicate_sync}"
    );
    assert!(
        duplicate_sync.contains("projected_events: 0"),
        "{duplicate_sync}"
    );

    let seconds = elapsed.as_secs_f64().max(0.000_001);
    let mib_per_second = (byte_len as f64 / 1_048_576.0) / seconds;
    eprintln!(
        "sync_perf file: bytes={byte_len} elapsed_ms={} rate={mib_per_second:.2} MiB/s",
        elapsed.as_millis()
    );
    assert!(mib_per_second.is_finite() && mib_per_second > 0.0);
}

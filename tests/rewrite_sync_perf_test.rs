mod cli_harness;

use cli_harness::*;
use std::time::Instant;

const ALICE_TO_BOB: &str = "5555555555555555555555555555555555555555555555555555555555555555";

#[test]
fn tcp_sync_perf_reports_message_rate_for_generated_events() {
    let tmp = tempfile::tempdir().unwrap();
    let alice_db = temp_db(&tmp, "alice.db");
    let bob_db = temp_db(&tmp, "bob.db");
    let count = 200usize;

    create_workspace(&alice_db, "perf");
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
    assert!(generated.contains("generated_messages: 200"));
    queue_events(&alice_db, ALICE_TO_BOB, None);

    let addr = free_addr();
    let receiver = spawn_receive(&bob_db, &addr, count + 1);
    let start = Instant::now();
    let sent = send_pending_with_retry(&alice_db, ALICE_TO_BOB, &addr);
    let elapsed = start.elapsed();
    assert!(sent.contains("sent_events: 201"), "{sent}");

    let received = receiver.wait_with_output().unwrap();
    assert!(
        received.status.success(),
        "receive failed: stdout={} stderr={}",
        stdout(&received),
        stderr(&received)
    );
    let receive_out = stdout(&received);
    assert!(
        receive_out.contains("received_events: 201"),
        "{receive_out}"
    );
    assert!(
        receive_out.contains("projected_events: 201"),
        "{receive_out}"
    );

    let messages = assert_success(topo(&bob_db, &["messages"]));
    assert!(messages.contains("MESSAGES (200):"));
    assert!(messages.contains("perf 000000"));
    assert!(messages.contains("perf 000199"));

    let seconds = elapsed.as_secs_f64().max(0.000_001);
    let messages_per_second = count as f64 / seconds;
    eprintln!(
        "tcp_sync_perf messages: count={count} elapsed_ms={} rate={messages_per_second:.0} messages/s",
        elapsed.as_millis()
    );
    assert!(messages_per_second.is_finite() && messages_per_second > 0.0);
}

#[test]
fn tcp_sync_perf_reports_file_throughput_for_file_event() {
    let tmp = tempfile::tempdir().unwrap();
    let alice_db = temp_db(&tmp, "alice.db");
    let bob_db = temp_db(&tmp, "bob.db");
    let file_path = tmp.path().join("payload.bin");
    let byte_len = 2 * 1024 * 1024usize;
    let bytes = (0..byte_len)
        .map(|idx| ((idx * 31 + 17) % 251) as u8)
        .collect::<Vec<_>>();
    let expected_hash = blake3::hash(&bytes).to_hex().to_string();
    std::fs::write(&file_path, &bytes).unwrap();

    create_workspace(&alice_db, "files");
    let sent_file = assert_success(topo(&alice_db, &["send-file", file_path.to_str().unwrap()]));
    assert!(sent_file.contains("file: payload.bin"));
    assert!(sent_file.contains(&expected_hash));
    queue_events(&alice_db, ALICE_TO_BOB, None);

    let addr = free_addr();
    let receiver = spawn_receive(&bob_db, &addr, 2);
    let start = Instant::now();
    let sent = send_pending_with_retry(&alice_db, ALICE_TO_BOB, &addr);
    let elapsed = start.elapsed();
    assert!(sent.contains("sent_events: 2"), "{sent}");

    let received = receiver.wait_with_output().unwrap();
    assert!(
        received.status.success(),
        "receive failed: stdout={} stderr={}",
        stdout(&received),
        stderr(&received)
    );

    let files = assert_success(topo(&bob_db, &["files"]));
    assert!(files.contains("FILES (1):"));
    assert!(files.contains("payload.bin"));
    assert!(files.contains("2097152 bytes"));
    assert!(files.contains(&expected_hash));

    let out_path = tmp.path().join("synced-payload.bin");
    let saved = assert_success(topo(
        &bob_db,
        &["save-file", "1", "--out", out_path.to_str().unwrap()],
    ));
    assert!(saved.contains("file: payload.bin"));
    assert_eq!(std::fs::read(out_path).unwrap(), bytes);

    let seconds = elapsed.as_secs_f64().max(0.000_001);
    let mib_per_second = (byte_len as f64 / 1_048_576.0) / seconds;
    eprintln!(
        "tcp_sync_perf file: bytes={byte_len} elapsed_ms={} rate={mib_per_second:.2} MiB/s",
        elapsed.as_millis()
    );
    assert!(mib_per_second.is_finite() && mib_per_second > 0.0);
}

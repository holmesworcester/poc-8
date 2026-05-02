mod cli_harness;

use std::time::{Duration, Instant};

use cli_harness::*;

#[test]
fn sync_converges_over_real_tcp() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let port = free_port();

    let listener = start_listener(&bob, port, 2);
    let connected = connect_with_retry(&alice, port);
    assert!(connected.contains("connected:"));

    let event_count = 128usize;
    let event_size = 256usize;
    let generated = generate(&alice, event_count, event_size);
    assert!(generated.contains("generated_events: 128"));

    let started = Instant::now();
    let sync_out = sync(&alice);
    assert!(sync_out.contains("peers_synced: 1"), "{sync_out}");

    let server_out = wait_success(listener, "sync listener");
    assert!(
        server_out.contains("received_events: 128"),
        "listener output:\n{server_out}"
    );

    assert_eventually_count(&bob, event_count, Duration::from_secs(5));
    let elapsed = started.elapsed();
    let seconds = elapsed.as_secs_f64().max(0.000_001);
    let events_per_second = event_count as f64 / seconds;
    let mib_per_second = (event_count * event_size) as f64 / 1_048_576.0 / seconds;
    eprintln!(
        "black_box_sync count={event_count} size={event_size} elapsed_ms={} events_per_s={events_per_second:.0} MiB_per_s={mib_per_second:.2}",
        elapsed.as_millis()
    );
}

#[test]
fn sync_perf_reports_10k_event_rate_from_sync_start_to_all_counted() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let port = free_port();

    let listener = start_listener(&bob, port, 2);
    connect_with_retry(&alice, port);

    let event_count = 10_000usize;
    let event_size = 512usize;
    let generated = generate(&alice, event_count, event_size);
    assert!(generated.contains("generated_events: 10000"));

    let started = Instant::now();
    let sync_out = sync(&alice);
    assert!(sync_out.contains("peers_synced: 1"), "{sync_out}");
    wait_success(listener, "perf sync listener");
    assert_eventually_count(&bob, event_count, Duration::from_secs(30));
    let elapsed = started.elapsed();

    let seconds = elapsed.as_secs_f64().max(0.000_001);
    let events_per_second = event_count as f64 / seconds;
    let mib_per_second = (event_count * event_size) as f64 / 1_048_576.0 / seconds;
    eprintln!(
        "black_box_sync_perf count={event_count} size={event_size} elapsed_ms={} events_per_s={events_per_second:.0} MiB_per_s={mib_per_second:.2}",
        elapsed.as_millis()
    );

    assert!(events_per_second.is_finite() && events_per_second > 0.0);
    assert!(mib_per_second.is_finite() && mib_per_second > 0.0);
}

#[test]
fn sync_splits_large_payloads_into_transport_sized_frames() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let port = free_port();

    let listener = start_listener(&bob, port, 2);
    connect_with_retry(&alice, port);

    let event_count = 600usize;
    let event_size = 256 * 1024usize;
    let generated = generate(&alice, event_count, event_size);
    assert!(generated.contains("generated_events: 600"));

    let started = Instant::now();
    let sync_out = sync(&alice);
    assert!(sync_out.contains("peers_synced: 1"), "{sync_out}");
    wait_success(listener, "large payload sync listener");
    assert_eventually_count(&bob, event_count, Duration::from_secs(60));
    let elapsed = started.elapsed();

    let seconds = elapsed.as_secs_f64().max(0.000_001);
    let events_per_second = event_count as f64 / seconds;
    let mib_per_second = (event_count * event_size) as f64 / 1_048_576.0 / seconds;
    eprintln!(
        "black_box_large_payload_sync count={event_count} size={event_size} elapsed_ms={} events_per_s={events_per_second:.0} MiB_per_s={mib_per_second:.2}",
        elapsed.as_millis()
    );

    assert!(events_per_second.is_finite() && events_per_second > 0.0);
    assert!(mib_per_second.is_finite() && mib_per_second > 0.0);
}

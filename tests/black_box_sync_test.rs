mod cli_harness;

use std::time::{Duration, Instant};

use cli_harness::*;

#[test]
fn sync_converges_over_real_tcp() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let port = free_port();
    let bob_invite = invite(&bob, port);

    let listener = start_listener(&bob, port, 2);
    let connected = connect_with_retry(&alice, &bob_invite);
    assert!(connected.contains("connected:"));

    let event_count = 128usize;
    let event_size = 256usize;
    let generated = generate(&alice, event_count, event_size);
    assert!(generated.contains("generated_events: 128"));

    let started = Instant::now();
    let sync_out = sync(&alice);
    assert!(sync_out.contains("routes_synced: 1"), "{sync_out}");

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
    let bob_invite = invite(&bob, port);

    let listener = start_listener(&bob, port, 2);
    connect_with_retry(&alice, &bob_invite);

    let event_count = 10_000usize;
    let event_size = 512usize;
    let generated = generate(&alice, event_count, event_size);
    assert!(generated.contains("generated_events: 10000"));

    let started = Instant::now();
    let sync_out = sync(&alice);
    assert!(sync_out.contains("routes_synced: 1"), "{sync_out}");
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
    let bob_invite = invite(&bob, port);

    let listener = start_listener(&bob, port, 2);
    connect_with_retry(&alice, &bob_invite);

    let event_count = 600usize;
    let event_size = 256 * 1024usize;
    let generated = generate(&alice, event_count, event_size);
    assert!(generated.contains("generated_events: 600"));

    let started = Instant::now();
    let sync_out = sync(&alice);
    assert!(sync_out.contains("routes_synced: 1"), "{sync_out}");
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

#[test]
fn invited_alice_bob_and_carol_sync_but_uninvited_mallory_cannot_connect() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = temp_db(&tmp, "alice.db");
    let bob = temp_db(&tmp, "bob.db");
    let carol = temp_db(&tmp, "carol.db");
    let mallory = temp_db(&tmp, "mallory.db");

    let alice_port = free_port();
    let bob_port = free_port();
    let carol_port = free_port();
    let alice_invite = invite(&alice, alice_port);
    let bob_invite = invite(&bob, bob_port);
    let carol_invite = invite(&carol, carol_port);

    let alice_listener = start_listener(&alice, alice_port, 4);
    let bob_listener = start_listener(&bob, bob_port, 4);
    let carol_listener = start_listener(&carol, carol_port, 4);

    connect_with_retry(&alice, &bob_invite);
    connect_with_retry(&alice, &carol_invite);
    connect_with_retry(&bob, &alice_invite);
    connect_with_retry(&bob, &carol_invite);
    connect_with_retry(&carol, &alice_invite);
    connect_with_retry(&carol, &bob_invite);

    let events_per_node = 24usize;
    let alice_event_size = 256usize;
    let bob_event_size = 257usize;
    let carol_event_size = 258usize;
    generate(&alice, events_per_node, alice_event_size);
    generate(&bob, events_per_node, bob_event_size);
    generate(&carol, events_per_node, carol_event_size);

    let started = Instant::now();
    let alice_sync = sync(&alice);
    let bob_sync = sync(&bob);
    let carol_sync = sync(&carol);
    assert!(alice_sync.contains("routes_synced: 2"), "{alice_sync}");
    assert!(bob_sync.contains("routes_synced: 2"), "{bob_sync}");
    assert!(carol_sync.contains("routes_synced: 2"), "{carol_sync}");

    wait_success(alice_listener, "alice listener");
    wait_success(bob_listener, "bob listener");
    wait_success(carol_listener, "carol listener");

    let total_events = events_per_node * 3;
    assert_eventually_count(&alice, total_events, Duration::from_secs(10));
    assert_eventually_count(&bob, total_events, Duration::from_secs(10));
    assert_eventually_count(&carol, total_events, Duration::from_secs(10));

    let elapsed = started.elapsed();
    let seconds = elapsed.as_secs_f64().max(0.000_001);
    let events_per_second = total_events as f64 / seconds;
    let total_payload_bytes =
        events_per_node * (alice_event_size + bob_event_size + carol_event_size);
    let mib_per_second = total_payload_bytes as f64 / 1_048_576.0 / seconds;
    eprintln!(
        "black_box_invited_triangle_sync count_per_node={events_per_node} elapsed_ms={} events_per_s={events_per_second:.0} MiB_per_s={mib_per_second:.2}",
        elapsed.as_millis()
    );

    let no_invite_connect = topo(&mallory, &["connect", &format!("127.0.0.1:{bob_port}")]);
    assert!(
        !no_invite_connect.status.success(),
        "mallory unexpectedly connected with port only:\n{}",
        stdout(&no_invite_connect)
    );
    assert!(
        stderr(&no_invite_connect).contains("invite must start with topo://invite/"),
        "stderr:\n{}",
        stderr(&no_invite_connect)
    );

    let wrong_private_key = "00".repeat(32);
    let wrong_bob_invite = replace_invite_private_key(&bob_invite, &wrong_private_key);
    let mallory_listener = start_listener(&bob, bob_port, 1);
    let mallory_connect = connect_with_invite_after_listener(&mallory, &wrong_bob_invite);
    assert!(
        !mallory_connect.status.success(),
        "mallory unexpectedly connected:\n{}",
        stdout(&mallory_connect)
    );
    let rejected = mallory_listener
        .wait_with_output()
        .expect("wait for mallory rejection");
    assert!(
        !rejected.status.success(),
        "bob unexpectedly accepted mallory:\n{}",
        stdout(&rejected)
    );
    assert_eq!(connection_count(&mallory), 0);
    assert_eq!(count(&mallory), 0);
}

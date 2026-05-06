mod cli_harness;

use std::time::Instant;

use cli_harness::*;

// Invariant: cascade cli replays event with deps out of order and unblocks 10k.
#[test]
fn cascade_cli_replays_event_with_deps_out_of_order_and_unblocks_10k() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "cascade.db");

    let staged = assert_success(topo(&["--db", &db, "generate-deps", "10000", "10"]));
    assert_eq!(line_value(&staged, "staged_events"), "10000");
    assert_eq!(line_value(&staged, "deps_per_event"), "10");
    assert_eq!(line_value(&staged, "dep_edges"), "99945");
    let status = assert_success(topo(&["--db", &db, "count"]));
    assert_eq!(
        line_value(&status, "events"),
        "0",
        "staged fixtures must be local-only"
    );

    let started = Instant::now();
    let replayed = assert_success(topo(&["--db", &db, "replay-deps-reverse"]));
    let elapsed = started.elapsed();

    assert_eq!(line_value(&replayed, "replayed_events"), "10000");
    assert_eq!(line_value(&replayed, "blocked_after_reverse"), "9990");
    assert_eq!(line_value(&replayed, "applied_events"), "10000");
    assert_eq!(line_value(&replayed, "ready_events"), "0");
    assert_eq!(line_value(&replayed, "blocked_events"), "0");
    assert_eq!(line_value(&replayed, "blocked_edges"), "0");

    let status = assert_success(topo(&["--db", &db, "count"]));
    assert_eq!(line_value(&status, "events"), "10000");
    assert_eq!(line_value(&status, "applied_events"), "10000");
    assert_eq!(line_value(&status, "blocked_events"), "0");
    assert_eq!(line_value(&status, "blocked_edges"), "0");

    let seconds = elapsed.as_secs_f64().max(0.001);
    let rate = 10_000f64 / seconds;
    eprintln!("black_box_cascade_10k events_per_s={rate:.0}");
    assert!(rate.is_finite() && rate > 0.0);
}

// Invariant: ignored 50k cascade run preserves unblock correctness at stress scale.
#[test]
#[ignore]
fn cascade_cli_replays_event_with_deps_out_of_order_and_unblocks_50k() {
    let tmp = tempfile::tempdir().unwrap();
    let db = temp_db(&tmp, "cascade-50k.db");

    let staged = assert_success(topo(&["--db", &db, "generate-deps", "50000", "10"]));
    assert_eq!(line_value(&staged, "staged_events"), "50000");

    let started = Instant::now();
    let replayed = assert_success(topo(&["--db", &db, "replay-deps-reverse"]));
    let elapsed = started.elapsed();

    assert_eq!(line_value(&replayed, "replayed_events"), "50000");
    assert_eq!(line_value(&replayed, "blocked_after_reverse"), "49990");
    assert_eq!(line_value(&replayed, "applied_events"), "50000");
    assert_eq!(line_value(&replayed, "blocked_events"), "0");
    assert_eq!(line_value(&replayed, "blocked_edges"), "0");

    let seconds = elapsed.as_secs_f64().max(0.001);
    let rate = 50_000f64 / seconds;
    eprintln!("black_box_cascade_50k events_per_s={rate:.0}");
}

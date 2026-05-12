//! Disappearing-floor dispatcher worker.
//!
//! Inputs:
//! - the latest admitted `disappearing_messages_setting` per workspace
//!   (read from `disappearing_messages_setting::schema::active_for_workspace`),
//!   whose `expires_at_or_before_minute` is the admin-tightened deletion floor;
//! - the local logical clock, which feeds the cover-horizon floor
//!   `now_minute - COVER_HORIZON_MINUTES`;
//! - the per-workspace `last_chopped_floor` row this worker writes
//!   (`disappearing_messages_setting::schema::WORKSPACE_CHOP_FLOOR`).
//!
//! Step: for each workspace + removal_frontier known on the local peer,
//! compute `effective_floor = max(setting_floor, horizon_floor)`. If
//! `effective_floor > last_chopped_floor`, invoke the encryption worker's
//! `Work::ChopTimeTreePrefix { floor_minute: effective_floor }` and persist
//! the new last-chopped value. The chop primitive is what does the real
//! work — this dispatcher is just the per-tick policy that turns the two
//! floor sources into a monotonically advancing floor.
//!
//! Outputs: tombstone rows + sibling-cover materializations written by the
//! encryption worker, plus an updated `WORKSPACE_CHOP_FLOOR` row per
//! workspace + frontier that advanced this tick.
//!
//! Sequencing: the daemon list runs `disappearing_minute_expiry` first,
//! then this worker. Per-message TTL retirements may write per-leaf
//! tombstones at coordinates that fall under the new chop range; the
//! coarse subtree tombstones written by the chop subsume them, so running
//! expiry first minimizes transient state. Correctness does not depend on
//! the order — the chop's range deletion is what the long-run storage
//! bound is built on, and per-message tombstones are individually cheap.
//!
//! Local-only state: the `last_chopped_floor` row is never propagated.
//! Each peer maintains its own; the value the dispatcher writes is
//! deterministic given the chain of admitted settings (shared) and the
//! local clock state (local), so two peers that have observed the same
//! setting chain and run their dispatchers under the same logical time
//! converge to byte-identical chop tombstones (the `chop_is_deterministic`
//! test in `src/workers/encryption.rs` covers the primitive's contract).
//!
//! Fairness: the loop iterates every `(workspace_id, removal_frontier_id)`
//! visible on the peer. `ctx.options.work_limit` caps the total number of
//! per-frontier chops issued per tick so a peer that wakes from a long
//! sleep with many tightened settings cannot block other workers.

use std::cmp::max;

use crate::core::daemon::{StepContext, Worker};
use crate::core::logical_clock;
use crate::core::store::Store;
use crate::protocol::event_modules::content::message::types::UNIX_MINUTE_MS;
use crate::protocol::event_modules::encryption::disappearing_messages_setting::schema as setting_schema;
use crate::protocol::event_modules::encryption::disappearing_messages_setting::types::COVER_HORIZON_MINUTES;
use crate::protocol::event_modules::encryption::removal_frontier::schema as frontier_schema;
use crate::protocol::event_modules::identity::workspace::schema as workspace_schema;
use crate::protocol::event_modules::types::EventId;
use crate::workers::encryption as encryption_worker;
use crate::workers::pipeline_helpers::event_pipeline::EventRegistry;
use crate::workers::DaemonWorkerContext;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DispatchReport {
    /// Number of `(workspace_id, removal_frontier_id)` pairs visited this tick.
    pub frontiers_visited: usize,
    /// Number of pairs whose effective floor strictly exceeded the
    /// stored `last_chopped_floor` and so triggered a chop call.
    pub chops_issued: usize,
    /// Sum of `subtree_tombstones_written` across every chop call this tick.
    pub subtree_tombstones_written: usize,
    /// Sum of `boundary_descend_tombstones_written` across every chop call.
    pub boundary_descend_tombstones_written: usize,
    /// Sum of `right_side_siblings_materialized` across every chop call.
    pub right_side_siblings_materialized: usize,
    /// Sum of canonical bytes purged across every chop call.
    pub purged_event_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    Drain { limit: usize },
}

pub(crate) fn daemon_worker<C>() -> Worker<C>
where
    C: DaemonWorkerContext,
{
    Worker {
        name: "disappearing_floor_dispatcher",
        run: daemon_step::<C>,
    }
}

fn daemon_step<C>(ctx: &mut StepContext<'_, C>) -> Result<(), String>
where
    C: DaemonWorkerContext,
{
    let app = &*ctx.app;
    let store = app.store();
    let report = run(
        store,
        app,
        Work::Drain {
            limit: ctx.options.work_limit,
        },
    )
    .map_err(|err| format!("disappearing floor dispatcher: {err}"))?;
    ctx.report
        .add("disappearing_floor_chops_issued", report.chops_issued);
    ctx.report.add(
        "disappearing_floor_subtree_tombstones",
        report.subtree_tombstones_written,
    );
    ctx.report.add(
        "disappearing_floor_boundary_tombstones",
        report.boundary_descend_tombstones_written,
    );
    Ok(())
}

/// Single public worker entrypoint. The daemon-step shim above and any
/// future ad-hoc test caller both go through this function.
pub fn run<R>(store: &Store, registry: &R, work: Work) -> Result<DispatchReport, String>
where
    R: EventRegistry,
{
    match work {
        Work::Drain { limit } => drain(store, registry, limit),
    }
}

fn drain<R>(store: &Store, registry: &R, limit: usize) -> Result<DispatchReport, String>
where
    R: EventRegistry,
{
    let mut report = DispatchReport::default();

    // Without a pinned clock, the cover-horizon floor is undefined and the
    // setting floor alone is unlikely to have changed since the last tick.
    // Treat this the same way `disappearing_minute_expiry` does: bail out
    // and let a later tick (after the daemon driver pins time) do the work.
    let Some(now_ms) = logical_clock::logical_time(store)? else {
        return Ok(report);
    };
    let now_minute = now_ms / UNIX_MINUTE_MS;
    let horizon_floor = now_minute.saturating_sub(COVER_HORIZON_MINUTES);

    let workspaces = workspace_schema::list_all(store)?;
    'workspaces: for workspace in workspaces {
        let setting_floor = setting_schema::active_for_workspace(store, workspace.workspace_id)?
            .map(|row| row.expires_at_or_before_minute)
            .unwrap_or(0);
        let effective_floor = max(setting_floor, horizon_floor);

        for frontier in frontier_schema::list_for_workspace(store, workspace.workspace_id)? {
            if report.chops_issued >= limit {
                // Bound work per tick. The next tick picks up where we left
                // off because the floor is monotonic and `last_chopped_floor`
                // already reflects every chop that did fire.
                break 'workspaces;
            }
            report.frontiers_visited += 1;
            let last_chopped = setting_schema::get_last_chopped_floor(
                store,
                workspace.workspace_id,
                frontier.removal_frontier_id,
            )?
            .unwrap_or(0);
            if effective_floor <= last_chopped {
                continue;
            }
            chop_one(
                store,
                registry,
                workspace.workspace_id,
                frontier.removal_frontier_id,
                effective_floor,
                &mut report,
            )?;
        }
    }

    Ok(report)
}

fn chop_one<R: EventRegistry>(
    store: &Store,
    registry: &R,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    floor_minute: u64,
    report: &mut DispatchReport,
) -> Result<(), String> {
    let output = encryption_worker::run(
        store,
        registry,
        encryption_worker::Work::ChopTimeTreePrefix {
            workspace_id,
            removal_frontier_id,
            floor_minute,
        },
    )
    .map_err(|err| format!("dispatch chop: {err}"))?;
    let encryption_worker::Output::ChoppedTimeTreePrefix(chop) = output else {
        return Err("unexpected encryption worker output dispatching chop".to_string());
    };
    report.chops_issued += 1;
    report.subtree_tombstones_written += chop.subtree_tombstones_written;
    report.boundary_descend_tombstones_written += chop.boundary_descend_tombstones_written;
    report.right_side_siblings_materialized += chop.right_side_siblings_materialized;
    report.purged_event_bytes += chop.purged_event_bytes;

    setting_schema::upsert_last_chopped_floor(
        store,
        workspace_id,
        removal_frontier_id,
        floor_minute,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::core::crypto::{self as core_crypto, Ed25519PrivateKey};
    use crate::core::store::Store;
    use crate::protocol::event_modules::encryption::disappearing_messages_setting::schema as setting_schema;
    use crate::protocol::event_modules::encryption::local_history_node_secret;
    use crate::protocol::event_modules::encryption::local_key_secret;
    use crate::protocol::event_modules::encryption::removal_frontier;
    use crate::protocol::event_modules::identity::workspace::schema as workspace_schema;
    use crate::protocol::event_modules::types::{event_id, EventId, EventStatus};
    use crate::protocol::Protocol;
    use crate::workers::pipeline_helpers::event_lifecycle;

    use super::*;

    const WORKSPACE: EventId = [1; 32];
    const KEY_SECRET: [u8; 32] = [7; 32];
    const ADMIN_ID: EventId = [9; 32];

    /// Mirror of the helper in `src/workers/encryption.rs` tests: build a
    /// signed removal-frontier record so the encryption worker can find F's
    /// row, then seed the local key secret. Returns the deterministic
    /// frontier id.
    fn build_signed_frontier_record(
        signer_private_key: &Ed25519PrivateKey,
    ) -> crate::protocol::event_modules::types::EventRecord {
        let payload =
            removal_frontier::codec::encode(&removal_frontier::types::RemovalFrontierEvent {
                workspace_id: WORKSPACE,
                created_at_ms: 1,
                authority_admin_id: ADMIN_ID,
                removal_event_ids: Vec::new(),
            })
            .expect("encode frontier");
        let envelope = removal_frontier::codec::sign([8; 32], signer_private_key, payload);
        let bytes = removal_frontier::codec::encode_signed(&envelope);
        removal_frontier::codec::signed_record_from_bytes(bytes).expect("signed record")
    }

    fn seed_local_key_secret(store: &Store) -> EventId {
        let signer_private_key = core_crypto::random_ed25519_private_key();
        let frontier_record = build_signed_frontier_record(&signer_private_key);
        let frontier_id = event_id(&frontier_record.canonical_bytes);

        let output =
            local_key_secret::commands::from_key_secret(WORKSPACE, frontier_id, KEY_SECRET)
                .expect("local key secret");
        let local_key_secret_id = output.value.local_key_secret_id;
        let record = output.events[0].record().clone();
        store
            .write_transaction(|store| {
                event_lifecycle::insert_event(store, &frontier_record, EventStatus::Applied)?;
                event_lifecycle::insert_event(store, &record, EventStatus::Applied)?;
                store.insert_table_rows_in_tx(vec![
                    local_key_secret::schema::local_key_secret_row(
                        local_key_secret_id,
                        &output.value.event,
                    ),
                ])?;
                Ok(())
            })
            .expect("seed local key secret");
        // The dispatcher enumerates `removal_frontier::schema` rows, which
        // get written by the projector for shared frontier events. The seed
        // helper inserts the frontier record but not its projection row, so
        // do that explicitly.
        store
            .insert_table_rows(vec![removal_frontier::schema::removal_frontier_row(
                frontier_id,
                &removal_frontier::types::RemovalFrontierEvent {
                    workspace_id: WORKSPACE,
                    created_at_ms: 1,
                    authority_admin_id: ADMIN_ID,
                    removal_event_ids: Vec::new(),
                },
            )
            .expect("frontier row")])
            .expect("insert frontier row");
        frontier_id
    }

    /// Insert a workspace projection row (without going through the codec /
    /// projector) so the dispatcher's `workspace_schema::list_all` finds it.
    fn seed_workspace_row(store: &Store) {
        let row = workspace_schema::workspace_row(
            WORKSPACE,
            1,
            [4; 32],
            0,
            "test",
        )
        .expect("workspace row");
        store
            .insert_table_rows(vec![row])
            .expect("insert workspace row");
    }

    /// Insert an admin-signed setting row directly into the schema. We
    /// don't go through `commands::set` here because that path requires
    /// admitting a real signed event with a chain of admin events; for
    /// the dispatcher's contract the only thing that matters is that
    /// `active_for_workspace` returns the row with the expected
    /// `expires_at_or_before_minute`.
    fn seed_setting(
        store: &Store,
        setting_event_id: EventId,
        ttl_minutes: u32,
        created_at_ms: u64,
        expires_at_or_before_minute: u64,
    ) {
        store
            .insert_table_rows(vec![setting_schema::setting_row(
                WORKSPACE,
                setting_event_id,
                ttl_minutes,
                created_at_ms / UNIX_MINUTE_MS,
                created_at_ms,
                expires_at_or_before_minute,
            )])
            .expect("insert setting row");
    }

    #[test]
    fn dispatcher_with_no_setting_uses_horizon_only() {
        // No setting events are admitted, but the clock has advanced past
        // `COVER_HORIZON_MINUTES`. The dispatcher must chop to
        // `now_minute - COVER_HORIZON_MINUTES` and persist that as the
        // last-chopped floor.
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        seed_workspace_row(&store);
        let frontier_id = seed_local_key_secret(&store);

        // Pin clock to a unix-minute that is at least COVER_HORIZON_MINUTES + 50
        // past zero. We pick `now_minute = COVER_HORIZON_MINUTES + 50` so the
        // expected horizon floor is exactly 50.
        let now_minute = COVER_HORIZON_MINUTES + 50;
        logical_clock::set_logical_time(&store, now_minute * UNIX_MINUTE_MS).expect("set clock");

        let report = run(
            &store,
            &protocol,
            Work::Drain {
                limit: usize::MAX,
            },
        )
        .expect("dispatch");
        assert_eq!(report.chops_issued, 1);
        assert_eq!(report.frontiers_visited, 1);

        let last = setting_schema::get_last_chopped_floor(&store, WORKSPACE, frontier_id)
            .expect("get last chopped");
        assert_eq!(
            last,
            Some(50),
            "no setting + clock at now_minute = horizon+50 ⇒ effective floor = 50"
        );
        // The chop primitive must have written tombstones for floor=50.
        assert!(
            report.subtree_tombstones_written + report.boundary_descend_tombstones_written > 0,
            "non-zero floor must produce at least one tombstone"
        );
    }

    #[test]
    fn dispatcher_chops_on_setting_tightening() {
        // Setting with floor=100 is admitted; horizon is well below 100
        // (clock is small). The dispatcher chops to 100 and persists it.
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        seed_workspace_row(&store);
        let frontier_id = seed_local_key_secret(&store);
        seed_setting(&store, [42; 32], 5, 12_000_000, 100);

        // Clock pinned somewhere small so the horizon floor is 0.
        logical_clock::set_logical_time(&store, 12_000_000).expect("set clock");

        let report = run(
            &store,
            &protocol,
            Work::Drain { limit: usize::MAX },
        )
        .expect("dispatch");
        assert_eq!(report.chops_issued, 1);
        assert_eq!(
            setting_schema::get_last_chopped_floor(&store, WORKSPACE, frontier_id)
                .expect("get last chopped"),
            Some(100)
        );
        // F must be wiped after a non-zero chop (the chop primitive's contract).
        assert!(
            local_key_secret::schema::get(&store, WORKSPACE, frontier_id)
                .expect("look up F")
                .is_none(),
            "F's row must be wiped by the dispatcher-issued chop"
        );
    }

    #[test]
    fn dispatcher_chops_on_horizon_passing_setting() {
        // Setting floor=50, but clock is so far advanced that the horizon
        // floor is well above 50. Effective floor is the horizon, NOT the
        // setting; the dispatcher chops to the horizon.
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        seed_workspace_row(&store);
        let frontier_id = seed_local_key_secret(&store);
        seed_setting(&store, [42; 32], 5, 12_000_000, 50);

        // Place the clock so horizon = COVER_HORIZON_MINUTES + 1000 - COVER_HORIZON_MINUTES = 1000.
        let now_minute = COVER_HORIZON_MINUTES + 1000;
        logical_clock::set_logical_time(&store, now_minute * UNIX_MINUTE_MS).expect("set clock");

        let report = run(
            &store,
            &protocol,
            Work::Drain { limit: usize::MAX },
        )
        .expect("dispatch");
        assert_eq!(report.chops_issued, 1);
        let last = setting_schema::get_last_chopped_floor(&store, WORKSPACE, frontier_id)
            .expect("get last chopped");
        assert_eq!(
            last,
            Some(1000),
            "horizon (1000) > setting (50) so effective floor must be 1000"
        );
    }

    #[test]
    fn dispatcher_is_idempotent() {
        // Two ticks back-to-back without changes. The first chops, the
        // second is a no-op because `last_chopped_floor == effective_floor`.
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        seed_workspace_row(&store);
        let frontier_id = seed_local_key_secret(&store);
        seed_setting(&store, [42; 32], 5, 12_000_000, 100);
        logical_clock::set_logical_time(&store, 12_000_000).expect("set clock");

        let first = run(
            &store,
            &protocol,
            Work::Drain { limit: usize::MAX },
        )
        .expect("first dispatch");
        assert_eq!(first.chops_issued, 1);

        let pre_tombstones =
            local_history_node_secret::schema::list_tombstones_for_workspace(&store, WORKSPACE)
                .expect("pre tombstones")
                .len();

        let second = run(
            &store,
            &protocol,
            Work::Drain { limit: usize::MAX },
        )
        .expect("second dispatch");
        assert_eq!(second.chops_issued, 0, "second tick must be a no-op");
        assert_eq!(second.frontiers_visited, 1);

        let post_tombstones =
            local_history_node_secret::schema::list_tombstones_for_workspace(&store, WORKSPACE)
                .expect("post tombstones")
                .len();
        assert_eq!(
            pre_tombstones, post_tombstones,
            "no tombstones may be added on the no-op second tick"
        );
        assert_eq!(
            setting_schema::get_last_chopped_floor(&store, WORKSPACE, frontier_id)
                .expect("get last chopped"),
            Some(100)
        );
    }

    #[test]
    fn dispatcher_progresses_floor_monotonically() {
        // Three ticks at advancing clock values, each pushing the horizon
        // floor strictly above the previous tick's floor. Each tick must
        // chop and bump `last_chopped_floor`.
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        seed_workspace_row(&store);
        let frontier_id = seed_local_key_secret(&store);

        let mut prev_floor: u64 = 0;
        for delta in [10u64, 25, 100] {
            let now_minute = COVER_HORIZON_MINUTES + prev_floor + delta;
            logical_clock::set_logical_time(&store, now_minute * UNIX_MINUTE_MS)
                .expect("set clock");

            let report = run(
                &store,
                &protocol,
                Work::Drain { limit: usize::MAX },
            )
            .expect("dispatch");
            assert_eq!(report.chops_issued, 1, "advancing clock must chop");

            let new_last = setting_schema::get_last_chopped_floor(&store, WORKSPACE, frontier_id)
                .expect("get last chopped")
                .expect("row exists after chop");
            assert!(
                new_last > prev_floor,
                "tick must advance last_chopped_floor strictly (prev={prev_floor}, new={new_last})"
            );
            prev_floor = new_last;
        }
    }

    #[test]
    fn dispatcher_with_unset_clock_is_a_noop() {
        // Without a pinned clock, the horizon floor is undefined. The
        // dispatcher must bail out entirely (mirroring how
        // `disappearing_minute_expiry` waits for the clock).
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        seed_workspace_row(&store);
        let frontier_id = seed_local_key_secret(&store);
        // Even with a tightened setting, no chop fires until the clock is
        // pinned. (Another sensible policy is "use only the setting floor"
        // but matching `disappearing_minute_expiry` keeps test/daemon
        // semantics simple.)
        seed_setting(&store, [42; 32], 5, 12_000_000, 100);

        let report = run(
            &store,
            &protocol,
            Work::Drain { limit: usize::MAX },
        )
        .expect("dispatch");
        assert_eq!(report.chops_issued, 0);
        assert_eq!(report.frontiers_visited, 0);
        assert_eq!(
            setting_schema::get_last_chopped_floor(&store, WORKSPACE, frontier_id)
                .expect("get last chopped"),
            None,
            "no chop ⇒ no last-chopped row"
        );
    }
}

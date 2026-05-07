//! Per-peer sync supervisor.
//!
//! `sync::tick` already produces compare/have/need events for routed peers, but
//! it leans on a single "local endpoint sorts before remote" leader rule for
//! starting rounds. That rule is fine for two-endpoint convergence, yet it
//! still hides two operational gaps:
//!
//! - A higher-endpoint peer with new content waits for the lower-endpoint
//!   peer's tick to start a round. If the lower-endpoint peer is paused or
//!   slow, the new content sits unsent.
//! - A daemon with several routed peers should not let a slow or unreachable
//!   peer block fresh rounds for healthier peers.
//!
//! This supervisor wakes once per daemon tick, claims one peer in fair rotation,
//! and asks the sync worker to start a round for that single peer when the
//! base sync worker would otherwise be quiet for that peer. Because
//! `sync::Work::StartForConnection` only runs one peer's compare command, a
//! failed dial (or a slow peer) cannot starve the rest of the rotation: the
//! transit_out worker drains the resulting `transit.out` rows on the same
//! tick, and on the next tick the supervisor advances to the next peer.
//!
//! The supervisor only runs against peers where the base sync worker has been
//! intentionally silent (the local endpoint sorts after the remote endpoint).
//! That keeps the supervisor's role narrow: it is the higher-endpoint peer's
//! way to push fresh content, not a redundant duplicate of the leader's tick.
//!
//! Inputs:
//! - `connection.transport_targets`: the routed peer set.
//!
//! State: process-local cursor `(connection_id, sequence)` so successive ticks
//! advance through the routed peer set with bounded fairness even when peers
//! come and go between ticks.
//!
//! Step: pick the peer that follows the cursor in lexicographic
//! `connection_id` order, ask the sync worker to run a single-peer start, and
//! enqueue the proposed compare events through the common pipeline.
//!
//! Outputs: connection-scoped compare events admitted through the common
//! pipeline; the existing `sync` and `transit_out` workers carry them onto the
//! wire on the same tick.
//!
//! Fairness: `Work::StartNextPeer { work_limit }` advances the cursor by one
//! routed peer per call. The daemon caller keeps the rotation bounded because
//! the round-robin runtime calls this worker exactly once per tick.
//!
//! Failure: a peer with no mutual workspace returns an empty start; the cursor
//! still advances so the next tick tries the following peer. Sync command
//! errors propagate as worker errors.

use std::sync::Mutex;

use crate::core::daemon::{StepContext, Worker};
use crate::core::store::Store;
use crate::protocol::event_modules::connection;
use crate::protocol::event_modules::identity::endpoint;
use crate::protocol::event_modules::sync::commands::SyncSelection;
use crate::workers::common::event_pipeline as event_worker;
use crate::workers::sync;
use crate::workers::DaemonWorkerContext;

/// Fair-rotation cursor over routed peers.
///
/// The cursor is the connection id of the *last* peer the supervisor
/// dispatched. Each call picks the next routed connection id strictly greater
/// than the cursor, wrapping to the smallest routed id when the cursor sits at
/// or past the maximum. The cursor lives in process memory only; restart starts
/// from the smallest routed id.
#[derive(Debug, Default)]
pub struct PeerCursor {
    last: Mutex<Option<connection::types::ConnectionId>>,
}

impl PeerCursor {
    pub fn new() -> Self {
        Self {
            last: Mutex::new(None),
        }
    }

    fn pick_next(
        &self,
        peers: &[connection::types::ConnectionId],
    ) -> Option<connection::types::ConnectionId> {
        if peers.is_empty() {
            return None;
        }
        let mut last = self
            .last
            .lock()
            .expect("peer supervisor cursor is not poisoned");
        let next = match *last {
            Some(previous) => peers
                .iter()
                .copied()
                .find(|id| *id > previous)
                .or_else(|| peers.first().copied()),
            None => peers.first().copied(),
        };
        *last = next;
        next
    }
}

/// Inputs accepted by the peer supervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    /// Pick the next routed peer in fair rotation and start a sync round
    /// against that single peer. `work_limit` bounds the proposed events
    /// returned by the sync command in one call.
    StartNextPeer { work_limit: usize },
}

/// Output of one supervisor turn.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SupervisorReport {
    pub considered_peers: usize,
    pub started_peer: Option<connection::types::ConnectionId>,
    pub sent_events: usize,
}

/// Run one supervisor step.
///
/// The function keeps the worker contract: a single public entrypoint that
/// takes a small enum of inputs and returns a small report. Helpers stay
/// private.
pub fn run(
    store: &Store,
    sync_index: &crate::protocol::event_modules::sync::SyncIndex,
    cursor: &PeerCursor,
    work: Work,
) -> Result<SupervisorReport, String> {
    match work {
        Work::StartNextPeer { work_limit } => {
            start_next_peer(store, sync_index, cursor, work_limit)
        }
    }
}

pub(crate) fn daemon_worker<C>() -> Worker<C>
where
    C: DaemonWorkerContext,
{
    Worker {
        name: "peer_supervisor",
        run: daemon_step::<C>,
    }
}

fn daemon_step<C>(ctx: &mut StepContext<'_, C>) -> Result<(), String>
where
    C: DaemonWorkerContext,
{
    let app = &*ctx.app;
    let report = start_next_peer(
        app.store(),
        app.sync_index(),
        app.peer_supervisor_cursor(),
        ctx.options.work_limit,
    )?;
    ctx.report.add("supervisor_peers", report.considered_peers);
    ctx.report
        .add("supervisor_started", usize::from(report.started_peer.is_some()));
    ctx.report.add("supervisor_sent_events", report.sent_events);
    Ok(())
}

fn start_next_peer(
    store: &Store,
    sync_index: &crate::protocol::event_modules::sync::SyncIndex,
    cursor: &PeerCursor,
    work_limit: usize,
) -> Result<SupervisorReport, String> {
    let peers = routed_peers(store)?;
    let mut report = SupervisorReport {
        considered_peers: peers.len(),
        ..SupervisorReport::default()
    };
    let Some(connection_id) = cursor.pick_next(&peers) else {
        return Ok(report);
    };
    let _ = work_limit; // sync::Work::StartForConnection has its own batching.
    let output = match sync::run(
        store,
        sync_index,
        sync::Work::StartForConnection {
            connection_id,
            selection: SyncSelection::All,
        },
    )? {
        sync::Output::Started(output) => output,
        other => {
            return Err(format!(
                "peer supervisor expected Started output, got {other:?}"
            ));
        }
    };
    report.started_peer = Some(connection_id);
    report.sent_events = output.value.sent_events;
    event_worker::enqueue_proposed_events(store, output.events)?;
    Ok(report)
}

fn routed_peers(store: &Store) -> Result<Vec<connection::types::ConnectionId>, String> {
    // The supervisor only nudges peers where the base sync worker stays
    // silent because of the leader rule. Peers where the local endpoint sorts
    // before the remote already get periodic compares from `sync::tick`; it
    // is the inverse case where the higher endpoint is otherwise quiet.
    //
    // The daemon may run before any local endpoint exists (a fresh database
    // is valid before invite acceptance). Treat that state as "no peers"
    // rather than erroring; the supervisor wakes again the next tick after
    // the endpoint has been written.
    let Some(local) = endpoint::commands::local_keypair(store)? else {
        return Ok(Vec::new());
    };
    let local = local.endpoint;
    let mut peers = Vec::new();
    for (key, _) in store
        .table_rows(connection::schema::TRANSPORT_TARGETS)
        .map_err(|err| format!("load transport targets: {err}"))?
    {
        let connection_id = connection::types::connection_id_from_bytes(&key)?;
        let remote = match connection::schema::remote_endpoint(store, connection_id) {
            Ok(remote) => remote,
            Err(_) => continue,
        };
        if local < remote {
            // Already a leader for this peer; tick handles it.
            continue;
        }
        peers.push(connection_id);
    }
    peers.sort();
    Ok(peers)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(byte: u8) -> connection::types::ConnectionId {
        [byte; 32]
    }

    #[test]
    fn cursor_rotates_through_peers_and_wraps() {
        let cursor = PeerCursor::new();
        let peers = vec![cid(1), cid(2), cid(3)];
        assert_eq!(cursor.pick_next(&peers), Some(cid(1)));
        assert_eq!(cursor.pick_next(&peers), Some(cid(2)));
        assert_eq!(cursor.pick_next(&peers), Some(cid(3)));
        assert_eq!(cursor.pick_next(&peers), Some(cid(1)));
    }

    #[test]
    fn cursor_handles_changing_peer_set() {
        let cursor = PeerCursor::new();
        assert_eq!(cursor.pick_next(&[cid(2), cid(4)]), Some(cid(2)));
        // A peer that joined sorts before the cursor; rotation still wraps.
        assert_eq!(cursor.pick_next(&[cid(1), cid(2), cid(4)]), Some(cid(4)));
        // A peer that disappeared; rotation falls back to the first available.
        assert_eq!(cursor.pick_next(&[cid(1), cid(2)]), Some(cid(1)));
    }

    #[test]
    fn cursor_returns_none_for_empty_peer_set() {
        let cursor = PeerCursor::new();
        assert!(cursor.pick_next(&[]).is_none());
    }
}

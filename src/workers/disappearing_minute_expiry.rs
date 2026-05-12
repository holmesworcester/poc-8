//! Disappearing-minute expiry worker.
//!
//! Inputs: workspace TTL settings, the logical clock, sealed message rows.
//! State: per-event leaf rows + minute_node + sealed/plaintext message rows
//! + canonical event bytes. Step: when `logical_time` advances past a
//! stored message's authored `expires_at_minute`, retire that message's
//! per-event leaf (delegating to the encryption worker's existing
//! per-leaf retirement primitive), exact-row-delete the read-model rows,
//! and purge canonical bytes. Outputs: per-leaf tombstones written by the
//! encryption worker, plus row deletes.
//!
//! Slice 1 ships with per-leaf retirement: every expired message produces
//! its own leaf tombstone. The plan's "one tombstone per minute"
//! optimization is left for slice 3 (deletion summary monotonicity); the
//! retention/cover-summary contract is identical either way because both
//! peers retire the same set of leaves deterministically.
//!
//! Fairness: bounded by `ctx.options.work_limit`.

use crate::core::daemon::{StepContext, Worker};
use crate::core::logical_clock;
use crate::core::store::Store;
use crate::protocol::event_modules::content::message::queries as message_queries;
use crate::protocol::event_modules::content::message::schema as message_schema;
use crate::protocol::event_modules::content::message::types::{
    message_event_id_in_minute, UNIX_MINUTE_MS,
};
use crate::protocol::event_modules::content::reaction::schema as reaction_schema;
use crate::protocol::event_modules::content::reaction::types::reaction_event_id_in_minute;
use crate::protocol::event_modules::identity::workspace::schema as workspace_schema;
use crate::protocol::event_modules::types::EventId;
use crate::workers::encryption as encryption_worker;
use crate::workers::pipeline_helpers::event_pipeline::EventRegistry;
use crate::workers::pipeline_helpers::purging;
use crate::workers::DaemonWorkerContext;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExpiryReport {
    pub retired_message_leaves: usize,
    pub purged_event_bytes: usize,
    pub deleted_message_rows: usize,
    /// Reactions/files/slices reclaimed by the post-expiry
    /// `content_purge` cascade in the same tick.
    pub cascaded_reaction_rows: usize,
    pub cascaded_file_rows: usize,
    pub cascaded_file_slice_rows: usize,
}

pub(crate) fn daemon_worker<C>() -> Worker<C>
where
    C: DaemonWorkerContext,
{
    Worker {
        name: "disappearing_minute_expiry",
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
    .map_err(|err| format!("disappearing minute expiry: {err}"))?;
    ctx.report
        .add("disappearing_retired_leaves", report.retired_message_leaves);
    ctx.report
        .add("disappearing_purged_event_bytes", report.purged_event_bytes);
    Ok(())
}

/// Single public worker entrypoint. The daemon-step shim above and any
/// future ad-hoc test caller both go through this function.
pub fn run<R>(store: &Store, registry: &R, work: Work) -> Result<ExpiryReport, String>
where
    R: EventRegistry,
{
    match work {
        Work::Drain { limit } => drain(store, registry, limit),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    Drain { limit: usize },
}

fn drain<R>(store: &Store, registry: &R, limit: usize) -> Result<ExpiryReport, String>
where
    R: EventRegistry,
{
    let mut report = ExpiryReport::default();

    // No clock pinned ⇒ nothing expires. Slice 1 leaves clock advancement
    // to the daemon driver and tests that pin time explicitly.
    let Some(now_ms) = logical_clock::logical_time(store)? else {
        return Ok(report);
    };
    let now_minute = now_ms / UNIX_MINUTE_MS;

    let workspaces = workspace_schema::list_all(store)?;
    let mut expired_jobs: Vec<ExpireMessageJob> = Vec::new();

    for workspace in workspaces {
        if workspace.disappearing_ttl_minutes == 0 {
            continue;
        }
        let sealed = sealed_messages_for_workspace(store, workspace.workspace_id)?;
        for row in sealed {
            if row.expires_at_minute == u64::MAX {
                continue;
            }
            if row.expires_at_minute >= now_minute {
                continue;
            }
            // Recompute the deterministic per-event leaf coord. Both peers
            // re-derive it from the canonical message fields, so retiring
            // the same coord on every peer keeps the FS state convergent.
            let event_id_in_minute = message_event_id_in_minute(
                &row.workspace_id,
                &row.author_user_id,
                &row.removal_frontier_id,
                row.created_at_ms,
            );
            expired_jobs.push(ExpireMessageJob {
                workspace_id: row.workspace_id,
                removal_frontier_id: row.removal_frontier_id,
                created_at_ms: row.created_at_ms,
                event_id_in_minute,
                message_id: row.message_id,
                author_user_id: row.author_user_id,
            });
        }
    }

    let job_count = expired_jobs.len().min(limit);
    let processed_jobs: Vec<ExpireMessageJob> = expired_jobs
        .into_iter()
        .take(job_count)
        .collect();
    for job in processed_jobs.iter().copied() {
        process_job(store, registry, &mut report, job)?;
    }

    // Slice 4: retire the per-event leaves of any reaction whose target
    // message we just expired. `content_purge` handles read-model and
    // sealed-bytes cleanup for reactions but does not call
    // `RetireDeletedEventLeaf` for the reaction's own leaf, so we do
    // that here. The reaction's leaf coord is deterministic from its
    // canonical fields; both peers retire the same coord. Skip if no
    // messages expired this tick.
    if !processed_jobs.is_empty() {
        retire_reaction_leaves_for_expired_messages(store, registry, &processed_jobs, &mut report)?;
    }

    // Cascade through `content_purge` so reactions/files/slices for
    // expired messages are reclaimed in the same tick. The message
    // tombstone rows we just wrote are the trigger:
    // `purge_reaction_for_deleted_message` and
    // `purge_file_for_deleted_message_or_file_deletion` both gate on
    // `message_tombstone_exists(target_message_id)`.
    if job_count > 0 {
        let cascade = crate::workers::content_purge::run(
            store,
            registry,
            crate::workers::content_purge::Work::Drain { limit: usize::MAX },
        )
        .map_err(|err| format!("content_purge cascade after expiry: {err}"))?;
        report.cascaded_reaction_rows += cascade.reaction_rows_deleted;
        report.cascaded_file_rows += cascade.file_rows_deleted;
        report.cascaded_file_slice_rows += cascade.file_slice_rows_deleted;
        report.purged_event_bytes += cascade.event_bytes_purged;
        report.retired_message_leaves += cascade.retired_message_leaves;
    }

    Ok(report)
}

#[derive(Debug, Clone, Copy)]
struct ExpireMessageJob {
    workspace_id: EventId,
    removal_frontier_id: EventId,
    created_at_ms: u64,
    event_id_in_minute: EventId,
    message_id: EventId,
    author_user_id: EventId,
}

fn process_job<R: EventRegistry>(
    store: &Store,
    registry: &R,
    report: &mut ExpiryReport,
    job: ExpireMessageJob,
) -> Result<(), String> {
    // Delete the read-model and sealed rows, write a `message_tombstones`
    // row so `content_purge` will cascade to reactions/files/slices on
    // its next tick (see `content_purge::purge_reaction_for_deleted_message`
    // and friends, which gate purges on
    // `message::schema::message_tombstone_exists`), and purge the
    // message's canonical bytes — all in one transaction.
    let messages_deleted = store
        .write_transaction(|tx_store| {
            let key = message_schema::message_key(job.workspace_id, job.message_id);
            let mut deleted = 0usize;
            deleted += tx_store
                .delete_table_rows_in_tx(message_schema::MESSAGES, vec![key.clone()])?
                as usize;
            tx_store
                .delete_table_rows_in_tx(message_schema::SEALED_MESSAGES, vec![key])?;
            tx_store.insert_table_rows_in_tx(vec![message_schema::message_tombstone_row(
                job.workspace_id,
                job.message_id,
                job.author_user_id,
                job.created_at_ms / UNIX_MINUTE_MS,
            )])?;
            purging::purge_event_storage_in_tx(tx_store, &job.message_id)?;
            Ok::<_, rusqlite::Error>(deleted)
        })
        .map_err(|err| format!("expire message cleanup: {err}"))?;
    report.deleted_message_rows += messages_deleted;

    // Retire the per-event leaf chain via the encryption worker. This
    // tombstones the leaf row, materializes splits to keep cover for any
    // surviving siblings in the minute, and purges retained leaf bytes.
    let output = encryption_worker::run(
        store,
        registry,
        encryption_worker::Work::RetireDeletedEventLeaf {
            workspace_id: job.workspace_id,
            removal_frontier_id: job.removal_frontier_id,
            created_at_ms: job.created_at_ms,
            event_id_in_minute: job.event_id_in_minute,
        },
    )
    .map_err(|err| format!("retire expired-minute leaf: {err}"))?;
    let encryption_worker::Output::RetiredDeletedEventLeaf(retired) = output else {
        return Err("unexpected encryption worker output retiring expired leaf".to_string());
    };
    if retired.leaf_id.is_some() {
        report.retired_message_leaves += 1;
    }
    report.purged_event_bytes += retired.purged_event_bytes;
    Ok(())
}

fn sealed_messages_for_workspace(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<message_schema::SealedMessageRow>, String> {
    Ok(message_schema::list_sealed(store, usize::MAX)?
        .into_iter()
        .filter(|row| row.workspace_id == workspace_id)
        .collect())
}

/// For each just-expired message, find every admitted reaction whose
/// `target_message_id` matches and call `RetireDeletedEventLeaf` for the
/// reaction's per-event leaf. Mirrors how the message leaf is retired,
/// so the reaction's AEAD key cannot be re-derived from any retained
/// state. The reaction's read-model row, sealed-bytes, and canonical
/// bytes are reclaimed by the `content_purge` cascade that follows.
fn retire_reaction_leaves_for_expired_messages<R: EventRegistry>(
    store: &Store,
    registry: &R,
    expired_messages: &[ExpireMessageJob],
    report: &mut ExpiryReport,
) -> Result<(), String> {
    let reactions = reaction_schema::list_sealed(store, usize::MAX)?;
    for reaction in reactions {
        let parent = expired_messages.iter().find(|job| {
            job.workspace_id == reaction.workspace_id
                && job.message_id == reaction.target_message_id
        });
        let Some(_) = parent else {
            continue;
        };
        let event_id_in_minute = reaction_event_id_in_minute(
            &reaction.workspace_id,
            &reaction.author_user_id,
            &reaction.target_message_id,
            &reaction.removal_frontier_id,
            reaction.created_at_ms,
        );
        let output = encryption_worker::run(
            store,
            registry,
            encryption_worker::Work::RetireDeletedEventLeaf {
                workspace_id: reaction.workspace_id,
                removal_frontier_id: reaction.removal_frontier_id,
                created_at_ms: reaction.created_at_ms,
                event_id_in_minute,
            },
        )
        .map_err(|err| format!("retire expired-reaction leaf: {err}"))?;
        let encryption_worker::Output::RetiredDeletedEventLeaf(retired) = output else {
            return Err("unexpected encryption worker output retiring reaction leaf".to_string());
        };
        if retired.leaf_id.is_some() {
            report.retired_message_leaves += 1;
        }
        report.purged_event_bytes += retired.purged_event_bytes;
    }
    Ok(())
}

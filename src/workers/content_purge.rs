//! Content purge worker.
//!
//! Inputs: durable shared content events plus deletion labels written by
//! projectors.
//! State: content read-model rows, durable message tombstone summaries, and the
//! protocol event store.
//! Step: verify message deletion labels against encrypted message metadata,
//! write tombstones, remove visible plaintext rows, and purge obsolete message
//! or reaction event bytes. After the transactional purge, retire each deleted
//! message's per-message HKDF leaf and intermediate path-node so the leaf
//! key cannot be recovered from disk.
//! Outputs: `content.message_tombstones` rows and row/event deletes; the leaf
//! retirement step writes a sibling-tombstone history-node event and purges
//! retired bytes.
//! Consume: purged event rows leave the durable deletion label/tombstone facts
//! behind so semantic deletion survives without keeping ciphertext bytes.
//! Failure: one malformed event aborts that worker transaction and will be
//! retried; projectors remain the authority on validity before normal reads.
//! Fairness: `Work::Drain { limit }` bounds one scan.

use crate::core::daemon::{self, StepContext, Worker};
use crate::core::store::{table_error, Store};
use crate::protocol::event_modules::content::{
    file, file_deletion, file_slice, message, message_deletion, reaction,
};
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::types::EventId;
use crate::workers::encryption as encryption_worker;
use crate::workers::pipeline_helpers::event_pipeline::EventRegistry;
use crate::workers::pipeline_helpers::purging;
use crate::workers::DaemonWorkerContext;

use message_deletion::schema as message_deletion_schema;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    Drain { limit: usize },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PurgeReport {
    pub scanned_events: usize,
    pub tombstones_written: usize,
    pub message_rows_deleted: usize,
    pub reaction_rows_deleted: usize,
    pub file_rows_deleted: usize,
    pub file_slice_rows_deleted: usize,
    pub event_bytes_purged: usize,
    pub retired_message_leaves: usize,
}

pub fn run<R: EventRegistry>(
    store: &Store,
    registry: &R,
    work: Work,
) -> Result<PurgeReport, String> {
    match work {
        Work::Drain { limit } => drain(store, registry, limit),
    }
}

pub(crate) fn daemon_worker<C>() -> Worker<C>
where
    C: DaemonWorkerContext,
{
    Worker {
        name: "content_purge",
        run: daemon_step::<C>,
    }
}

fn daemon_step<C>(ctx: &mut StepContext<'_, C>) -> Result<(), String>
where
    C: DaemonWorkerContext,
{
    daemon::run_step(
        ctx,
        "purge content",
        |app, limit| run(app.store(), app, Work::Drain { limit }),
        |report, out| {
            out.add("purged_content_events", report.event_bytes_purged);
            out.add("retired_message_leaves", report.retired_message_leaves);
        },
    )
}

#[derive(Debug, Clone, Copy)]
struct RetireLeafJob {
    workspace_id: EventId,
    removal_frontier_id: EventId,
    created_at_ms: u64,
    event_id_in_minute: EventId,
}

fn drain<R: EventRegistry>(
    store: &Store,
    registry: &R,
    limit: usize,
) -> Result<PurgeReport, String> {
    let (mut report, retire_jobs) = store
        .write_transaction(|store| drain_in_tx(store, limit).map_err(table_error))
        .map_err(|err| format!("drain content purge: {err}"))?;
    // Retire per-message leaf chains outside the purge transaction. Each
    // retirement runs the encryption worker, which admits a sibling-tombstone
    // history-node event through the common worker and purges retired bytes.
    // Doing this after the purge transaction commits avoids nesting the
    // event-admission transactions inside the purge's own write transaction.
    for job in retire_jobs {
        let output = encryption_worker::run(
            store,
            registry,
            encryption_worker::Work::RetireDeletedEventLeaf {
                workspace_id: job.workspace_id,
                removal_frontier_id: job.removal_frontier_id,
                created_at_ms: job.created_at_ms,
                event_id_in_minute: job.event_id_in_minute,
            },
        )?;
        let encryption_worker::Output::RetiredDeletedEventLeaf(retired) = output else {
            return Err("unexpected encryption worker output retiring deleted leaf".to_string());
        };
        report.event_bytes_purged += retired.purged_event_bytes;
        if retired.leaf_id.is_some() {
            report.retired_message_leaves += 1;
        }
    }
    Ok(report)
}

fn drain_in_tx(store: &Store, limit: usize) -> Result<(PurgeReport, Vec<RetireLeafJob>), String> {
    let entries = event_schema::event_index_entries_in_timestamp_range(store, 0, u64::MAX)
        .map_err(|err| format!("load event index: {err}"))?;
    let mut report = PurgeReport::default();
    let mut retire_jobs = Vec::new();
    for entry in entries.into_iter().take(limit) {
        let Some(bytes) = event_schema::event_bytes(store, &entry.event_id)
            .map_err(|err| format!("load event bytes: {err}"))?
        else {
            continue;
        };
        report.scanned_events += 1;
        match bytes.first().copied() {
            Some(message::codec::TYPE_SIGNED_MESSAGE) => {
                purge_deleted_message(
                    store,
                    entry.event_id,
                    &bytes,
                    &mut report,
                    &mut retire_jobs,
                )?;
            }
            Some(reaction::codec::TYPE_SIGNED_REACTION) => {
                purge_reaction_for_deleted_message(store, entry.event_id, &bytes, &mut report)?;
            }
            Some(file::codec::TYPE_SIGNED_FILE) => {
                purge_file_for_deleted_message_or_file_deletion(
                    store,
                    entry.event_id,
                    &bytes,
                    &mut report,
                    &mut retire_jobs,
                )?;
            }
            Some(file_slice::codec::TYPE_SIGNED_FILE_SLICE) => {
                purge_file_slice_for_deleted_file(store, entry.event_id, &bytes, &mut report)?;
            }
            _ => {}
        }
    }
    // The drain ran a full scan, so the purge_pending trigger queue is now
    // satisfied for whatever projection wrote into it. Clearing it keeps the
    // post-admission hook from looping on the same trigger forever.
    message_deletion_schema::delete_all_purge_pending_in_tx(store)
        .map_err(|err| format!("clear purge pending: {err}"))?;
    Ok((report, retire_jobs))
}

fn purge_deleted_message(
    store: &Store,
    message_id: EventId,
    bytes: &[u8],
    report: &mut PurgeReport,
    retire_jobs: &mut Vec<RetireLeafJob>,
) -> Result<(), String> {
    let envelope = message::codec::decode_signed(bytes)?;
    let event = message::codec::decode(&envelope.payload)?;
    if !has_author_deletion_label(store, &message_id, &event.author_user_id)? {
        return Ok(());
    }
    retire_jobs.push(RetireLeafJob {
        workspace_id: event.workspace_id,
        removal_frontier_id: event.removal_frontier_id,
        created_at_ms: event.created_at_ms,
        event_id_in_minute: event.event_id_in_minute_derived(),
    });

    let inserted = store
        .insert_table_rows_in_tx(vec![message::schema::message_tombstone_row(
            event.workspace_id,
            message_id,
            event.author_user_id,
        )])
        .map_err(|err| format!("write message tombstone: {err}"))?;
    report.tombstones_written += inserted;

    report.message_rows_deleted += store
        .delete_table_rows_in_tx(
            message::schema::MESSAGES,
            vec![message::schema::message_key(event.workspace_id, message_id)],
        )
        .map_err(|err| format!("delete message row: {err}"))?;
    if purging::purge_event_storage_in_tx(store, &message_id)
        .map_err(|err| format!("purge message event: {err}"))?
    {
        report.event_bytes_purged += 1;
    }
    Ok(())
}

fn purge_reaction_for_deleted_message(
    store: &Store,
    reaction_id: EventId,
    bytes: &[u8],
    report: &mut PurgeReport,
) -> Result<(), String> {
    let envelope = reaction::codec::decode_signed(bytes)?;
    let event = reaction::codec::decode(&envelope.payload)?;
    if !message::schema::message_tombstone_exists(
        store,
        event.workspace_id,
        event.target_message_id,
    )? {
        return Ok(());
    }
    report.reaction_rows_deleted += store
        .delete_table_rows_in_tx(
            reaction::schema::REACTIONS,
            vec![reaction::schema::reaction_key(
                event.workspace_id,
                reaction_id,
            )],
        )
        .map_err(|err| format!("delete reaction row: {err}"))?;
    if purging::purge_event_storage_in_tx(store, &reaction_id)
        .map_err(|err| format!("purge reaction event: {err}"))?
    {
        report.event_bytes_purged += 1;
    }
    Ok(())
}

/// Decide whether a file event should be purged, and if so, drop its
/// projection rows + slice rows + canonical bytes and queue its leaf for
/// retirement. A file is purged when:
///
///   * the parent message has been tombstoned (cascade from
///     `message_deletion`), or
///   * the file event itself carries an author-signed deletion label from
///     an admitted `file_deletion`.
///
/// In both cases the file's per-event leaf is retired, parallel to how a
/// deleted message retires its own leaf.
fn purge_file_for_deleted_message_or_file_deletion(
    store: &Store,
    file_event_id: EventId,
    bytes: &[u8],
    report: &mut PurgeReport,
    retire_jobs: &mut Vec<RetireLeafJob>,
) -> Result<(), String> {
    let envelope = file::codec::decode_signed(bytes)?;
    let event = file::codec::decode(&envelope.payload)?;
    let parent_deleted =
        message::schema::message_tombstone_exists(store, event.workspace_id, event.message_id)?;
    let file_self_deleted = has_file_deletion_label(store, &file_event_id, &event.author_user_id)?;
    if !parent_deleted && !file_self_deleted {
        return Ok(());
    }
    retire_jobs.push(RetireLeafJob {
        workspace_id: event.workspace_id,
        removal_frontier_id: event.removal_frontier_id,
        created_at_ms: event.created_at_ms,
        event_id_in_minute: event.event_id_in_minute_derived(),
    });

    // Delete projection rows for this file_event_id and file_id.
    let primary_key = file::schema::file_key(event.workspace_id, file_event_id);
    let by_message_key =
        file::schema::file_by_message_key(event.workspace_id, event.message_id, file_event_id);
    let by_file_id_key =
        file::schema::file_by_file_id_key(event.workspace_id, event.file_id, file_event_id);
    report.file_rows_deleted += store
        .delete_table_rows_in_tx(file::schema::FILES, vec![primary_key])
        .map_err(|err| format!("delete file row: {err}"))?;
    let _ = store
        .delete_table_rows_in_tx(file::schema::FILES_BY_MESSAGE, vec![by_message_key])
        .map_err(|err| format!("delete files_by_message row: {err}"))?;
    let _ = store
        .delete_table_rows_in_tx(file::schema::FILES_BY_FILE_ID, vec![by_file_id_key])
        .map_err(|err| format!("delete files_by_file_id row: {err}"))?;

    // Delete every slice projection row for this file_id. Slice canonical
    // bytes are purged when the slice itself is scanned next; the slice's
    // descriptor lookup will fail and trigger its own purge branch.
    let slice_keys = store
        .table_rows_with_key_prefix(
            file_slice::schema::FILE_SLICES,
            &file_slice::schema::file_slice_prefix(event.workspace_id, event.file_id),
            usize::MAX,
        )
        .map_err(|err| format!("load file slice rows: {err}"))?;
    let keys: Vec<Vec<u8>> = slice_keys.iter().map(|(key, _)| key.clone()).collect();
    if !keys.is_empty() {
        report.file_slice_rows_deleted += store
            .delete_table_rows_in_tx(file_slice::schema::FILE_SLICES, keys)
            .map_err(|err| format!("delete file slice rows: {err}"))?;
    }

    if purging::purge_event_storage_in_tx(store, &file_event_id)
        .map_err(|err| format!("purge file event: {err}"))?
    {
        report.event_bytes_purged += 1;
    }
    Ok(())
}

fn purge_file_slice_for_deleted_file(
    store: &Store,
    slice_event_id: EventId,
    bytes: &[u8],
    report: &mut PurgeReport,
) -> Result<(), String> {
    let envelope = file_slice::codec::decode_signed(bytes)?;
    let (slice, file_event_id) = file_slice::codec::decode(&envelope.payload)?;
    let descriptor_purged = event_schema::event_bytes(store, &file_event_id)
        .map_err(|err| format!("load descriptor bytes: {err}"))?
        .is_none();
    let message_id_tombstoned = if descriptor_purged {
        // The descriptor was already purged. We rely on the file_id index
        // also being gone: confirm by looking up by file_id; if the
        // descriptor row is still present we honor it as live.
        file::schema::file_event_id_for_file_id(store, slice.workspace_id, slice.file_id)?.is_none()
    } else {
        // Descriptor still exists. Look up its message_id and check whether
        // that message has a tombstone; if yes, this slice should also be
        // purged on the next scan-after-descriptor path. If the descriptor
        // exists and message has no tombstone, the slice is live.
        let Some(descriptor_bytes) = event_schema::event_bytes(store, &file_event_id)
            .map_err(|err| format!("load descriptor bytes: {err}"))?
        else {
            // Race: descriptor was purged between checks. Treat as deleted.
            return purge_slice_rows_and_event(store, slice_event_id, &slice, report);
        };
        let descriptor_envelope = file::codec::decode_signed(&descriptor_bytes)?;
        let descriptor = file::codec::decode(&descriptor_envelope.payload)?;
        message::schema::message_tombstone_exists(
            store,
            descriptor.workspace_id,
            descriptor.message_id,
        )?
    };
    if !message_id_tombstoned {
        return Ok(());
    }
    purge_slice_rows_and_event(store, slice_event_id, &slice, report)
}

fn purge_slice_rows_and_event(
    store: &Store,
    slice_event_id: EventId,
    slice: &file_slice::types::FileSliceEvent,
    report: &mut PurgeReport,
) -> Result<(), String> {
    let slot_key =
        file_slice::schema::file_slice_key(slice.workspace_id, slice.file_id, slice.slice_number);
    report.file_slice_rows_deleted += store
        .delete_table_rows_in_tx(file_slice::schema::FILE_SLICES, vec![slot_key])
        .map_err(|err| format!("delete file slice row: {err}"))?;
    if purging::purge_event_storage_in_tx(store, &slice_event_id)
        .map_err(|err| format!("purge file slice event: {err}"))?
    {
        report.event_bytes_purged += 1;
    }
    Ok(())
}

fn has_author_deletion_label(
    store: &Store,
    message_id: &EventId,
    author_user_id: &EventId,
) -> Result<bool, String> {
    let labels = event_schema::event_labels(store, message_id)
        .map_err(|err| format!("load deletion labels: {err}"))?;
    Ok(labels.iter().any(|label| {
        message_deletion::types::deletion_label_author(label)
            .map(|author| author == *author_user_id)
            .unwrap_or(false)
    }))
}

fn has_file_deletion_label(
    store: &Store,
    file_event_id: &EventId,
    author_user_id: &EventId,
) -> Result<bool, String> {
    let labels = event_schema::event_labels(store, file_event_id)
        .map_err(|err| format!("load file deletion labels: {err}"))?;
    Ok(labels.iter().any(|label| {
        file_deletion::types::deletion_label_author(label)
            .map(|author| author == *author_user_id)
            .unwrap_or(false)
    }))
}


#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::content::message::types::MessagePlaintext;
    use crate::protocol::event_modules::content::reaction::types::ReactionPlaintext;
    use crate::protocol::event_modules::schema::EventLabel;
    use crate::protocol::event_modules::types::{event_id, EventStatus};
    use crate::protocol::Protocol;
    use crate::workers::pipeline_helpers::event_lifecycle;

    use super::*;

    const WORKSPACE: EventId = [1; 32];
    const AUTHOR: EventId = [2; 32];
    const SIGNER: EventId = [3; 32];
    const FRONTIER: EventId = [4; 32];
    const KEY_SECRET: [u8; 32] = [5; 32];

    const LEAF_NODE_ID: EventId = [42; 32];

    fn message_record(text: &str) -> crate::protocol::event_modules::types::EventRecord {
        let output = message::commands::send(message::commands::SendMessage {
            workspace_id: WORKSPACE,
            created_at_ms: 10,
            author_user_id: AUTHOR,
            signer_endpoint_shared_id: SIGNER,
            signer_private_key: [9; 32],
            removal_frontier_id: FRONTIER,
            local_history_node_secret_id: LEAF_NODE_ID,
            leaf_node_secret: KEY_SECRET,
            text: text.to_string(),
        })
        .expect("message");
        output.events[0].record().clone()
    }

    fn reaction_record(
        target_message_id: EventId,
    ) -> crate::protocol::event_modules::types::EventRecord {
        let output = reaction::commands::post(reaction::commands::PostReaction {
            workspace_id: WORKSPACE,
            created_at_ms: 11,
            target_message_id,
            author_user_id: AUTHOR,
            signer_endpoint_shared_id: SIGNER,
            signer_private_key: [9; 32],
            removal_frontier_id: FRONTIER,
            local_history_node_secret_id: LEAF_NODE_ID,
            leaf_node_secret: KEY_SECRET,
            emoji: "+1".to_string(),
        })
        .expect("reaction");
        output.events[0].record().clone()
    }

    #[test]
    fn purges_deleted_message_and_attached_reaction_bytes_and_rows() {
        let store = Protocol::open_memory_store().expect("store");
        let message_record = message_record("delete me");
        let message_id = event_id(&message_record.canonical_bytes);
        let reaction_record = reaction_record(message_id);
        let reaction_id = event_id(&reaction_record.canonical_bytes);

        event_lifecycle::insert_event(&store, &message_record, EventStatus::Applied)
            .expect("insert message event");
        event_lifecycle::insert_event(&store, &reaction_record, EventStatus::Applied)
            .expect("insert reaction event");
        store
            .insert_table_rows(vec![
                message::schema::message_row(
                    message_id,
                    SIGNER,
                    &MessagePlaintext {
                        workspace_id: WORKSPACE,
                        created_at_ms: 10,
                        author_user_id: AUTHOR,
                        removal_frontier_id: FRONTIER,
                        local_history_node_secret_id: LEAF_NODE_ID,
                        text: "delete me".to_string(),
                    },
                )
                .expect("message row"),
                reaction::schema::reaction_row(
                    reaction_id,
                    SIGNER,
                    &ReactionPlaintext {
                        workspace_id: WORKSPACE,
                        created_at_ms: 11,
                        target_message_id: message_id,
                        author_user_id: AUTHOR,
                        removal_frontier_id: FRONTIER,
                        local_history_node_secret_id: LEAF_NODE_ID,
                        emoji: "+1".to_string(),
                    },
                )
                .expect("reaction row"),
            ])
            .expect("insert read rows");
        store
            .insert_table_rows(event_schema::event_label_rows(vec![EventLabel {
                event_id: message_id,
                label: message_deletion::types::deletion_label(&AUTHOR),
            }]))
            .expect("insert deletion label");

        let protocol = Protocol::new();
        let report = run(&store, &protocol, Work::Drain { limit: 10 }).expect("purge");

        assert_eq!(report.tombstones_written, 1);
        assert_eq!(report.event_bytes_purged, 2);
        assert!(event_schema::event_bytes(&store, &message_id)
            .expect("message bytes")
            .is_none());
        assert!(event_schema::event_bytes(&store, &reaction_id)
            .expect("reaction bytes")
            .is_none());
        assert!(
            message::schema::message_tombstone_exists(&store, WORKSPACE, message_id)
                .expect("tombstone")
        );
        assert!(
            message::schema::message_by_id(&store, WORKSPACE, message_id)
                .expect("message row")
                .is_none()
        );
        assert_eq!(
            reaction::schema::list_for_workspace(&store, WORKSPACE)
                .expect("reactions")
                .len(),
            0
        );
    }

    #[test]
    fn ignores_deletion_label_from_non_author() {
        let store = Protocol::open_memory_store().expect("store");
        let message_record = message_record("keep me");
        let message_id = event_id(&message_record.canonical_bytes);
        event_lifecycle::insert_event(&store, &message_record, EventStatus::Applied)
            .expect("insert message event");
        store
            .insert_table_rows(event_schema::event_label_rows(vec![EventLabel {
                event_id: message_id,
                label: message_deletion::types::deletion_label(&[99; 32]),
            }]))
            .expect("insert deletion label");

        let protocol = Protocol::new();
        let report = run(&store, &protocol, Work::Drain { limit: 10 }).expect("purge");

        assert_eq!(report.event_bytes_purged, 0);
        assert!(event_schema::event_bytes(&store, &message_id)
            .expect("message bytes")
            .is_some());
        assert!(
            !message::schema::message_tombstone_exists(&store, WORKSPACE, message_id)
                .expect("tombstone")
        );
    }
}

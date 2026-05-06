//! Content purge worker.
//!
//! Inputs: durable shared content events plus deletion labels written by
//! projectors.
//! State: content read-model rows, durable message tombstone summaries, and the
//! protocol event store.
//! Step: verify message deletion labels against encrypted message metadata,
//! write tombstones, remove visible plaintext rows, and purge obsolete message
//! or reaction event bytes.
//! Outputs: `content.message_tombstones` rows and row/event deletes.
//! Consume: purged event rows leave the durable deletion label/tombstone facts
//! behind so semantic deletion survives without keeping ciphertext bytes.
//! Failure: one malformed event aborts that worker transaction and will be
//! retried; projectors remain the authority on validity before normal reads.
//! Fairness: `Work::Drain { limit }` bounds one scan.

use crate::core::daemon::{StepContext, Worker};
use crate::core::store::Store;
use crate::protocol::event_modules::content::{message, message_deletion, reaction};
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::types::EventId;
use crate::workers::common;
use crate::workers::DaemonWorkerContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    Drain { limit: usize },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PurgeReport {
    pub scanned_events: usize,
    pub tombstones_written: usize,
    pub message_rows_deleted: usize,
    pub reaction_rows_deleted: usize,
    pub event_bytes_purged: usize,
}

pub fn run(store: &Store, work: Work) -> Result<PurgeReport, String> {
    match work {
        Work::Drain { limit } => drain(store, limit),
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
    let report = run(
        ctx.app.store(),
        Work::Drain {
            limit: ctx.options.work_limit,
        },
    )
    .map_err(|err| format!("purge content: {err}"))?;
    ctx.report
        .add("purged_content_events", report.event_bytes_purged);
    Ok(())
}

fn drain(store: &Store, limit: usize) -> Result<PurgeReport, String> {
    store
        .write_transaction(|store| drain_in_tx(store, limit).map_err(table_error))
        .map_err(|err| format!("drain content purge: {err}"))
}

fn drain_in_tx(store: &Store, limit: usize) -> Result<PurgeReport, String> {
    let entries = event_schema::event_index_entries_in_timestamp_range(store, 0, u64::MAX)
        .map_err(|err| format!("load event index: {err}"))?;
    let mut report = PurgeReport::default();
    for entry in entries.into_iter().take(limit) {
        let Some(bytes) = event_schema::event_bytes(store, &entry.event_id)
            .map_err(|err| format!("load event bytes: {err}"))?
        else {
            continue;
        };
        report.scanned_events += 1;
        match bytes.first().copied() {
            Some(message::codec::TYPE_SIGNED_MESSAGE) => {
                purge_deleted_message(store, entry.event_id, &bytes, &mut report)?;
            }
            Some(reaction::codec::TYPE_SIGNED_REACTION) => {
                purge_reaction_for_deleted_message(store, entry.event_id, &bytes, &mut report)?;
            }
            _ => {}
        }
    }
    Ok(report)
}

fn purge_deleted_message(
    store: &Store,
    message_id: EventId,
    bytes: &[u8],
    report: &mut PurgeReport,
) -> Result<(), String> {
    let envelope = message::codec::decode_signed(bytes)?;
    let event = message::codec::decode(&envelope.payload)?;
    if !has_author_deletion_label(store, &message_id, &event.author_user_id)? {
        return Ok(());
    }

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
    if common::purge_event_storage_in_tx(store, &message_id)
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
    if common::purge_event_storage_in_tx(store, &reaction_id)
        .map_err(|err| format!("purge reaction event: {err}"))?
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

fn table_error(err: String) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(err)
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::content::message::types::MessagePlaintext;
    use crate::protocol::event_modules::content::reaction::types::ReactionPlaintext;
    use crate::protocol::event_modules::encryption::local_key_secret;
    use crate::protocol::event_modules::schema::EventLabel;
    use crate::protocol::event_modules::types::{event_id, EventStatus};
    use crate::protocol::Protocol;

    use super::*;

    const WORKSPACE: EventId = [1; 32];
    const AUTHOR: EventId = [2; 32];
    const SIGNER: EventId = [3; 32];
    const FRONTIER: EventId = [4; 32];
    const KEY_SECRET: [u8; 32] = [5; 32];

    fn local_key_secret_id() -> EventId {
        local_key_secret::commands::from_key_secret(WORKSPACE, FRONTIER, KEY_SECRET)
            .expect("local key")
            .value
            .local_key_secret_id
    }

    fn message_record(text: &str) -> crate::protocol::event_modules::types::EventRecord {
        let output = message::commands::send(message::commands::SendMessage {
            workspace_id: WORKSPACE,
            created_at_ms: 10,
            author_user_id: AUTHOR,
            signer_endpoint_shared_id: SIGNER,
            signer_private_key: [9; 32],
            removal_frontier_id: FRONTIER,
            local_key_secret_id: local_key_secret_id(),
            key_secret: KEY_SECRET,
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
            local_key_secret_id: local_key_secret_id(),
            key_secret: KEY_SECRET,
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

        event_schema::insert_event(&store, &message_record, EventStatus::Applied)
            .expect("insert message event");
        event_schema::insert_event(&store, &reaction_record, EventStatus::Applied)
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
                        local_key_secret_id: local_key_secret_id(),
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
                        local_key_secret_id: local_key_secret_id(),
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

        let report = run(&store, Work::Drain { limit: 10 }).expect("purge");

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
        event_schema::insert_event(&store, &message_record, EventStatus::Applied)
            .expect("insert message event");
        store
            .insert_table_rows(event_schema::event_label_rows(vec![EventLabel {
                event_id: message_id,
                label: message_deletion::types::deletion_label(&[99; 32]),
            }]))
            .expect("insert deletion label");

        let report = run(&store, Work::Drain { limit: 10 }).expect("purge");

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

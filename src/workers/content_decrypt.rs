//! Content decrypt worker.
//!
//! Inputs: sealed message/reaction rows written by content projectors.
//! State: local key-secret rows, removal frontier rows, plaintext content read
//! rows, and tombstone rows.
//! Step: open sealed rows only when the matching local key-secret commitment is
//! present, then materialize the ordinary read-model row and remove the sealed
//! work row.
//! Outputs: `content.messages` and `content.reactions` rows.
//! Consume: sealed rows are deleted after successful materialization or after a
//! tombstone proves the content should stay hidden.
//! Failure: rows with missing or mismatched key material are left for a later
//! run; malformed ciphertext aborts only that bounded worker transaction.
//! Fairness: `Work::Drain { limit }` bounds one scan.

use crate::core::crypto;
use crate::core::daemon::{StepContext, Worker};
use crate::core::store::Store;
use crate::protocol::event_modules::content::{message, reaction};
use crate::protocol::event_modules::encryption::{local_key_secret, removal_frontier};
use crate::workers::DaemonWorkerContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    Drain { limit: usize },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecryptReport {
    pub scanned_messages: usize,
    pub materialized_messages: usize,
    pub skipped_messages: usize,
    pub scanned_reactions: usize,
    pub materialized_reactions: usize,
    pub skipped_reactions: usize,
}

pub fn run(store: &Store, work: Work) -> Result<DecryptReport, String> {
    match work {
        Work::Drain { limit } => drain(store, limit),
    }
}

pub(crate) fn daemon_worker<C>() -> Worker<C>
where
    C: DaemonWorkerContext,
{
    Worker {
        name: "content_decrypt",
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
    .map_err(|err| format!("decrypt content: {err}"))?;
    ctx.report
        .add("messages_opened", report.materialized_messages);
    ctx.report
        .add("reactions_opened", report.materialized_reactions);
    Ok(())
}

fn drain(store: &Store, limit: usize) -> Result<DecryptReport, String> {
    store
        .write_transaction(|store| drain_in_tx(store, limit).map_err(table_error))
        .map_err(|err| format!("drain content decrypt: {err}"))
}

fn drain_in_tx(store: &Store, limit: usize) -> Result<DecryptReport, String> {
    let mut report = DecryptReport::default();
    for row in message::schema::list_sealed(store, limit)? {
        report.scanned_messages += 1;
        if materialize_message(store, &row)? {
            report.materialized_messages += 1;
        } else {
            report.skipped_messages += 1;
        }
    }
    for row in reaction::schema::list_sealed(store, limit)? {
        report.scanned_reactions += 1;
        if materialize_reaction(store, &row)? {
            report.materialized_reactions += 1;
        } else {
            report.skipped_reactions += 1;
        }
    }
    Ok(report)
}

fn materialize_message(
    store: &Store,
    row: &message::schema::SealedMessageRow,
) -> Result<bool, String> {
    if message::schema::message_tombstone_exists(store, row.workspace_id, row.message_id)? {
        delete_sealed_message(store, row)?;
        return Ok(false);
    }
    if message::schema::message_by_id(store, row.workspace_id, row.message_id)?.is_some() {
        delete_sealed_message(store, row)?;
        return Ok(false);
    }
    let Some(secret) = content_key_secret(store, row.workspace_id, row.removal_frontier_id)? else {
        return Ok(false);
    };
    if secret.local_key_secret_id != row.local_key_secret_id {
        return Ok(false);
    }

    let event = message::types::MessageEvent {
        workspace_id: row.workspace_id,
        created_at_ms: row.created_at_ms,
        author_user_id: row.author_user_id,
        removal_frontier_id: row.removal_frontier_id,
        local_key_secret_id: row.local_key_secret_id,
        nonce: row.nonce,
        ciphertext: row.ciphertext,
    };
    let plaintext = crypto::xchacha20poly1305_decrypt(
        &secret.key_secret,
        &message::codec::associated_data(&event, row.signer_endpoint_shared_id),
        &event.nonce,
        &event.ciphertext,
    )
    .map_err(|_| "open sealed message".to_string())?;
    let text = message::codec::decode_text_slot(&plaintext)?;
    store
        .insert_table_rows_in_tx(vec![message::schema::message_row(
            row.message_id,
            row.signer_endpoint_shared_id,
            &message::types::MessagePlaintext {
                workspace_id: row.workspace_id,
                created_at_ms: row.created_at_ms,
                author_user_id: row.author_user_id,
                removal_frontier_id: row.removal_frontier_id,
                local_key_secret_id: row.local_key_secret_id,
                text,
            },
        )?])
        .map_err(|err| format!("write message row: {err}"))?;
    delete_sealed_message(store, row)?;
    Ok(true)
}

fn materialize_reaction(
    store: &Store,
    row: &reaction::schema::SealedReactionRow,
) -> Result<bool, String> {
    if message::schema::message_tombstone_exists(store, row.workspace_id, row.target_message_id)? {
        delete_sealed_reaction(store, row)?;
        return Ok(false);
    }
    let Some(secret) = content_key_secret(store, row.workspace_id, row.removal_frontier_id)? else {
        return Ok(false);
    };
    if secret.local_key_secret_id != row.local_key_secret_id {
        return Ok(false);
    }

    let event = reaction::types::ReactionEvent {
        workspace_id: row.workspace_id,
        created_at_ms: row.created_at_ms,
        target_message_id: row.target_message_id,
        author_user_id: row.author_user_id,
        removal_frontier_id: row.removal_frontier_id,
        local_key_secret_id: row.local_key_secret_id,
        nonce: row.nonce,
        ciphertext: row.ciphertext,
    };
    let plaintext = crypto::xchacha20poly1305_decrypt(
        &secret.key_secret,
        &reaction::codec::associated_data(&event, row.signer_endpoint_shared_id),
        &event.nonce,
        &event.ciphertext,
    )
    .map_err(|_| "open sealed reaction".to_string())?;
    let emoji = reaction::codec::decode_emoji_slot(&plaintext)?;
    store
        .insert_table_rows_in_tx(vec![reaction::schema::reaction_row(
            row.reaction_id,
            row.signer_endpoint_shared_id,
            &reaction::types::ReactionPlaintext {
                workspace_id: row.workspace_id,
                created_at_ms: row.created_at_ms,
                target_message_id: row.target_message_id,
                author_user_id: row.author_user_id,
                removal_frontier_id: row.removal_frontier_id,
                local_key_secret_id: row.local_key_secret_id,
                emoji,
            },
        )?])
        .map_err(|err| format!("write reaction row: {err}"))?;
    delete_sealed_reaction(store, row)?;
    Ok(true)
}

fn content_key_secret(
    store: &Store,
    workspace_id: crate::protocol::event_modules::types::EventId,
    removal_frontier_id: crate::protocol::event_modules::types::EventId,
) -> Result<Option<local_key_secret::types::LocalKeySecretRow>, String> {
    if removal_frontier::schema::get(store, workspace_id, removal_frontier_id)?.is_none() {
        return Ok(None);
    }
    local_key_secret::schema::get(store, workspace_id, removal_frontier_id)
}

fn delete_sealed_message(
    store: &Store,
    row: &message::schema::SealedMessageRow,
) -> Result<(), String> {
    store
        .delete_table_rows_in_tx(
            message::schema::SEALED_MESSAGES,
            vec![message::schema::message_key(
                row.workspace_id,
                row.message_id,
            )],
        )
        .map_err(|err| format!("delete sealed message row: {err}"))?;
    Ok(())
}

fn delete_sealed_reaction(
    store: &Store,
    row: &reaction::schema::SealedReactionRow,
) -> Result<(), String> {
    store
        .delete_table_rows_in_tx(
            reaction::schema::SEALED_REACTIONS,
            vec![reaction::schema::reaction_key(
                row.workspace_id,
                row.reaction_id,
            )],
        )
        .map_err(|err| format!("delete sealed reaction row: {err}"))?;
    Ok(())
}

fn table_error(err: String) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(err)
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::encryption::{local_key_secret, removal_frontier};
    use crate::protocol::event_modules::types::{event_id, EventId};
    use crate::protocol::Protocol;

    use super::*;

    const WORKSPACE: EventId = [1; 32];
    const AUTHOR: EventId = [2; 32];
    const SIGNER: EventId = [3; 32];
    const KEY_SECRET: [u8; 32] = [7; 32];

    #[test]
    fn materializes_plaintext_rows_from_sealed_message_and_reaction_rows() {
        let store = Protocol::open_memory_store().expect("store");
        let frontier =
            removal_frontier::commands::create(removal_frontier::commands::CreateRemovalFrontier {
                workspace_id: WORKSPACE,
                created_at_ms: 1,
                authority_admin_id: [4; 32],
                signer_endpoint_shared_id: [5; 32],
                signer_private_key: [6; 32],
                removal_event_ids: Vec::new(),
            })
            .expect("frontier");
        let frontier_record = frontier.events[0].record().clone();
        let frontier_id = event_id(&frontier_record.canonical_bytes);
        let frontier_event = removal_frontier::codec::decode(
            &removal_frontier::codec::decode_signed(&frontier_record.canonical_bytes)
                .expect("signed frontier")
                .payload,
        )
        .expect("frontier event");
        let local_secret =
            local_key_secret::commands::from_key_secret(WORKSPACE, frontier_id, KEY_SECRET)
                .expect("local secret")
                .value;

        store
            .insert_table_rows(vec![
                removal_frontier::schema::removal_frontier_row(frontier_id, &frontier_event)
                    .expect("frontier row"),
                local_key_secret::schema::local_key_secret_row(
                    local_secret.local_key_secret_id,
                    &local_secret.event,
                ),
            ])
            .expect("insert key rows");

        let message_output = message::commands::send(message::commands::SendMessage {
            workspace_id: WORKSPACE,
            created_at_ms: 10,
            author_user_id: AUTHOR,
            signer_endpoint_shared_id: SIGNER,
            signer_private_key: [9; 32],
            removal_frontier_id: frontier_id,
            local_key_secret_id: local_secret.local_key_secret_id,
            key_secret: KEY_SECRET,
            text: "opened".to_string(),
        })
        .expect("message");
        let message_record = message_output.events[0].record().clone();
        let message_event = message::codec::decode(
            &message::codec::decode_signed(&message_record.canonical_bytes)
                .expect("signed message")
                .payload,
        )
        .expect("message event");

        let reaction_output = reaction::commands::post(reaction::commands::PostReaction {
            workspace_id: WORKSPACE,
            created_at_ms: 11,
            target_message_id: message_output.value.message_id,
            author_user_id: AUTHOR,
            signer_endpoint_shared_id: SIGNER,
            signer_private_key: [9; 32],
            removal_frontier_id: frontier_id,
            local_key_secret_id: local_secret.local_key_secret_id,
            key_secret: KEY_SECRET,
            emoji: "ok".to_string(),
        })
        .expect("reaction");
        let reaction_record = reaction_output.events[0].record().clone();
        let reaction_event = reaction::codec::decode(
            &reaction::codec::decode_signed(&reaction_record.canonical_bytes)
                .expect("signed reaction")
                .payload,
        )
        .expect("reaction event");

        store
            .insert_table_rows(vec![
                message::schema::sealed_message_row(
                    message_output.value.message_id,
                    SIGNER,
                    &message_event,
                )
                .expect("sealed message"),
                reaction::schema::sealed_reaction_row(
                    reaction_output.value.reaction_id,
                    SIGNER,
                    &reaction_event,
                )
                .expect("sealed reaction"),
            ])
            .expect("insert sealed rows");

        let report = run(&store, Work::Drain { limit: 10 }).expect("materialize");

        assert_eq!(report.materialized_messages, 1);
        assert_eq!(report.materialized_reactions, 1);
        assert_eq!(
            message::schema::message_by_id(&store, WORKSPACE, message_output.value.message_id)
                .expect("message row")
                .expect("message present")
                .text,
            "opened"
        );
        assert_eq!(
            reaction::schema::list_for_workspace(&store, WORKSPACE).expect("reaction rows")[0]
                .emoji,
            "ok"
        );
        assert!(message::schema::list_sealed(&store, 10)
            .expect("sealed messages")
            .is_empty());
        assert!(reaction::schema::list_sealed(&store, 10)
            .expect("sealed reactions")
            .is_empty());
    }
}

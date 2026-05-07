//! Encryption worker.
//!
//! Projection records shared key-wrap facts; this worker performs the bounded
//! active step that can follow from those facts. It opens wraps only when the
//! matching local recipient private material is present, then admits the
//! resulting local key-secret event through the common event worker.
//!
//! History-node derivation is also a worker concern: when a sibling node names
//! `tombstone_node_id`, the projector exact-deletes the retired projection row,
//! and this worker follows up by purging the retired path-node's canonical
//! event bytes through `workers::pipeline_helpers::purging`. Without that purge the
//! plaintext `node_secret` from the retired event would still sit in
//! `event_modules.events`, defeating the HKDF range tree's forward-secrecy
//! claim.
//!
//! Recipient-key rotation also lives here. After the rotation worker admits the
//! `recipient_key_tombstone` shared events, it owns a follow-up local-retention
//! step: the retired `encryption.local_recipient_keys` row, the retired
//! `local_recipient_key` event canonical bytes, the retired `recipient_key`
//! event canonical bytes, and every `key_wrap` row plus event canonical bytes
//! addressed to a retired recipient must be purged. The tombstone projector
//! keeps the public read-model row delete; durable canonical-byte purge stays
//! in this worker because it crosses the retention boundary owned by
//! `workers::pipeline_helpers::purging`. Rotation depends on real X25519 +
//! XChaCha20-Poly1305 material from `core::crypto`; this file only schedules
//! commands and runs the cleanup transaction, it does not invent crypto.

use crate::core::crypto;
use crate::core::logical_clock;
use crate::core::store::Store;
use crate::protocol::event_modules::identity::{endpoint, endpoint_shared};
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::{self, EventRegistry};
use crate::workers::pipeline_helpers::purging;

use crate::protocol::event_modules::encryption::{
    key_wrap, local_history_node_secret, local_key_secret, local_recipient_key, recipient_key,
    recipient_key_tombstone,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    DeriveKeySecrets {
        batch_size: usize,
    },
    RotateRecipientKey {
        workspace_id: EventId,
    },
    DeriveHistoryNode {
        workspace_id: EventId,
        removal_frontier_id: EventId,
        source_secret_id: EventId,
        range_start: u64,
        range_width: u64,
        event_id_in_minute: Option<EventId>,
        tombstone_node_id: Option<EventId>,
    },
    /// Idempotently derive (or look up) the per-minute coarse-cover node and
    /// the per-message leaf for one
    /// `(workspace_id, removal_frontier_id, created_at_ms, leaf_nonce)` tuple.
    /// Senders call this before authoring a message so the canonical event
    /// can name the leaf id; receivers call it after admission blocks on the
    /// named leaf so dependency unblock can let the message project.
    DeriveMessageLeaf {
        workspace_id: EventId,
        removal_frontier_id: EventId,
        created_at_ms: u64,
        leaf_nonce: EventId,
    },
    /// Retire one deleted message's per-message leaf by purging the leaf's
    /// canonical event bytes and exact-deleting its projection row. The
    /// minute_node above it stays so other messages in the same minute keep
    /// decrypting.
    RetireDeletedMessageLeaf {
        workspace_id: EventId,
        removal_frontier_id: EventId,
        created_at_ms: u64,
        leaf_nonce: EventId,
    },
    /// Scan a bounded batch of admitted message and reaction events and derive
    /// their per-message leaves. This is the receiver-side wiring: when a
    /// signed message arrives blocked on a leaf id this peer has not yet
    /// derived, this work item reads `(workspace, frontier, created_at_ms,
    /// leaf_nonce)` out of the canonical bytes and runs `DeriveMessageLeaf`
    /// so dependency unblock can let the message project.
    DrainPendingMessageLeaves { batch_size: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    DerivedKeySecrets(DeriveReport),
    RotatedRecipientKey(RotateRecipientKeyReport),
    DerivedHistoryNode(DeriveHistoryNodeReport),
    DerivedMessageLeaf(DeriveMessageLeafReport),
    RetiredDeletedMessageLeaf(RetireDeletedMessageLeafReport),
    DrainedPendingMessageLeaves(DrainPendingLeavesReport),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DrainPendingLeavesReport {
    pub scanned_events: usize,
    pub derived_leaves: usize,
    pub admitted_events: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeriveReport {
    pub scanned_key_wraps: usize,
    pub derived_key_secrets: usize,
    pub failed_key_wraps: usize,
    pub admitted_events: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RotateRecipientKeyReport {
    pub old_active_recipient_keys: usize,
    pub tombstoned_recipient_keys: usize,
    pub local_recipient_key_id: Option<EventId>,
    pub recipient_key_id: Option<EventId>,
    pub admitted_events: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeriveHistoryNodeReport {
    pub local_history_node_secret_id: Option<EventId>,
    pub tombstoned_node_id: Option<EventId>,
    pub admitted_events: usize,
    pub purged_event_bytes: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeriveMessageLeafReport {
    pub local_history_node_secret_id: Option<EventId>,
    pub leaf_node_secret: Option<crate::core::crypto::XChaCha20Poly1305Key>,
    pub admitted_events: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetireDeletedMessageLeafReport {
    pub leaf_id: Option<EventId>,
    pub admitted_events: usize,
    pub purged_event_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RetiredRecipientKey {
    recipient_key_id: EventId,
    local_recipient_key_id: EventId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HistoryNodeJob {
    workspace_id: EventId,
    removal_frontier_id: EventId,
    source_secret_id: EventId,
    range_start: u64,
    range_width: u64,
    event_id_in_minute: Option<EventId>,
    tombstone_node_id: Option<EventId>,
}

pub fn run<R: EventRegistry>(store: &Store, registry: &R, work: Work) -> Result<Output, String> {
    match work {
        Work::DeriveKeySecrets { batch_size } => {
            derive_key_secrets(store, registry, batch_size).map(Output::DerivedKeySecrets)
        }
        Work::RotateRecipientKey { workspace_id } => {
            rotate_recipient_key(store, registry, workspace_id).map(Output::RotatedRecipientKey)
        }
        Work::DeriveHistoryNode {
            workspace_id,
            removal_frontier_id,
            source_secret_id,
            range_start,
            range_width,
            event_id_in_minute,
            tombstone_node_id,
        } => derive_history_node(
            store,
            registry,
            HistoryNodeJob {
                workspace_id,
                removal_frontier_id,
                source_secret_id,
                range_start,
                range_width,
                event_id_in_minute,
                tombstone_node_id,
            },
        )
        .map(Output::DerivedHistoryNode),
        Work::DeriveMessageLeaf {
            workspace_id,
            removal_frontier_id,
            created_at_ms,
            leaf_nonce,
        } => derive_message_leaf(
            store,
            registry,
            workspace_id,
            removal_frontier_id,
            created_at_ms,
            leaf_nonce,
        )
        .map(Output::DerivedMessageLeaf),
        Work::RetireDeletedMessageLeaf {
            workspace_id,
            removal_frontier_id,
            created_at_ms,
            leaf_nonce,
        } => retire_deleted_message_leaf(
            store,
            registry,
            workspace_id,
            removal_frontier_id,
            created_at_ms,
            leaf_nonce,
        )
        .map(Output::RetiredDeletedMessageLeaf),
        Work::DrainPendingMessageLeaves { batch_size } => {
            drain_pending_message_leaves(store, registry, batch_size)
                .map(Output::DrainedPendingMessageLeaves)
        }
    }
}

fn derive_key_secrets<R: EventRegistry>(
    store: &Store,
    registry: &R,
    batch_size: usize,
) -> Result<DeriveReport, String> {
    let mut report = DeriveReport::default();
    for row in key_wrap::schema::list_all(store)? {
        if report.scanned_key_wraps >= batch_size {
            break;
        }
        report.scanned_key_wraps += 1;
        if local_key_secret::schema::get(store, row.workspace_id, row.removal_frontier_id)?
            .is_some()
        {
            continue;
        }
        let Some(recipient) = recipient_key_row(store, row.workspace_id, row.recipient_key_id)?
        else {
            continue;
        };
        let Some(local_recipient) =
            local_recipient_key::schema::list_for_workspace(store, row.workspace_id)?
                .into_iter()
                .find(|candidate| candidate.recipient_key == recipient.recipient_key)
        else {
            continue;
        };

        let key_wrap_event = key_wrap_event_from_row(&row);
        let plaintext = match crypto::x25519_xchacha20poly1305_decrypt(
            &local_recipient.recipient_secret,
            &row.sender_wrap_public_key,
            key_wrap::codec::KEY_WRAP_PURPOSE,
            &key_wrap::codec::associated_data(&key_wrap_event, row.signer_endpoint_shared_id),
            &row.nonce,
            &row.ciphertext,
        ) {
            Ok(plaintext) => plaintext,
            Err(_) => {
                report.failed_key_wraps += 1;
                continue;
            }
        };
        let key_secret = match plaintext.try_into() {
            Ok(secret) => secret,
            Err(_) => {
                report.failed_key_wraps += 1;
                continue;
            }
        };
        let output = local_key_secret::commands::from_key_secret(
            row.workspace_id,
            row.removal_frontier_id,
            key_secret,
        )?;
        if output.value.local_key_secret_id != row.local_key_secret_id {
            report.failed_key_wraps += 1;
            continue;
        }

        let admitted = worker::run(
            store,
            registry,
            worker::AdmitAndDrain {
                output,
                batch_size: worker::DEFAULT_READY_BATCH,
            },
        )
        .map_err(|err| format!("admit local key secret: {err}"))?;
        if admitted.admitted.inserted_events > 0 {
            report.derived_key_secrets += 1;
        }
        report.admitted_events += admitted.admitted.inserted_events;
    }
    Ok(report)
}

fn rotate_recipient_key<R: EventRegistry>(
    store: &Store,
    registry: &R,
    workspace_id: EventId,
) -> Result<RotateRecipientKeyReport, String> {
    let membership = local_membership(store, workspace_id)?;
    let local = endpoint::commands::local_keypair(store)?
        .ok_or_else(|| "local endpoint is missing".to_string())?;
    if membership.signing_public_key != local.signing_public_key {
        return Err("local endpoint signing key does not match workspace membership".to_string());
    }
    if !membership.endpoint_role.can_receive_key_wraps() {
        return Err("local endpoint role cannot receive key wraps".to_string());
    }
    let old_active =
        active_local_recipient_keys(store, workspace_id, membership.endpoint_shared_id)?;
    let mut report = RotateRecipientKeyReport {
        old_active_recipient_keys: old_active.len(),
        ..RotateRecipientKeyReport::default()
    };

    let local_output = local_recipient_key::commands::create(workspace_id)?;
    let local_recipient_key_id = local_output.events[0].event_id();
    let local_public_key = local_output.value.recipient_key;
    let admitted = worker::run(
        store,
        registry,
        worker::AdmitAndDrain {
            output: local_output,
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("admit rotated local recipient key: {err}"))?;
    report.admitted_events += admitted.admitted.inserted_events;
    report.local_recipient_key_id = Some(local_recipient_key_id);

    let recipient_output =
        recipient_key::commands::publish(recipient_key::commands::PublishRecipientKey {
            workspace_id,
            created_at_ms: next_timestamp(store)?,
            endpoint_shared_id: membership.endpoint_shared_id,
            signer_private_key: local.signing_secret,
            recipient_key: local_public_key,
        })?;
    let new_recipient_key_id = recipient_output.value.recipient_key_id;
    let admitted = worker::run(
        store,
        registry,
        worker::AdmitAndDrain {
            output: recipient_output,
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("admit rotated recipient key: {err}"))?;
    report.admitted_events += admitted.admitted.inserted_events;
    report.recipient_key_id = Some(new_recipient_key_id);

    let mut retired = Vec::with_capacity(old_active.len());
    for old_key in &old_active {
        let tombstone = recipient_key_tombstone::commands::tombstone(
            recipient_key_tombstone::commands::TombstoneRecipientKey {
                workspace_id,
                created_at_ms: next_timestamp(store)?,
                endpoint_shared_id: membership.endpoint_shared_id,
                signer_private_key: local.signing_secret,
                old_recipient_key_id: old_key.recipient_key_id,
                new_recipient_key_id,
            },
        )?;
        let admitted = worker::run(
            store,
            registry,
            worker::AdmitAndDrain {
                output: tombstone,
                batch_size: worker::DEFAULT_READY_BATCH,
            },
        )
        .map_err(|err| format!("admit recipient key tombstone: {err}"))?;
        if admitted.admitted.inserted_events > 0 {
            report.tombstoned_recipient_keys += 1;
        }
        report.admitted_events += admitted.admitted.inserted_events;
        retired.push(*old_key);
    }

    // The shared tombstones above are durable, so the retired keys can never
    // re-enter the active set. Now purge the locally retained material that
    // would otherwise let an on-disk attacker reconstruct the old key secret:
    // the local X25519 private row, the retired local/recipient event bytes,
    // and every key_wrap event addressed to a retired recipient (rows and
    // canonical bytes alike). The tombstone semantic record itself is
    // intentionally preserved.
    purge_retired_recipient_material(store, workspace_id, &retired)
        .map_err(|err| format!("purge retired recipient material: {err}"))?;

    Ok(report)
}

fn derive_history_node<R: EventRegistry>(
    store: &Store,
    registry: &R,
    job: HistoryNodeJob,
) -> Result<DeriveHistoryNodeReport, String> {
    let source_secret = source_secret_material(
        store,
        job.workspace_id,
        job.removal_frontier_id,
        job.source_secret_id,
    )?;
    let output = local_history_node_secret::commands::derive(
        local_history_node_secret::commands::DeriveHistoryNodeSecret {
            workspace_id: job.workspace_id,
            removal_frontier_id: job.removal_frontier_id,
            source_secret_id: job.source_secret_id,
            source_secret,
            range_start: job.range_start,
            range_width: job.range_width,
            event_id_in_minute: job.event_id_in_minute,
            tombstone_node_id: job.tombstone_node_id,
        },
    )?;
    let local_history_node_secret_id = output.value.local_history_node_secret_id;
    let admitted = worker::run(
        store,
        registry,
        worker::AdmitAndDrain {
            output,
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("admit local history node secret: {err}"))?;
    let mut purged_event_bytes = 0;
    if let Some(retired_node_id) = job.tombstone_node_id {
        // The retired path-node event carries 32 bytes of plaintext node_secret
        // in its canonical bytes. The projection row was just exact-deleted by
        // the local_history_node_secret projector; without also purging the
        // durable canonical bytes, an on-disk attacker could still read
        // node_secret and re-derive every descendant secret the projector
        // pretends to have forgotten. Retention is worker territory because
        // projectors cannot purge durable event-store rows. The newly admitted
        // child event itself is intentionally preserved as the durable record
        // of supersession.
        let purged = store
            .write_transaction(|store| {
                purging::purge_event_storage_in_tx(store, &retired_node_id)
            })
            .map_err(|err| format!("purge retired history node bytes: {err}"))?;
        if purged {
            purged_event_bytes += 1;
        }
    }
    Ok(DeriveHistoryNodeReport {
        local_history_node_secret_id: Some(local_history_node_secret_id),
        tombstoned_node_id: job.tombstone_node_id,
        admitted_events: admitted.admitted.inserted_events,
        purged_event_bytes,
    })
}

/// Idempotently derive (or look up) the per-message leaf chain.
///
/// The chain is `local_key_secret_root -> minute_node -> leaf` where:
///
///   * `minute_node` lives at
///     `(workspace_id, removal_frontier_id, range_start=unix_minute,
///       range_width=1, event_id_in_minute=None)` and is shared across every
///     message authored in the same `unix_minute`.
///   * `leaf` lives at the same range with
///     `event_id_in_minute=Some(leaf_nonce)` and is private to this message.
///
/// Both sender and receiver call this with the same `(created_at_ms,
/// leaf_nonce)` and reach the same leaf id by BLAKE3-keyed-hash determinism.
/// The minute_node row is reused on subsequent calls in the same minute.
fn derive_message_leaf<R: EventRegistry>(
    store: &Store,
    registry: &R,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    created_at_ms: u64,
    leaf_nonce: EventId,
) -> Result<DeriveMessageLeafReport, String> {
    if leaf_nonce.iter().all(|byte| *byte == 0) {
        return Err("derive_message_leaf requires non-zero leaf_nonce".to_string());
    }
    let root = local_key_secret::schema::get(store, workspace_id, removal_frontier_id)?
        .ok_or_else(|| "local key secret is missing for removal frontier".to_string())?;
    let unix_minute =
        crate::protocol::event_modules::content::message::types::unix_minute_for(created_at_ms);
    let leaf_width = crate::protocol::event_modules::content::message::types::LEAF_RANGE_WIDTH;

    let mut admitted_events = 0;
    let minute_id = match local_history_node_secret::schema::get(
        store,
        workspace_id,
        removal_frontier_id,
        unix_minute,
        leaf_width,
        None,
    )? {
        Some(row) => row.local_history_node_secret_id,
        None => {
            let report = derive_history_node(
                store,
                registry,
                HistoryNodeJob {
                    workspace_id,
                    removal_frontier_id,
                    source_secret_id: root.local_key_secret_id,
                    range_start: unix_minute,
                    range_width: leaf_width,
                    event_id_in_minute: None,
                    tombstone_node_id: None,
                },
            )?;
            admitted_events += report.admitted_events;
            report
                .local_history_node_secret_id
                .ok_or_else(|| "minute history node was not admitted".to_string())?
        }
    };

    let leaf_row = match local_history_node_secret::schema::get_leaf(
        store,
        workspace_id,
        removal_frontier_id,
        unix_minute,
        leaf_nonce,
    )? {
        Some(row) => row,
        None => {
            let report = derive_history_node(
                store,
                registry,
                HistoryNodeJob {
                    workspace_id,
                    removal_frontier_id,
                    source_secret_id: minute_id,
                    range_start: unix_minute,
                    range_width: leaf_width,
                    event_id_in_minute: Some(leaf_nonce),
                    tombstone_node_id: None,
                },
            )?;
            admitted_events += report.admitted_events;
            local_history_node_secret::schema::get_leaf(
                store,
                workspace_id,
                removal_frontier_id,
                unix_minute,
                leaf_nonce,
            )?
            .ok_or_else(|| "leaf history node was not projected".to_string())?
        }
    };

    Ok(DeriveMessageLeafReport {
        local_history_node_secret_id: Some(leaf_row.local_history_node_secret_id),
        leaf_node_secret: Some(leaf_row.node_secret),
        admitted_events,
    })
}

/// Retire the per-message leaf bytes for a deleted message.
///
/// With per-message leaves under a per-minute coarse cover, manual delete
/// only purges the leaf event canonical bytes and exact-deletes its
/// projection row. The minute_node above the leaf stays intact so other
/// messages in the same minute keep decrypting; whole-minute retirement
/// (disappearing messages) is a separate flow that lands later.
fn retire_deleted_message_leaf<R: EventRegistry>(
    store: &Store,
    _registry: &R,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    created_at_ms: u64,
    leaf_nonce: EventId,
) -> Result<RetireDeletedMessageLeafReport, String> {
    let unix_minute =
        crate::protocol::event_modules::content::message::types::unix_minute_for(created_at_ms);

    let mut purged_event_bytes = 0;

    let leaf_row = local_history_node_secret::schema::get_leaf(
        store,
        workspace_id,
        removal_frontier_id,
        unix_minute,
        leaf_nonce,
    )?;
    let leaf_id = leaf_row.as_ref().map(|row| row.local_history_node_secret_id);

    if let Some(leaf_id) = leaf_id {
        // Purge the leaf's canonical event bytes. The leaf carries the
        // plaintext per-message AEAD key in its canonical body; without this
        // explicit purge an on-disk attacker could still read the leaf bytes
        // and decrypt the deleted message.
        let purged = store
            .write_transaction(|store| purging::purge_event_storage_in_tx(store, &leaf_id))
            .map_err(|err| format!("purge deleted message leaf bytes: {err}"))?;
        if purged {
            purged_event_bytes += 1;
        }
        // Exact-delete the leaf projection row. Whether the canonical bytes
        // were already purged or not, dropping the row keeps workers from
        // re-deriving children from this leaf coordinate.
        store
            .delete_table_rows(
                local_history_node_secret::schema::LOCAL_HISTORY_NODE_SECRETS,
                vec![local_history_node_secret::schema::local_history_node_secret_key(
                    workspace_id,
                    removal_frontier_id,
                    unix_minute,
                    1,
                    Some(leaf_nonce),
                )],
            )
            .map_err(|err| format!("delete leaf projection row: {err}"))?;
    }

    Ok(RetireDeletedMessageLeafReport {
        leaf_id,
        admitted_events: 0,
        purged_event_bytes,
    })
}

/// Scan blocked content events whose missing dep is the per-message HKDF
/// leaf and derive each one's leaf if it is not already projected locally.
/// The common worker's dependency-unblock pass then unblocks any blocked
/// content event whose leaf has just been admitted.
///
/// Iteration is bounded by `batch_size` so the daemon never spends an
/// unbounded fairness slice scanning all events. We walk only the
/// `BLOCKED_EVENTS_BY_MISSING_DEP` index, which is empty unless an inbound
/// content event is currently waiting on a leaf this peer has not yet
/// derived; on the sender side that index does not grow.
fn drain_pending_message_leaves<R: EventRegistry>(
    store: &Store,
    registry: &R,
    batch_size: usize,
) -> Result<DrainPendingLeavesReport, String> {
    use crate::protocol::event_modules::content::{message, reaction};

    let mut report = DrainPendingLeavesReport::default();
    let blocked_pairs = store
        .table_rows_with_key_prefix(
            event_schema::BLOCKED_EVENTS_BY_MISSING_DEP,
            &[],
            batch_size,
        )
        .map_err(|err| format!("load blocked edges: {err}"))?;
    for (key, _) in blocked_pairs {
        if report.scanned_events >= batch_size {
            break;
        }
        let Ok((_missing_dep_id, blocked_event_id)) = event_schema::split_edge_key(&key) else {
            continue;
        };
        let Some(bytes) = event_schema::event_bytes(store, &blocked_event_id)
            .map_err(|err| format!("load event bytes: {err}"))?
        else {
            continue;
        };
        let (workspace_id, removal_frontier_id, created_at_ms, leaf_id, leaf_nonce) = match bytes
            .first()
            .copied()
        {
            Some(message::codec::TYPE_SIGNED_MESSAGE) => {
                let envelope = match message::codec::decode_signed(&bytes) {
                    Ok(envelope) => envelope,
                    Err(_) => continue,
                };
                let event = match message::codec::decode(&envelope.payload) {
                    Ok(event) => event,
                    Err(_) => continue,
                };
                (
                    event.workspace_id,
                    event.removal_frontier_id,
                    event.created_at_ms,
                    event.local_history_node_secret_id,
                    event.leaf_nonce,
                )
            }
            Some(reaction::codec::TYPE_SIGNED_REACTION) => {
                let envelope = match reaction::codec::decode_signed(&bytes) {
                    Ok(envelope) => envelope,
                    Err(_) => continue,
                };
                let event = match reaction::codec::decode(&envelope.payload) {
                    Ok(event) => event,
                    Err(_) => continue,
                };
                (
                    event.workspace_id,
                    event.removal_frontier_id,
                    event.created_at_ms,
                    event.local_history_node_secret_id,
                    event.leaf_nonce,
                )
            }
            _ => continue,
        };
        report.scanned_events += 1;
        // Skip if local_key_secret root is missing for this frontier — the
        // common worker is still blocked on key wraps and will retry once the
        // frontier has key material locally.
        if local_key_secret::schema::get(store, workspace_id, removal_frontier_id)?.is_none() {
            continue;
        }
        // Skip if the leaf event already lives in this peer's event store.
        if event_schema::has_event(store, &leaf_id)
            .map_err(|err| format!("look up leaf event: {err}"))?
        {
            continue;
        }
        let derived = derive_message_leaf(
            store,
            registry,
            workspace_id,
            removal_frontier_id,
            created_at_ms,
            leaf_nonce,
        )?;
        if derived
            .local_history_node_secret_id
            .is_some_and(|id| id == leaf_id)
        {
            report.derived_leaves += 1;
            report.admitted_events += derived.admitted_events;
        }
    }
    Ok(report)
}

pub(crate) fn daemon_worker<C>() -> crate::core::daemon::Worker<C>
where
    C: crate::workers::DaemonWorkerContext,
{
    use crate::core::daemon::{StepContext, Worker};
    fn step<C>(ctx: &mut StepContext<'_, C>) -> Result<(), String>
    where
        C: crate::workers::DaemonWorkerContext,
    {
        let app = &*ctx.app;
        let store = app.store();
        let report = drain_pending_message_leaves(store, app, ctx.options.work_limit)
            .map_err(|err| format!("drain pending message leaves: {err}"))?;
        ctx.report
            .add("derived_message_leaves", report.derived_leaves);
        Ok(())
    }
    Worker {
        name: "encryption_message_leaves",
        run: step::<C>,
    }
}

fn recipient_key_row(
    store: &Store,
    workspace_id: EventId,
    recipient_key_id: EventId,
) -> Result<Option<recipient_key::types::RecipientKeyRow>, String> {
    let key = recipient_key::schema::recipient_key_key(workspace_id, recipient_key_id);
    store
        .table_row(recipient_key::schema::RECIPIENT_KEYS, &key)
        .map_err(|err| format!("load recipient key: {err}"))?
        .map(|value| recipient_key::schema::decode_recipient_key_row(&key, &value))
        .transpose()
}

fn local_membership(
    store: &Store,
    workspace_id: EventId,
) -> Result<endpoint_shared::types::EndpointMembershipRow, String> {
    let local = endpoint::commands::local_keypair(store)?
        .ok_or_else(|| "local endpoint is missing".to_string())?;
    let key = endpoint_shared::schema::endpoint_membership_key(local.endpoint, workspace_id);
    let value = store
        .table_row(endpoint_shared::schema::ENDPOINT_MEMBERSHIPS, &key)
        .map_err(|err| format!("load endpoint membership: {err}"))?
        .ok_or_else(|| "local endpoint is not joined to workspace".to_string())?;
    endpoint_shared::schema::decode_endpoint_membership_row(&key, &value)
}

fn active_local_recipient_keys(
    store: &Store,
    workspace_id: EventId,
    endpoint_shared_id: EventId,
) -> Result<Vec<RetiredRecipientKey>, String> {
    let local_keys = local_recipient_key::schema::list_for_workspace(store, workspace_id)?;
    let mut active = Vec::new();
    for row in recipient_key::schema::list_for_workspace(store, workspace_id)? {
        if row.endpoint_shared_id != endpoint_shared_id {
            continue;
        }
        let Some(local) = local_keys
            .iter()
            .find(|candidate| candidate.recipient_key == row.recipient_key)
        else {
            continue;
        };
        if recipient_key_tombstone::schema::get(store, workspace_id, row.recipient_key_id)?
            .is_some()
        {
            continue;
        }
        active.push(RetiredRecipientKey {
            recipient_key_id: row.recipient_key_id,
            local_recipient_key_id: local.local_recipient_key_id,
        });
    }
    Ok(active)
}

fn purge_retired_recipient_material(
    store: &Store,
    workspace_id: EventId,
    retired: &[RetiredRecipientKey],
) -> Result<(), String> {
    if retired.is_empty() {
        return Ok(());
    }
    // Collect the wraps to retire outside the write transaction so the cleanup
    // tx only does writes. Wrap row keys are prefixed by `workspace_id`, so a
    // single workspace scan finds every wrap addressed to a retired recipient.
    let workspace_wraps = key_wrap::schema::list_for_workspace(store, workspace_id)?;
    let mut wraps_to_purge = Vec::new();
    for wrap in workspace_wraps {
        if retired
            .iter()
            .any(|key| key.recipient_key_id == wrap.recipient_key_id)
        {
            wraps_to_purge.push(wrap);
        }
    }

    let local_recipient_keys: Vec<Vec<u8>> = retired
        .iter()
        .map(|key| {
            local_recipient_key::schema::local_recipient_key_key(
                workspace_id,
                key.local_recipient_key_id,
            )
        })
        .collect();
    let key_wrap_row_keys: Vec<Vec<u8>> = wraps_to_purge
        .iter()
        .map(|wrap| {
            key_wrap::schema::key_wrap_key(
                wrap.workspace_id,
                wrap.removal_frontier_id,
                wrap.recipient_key_id,
            )
        })
        .collect();
    let event_ids_to_purge: Vec<EventId> = retired
        .iter()
        .flat_map(|key| [key.recipient_key_id, key.local_recipient_key_id])
        .chain(wraps_to_purge.iter().map(|wrap| wrap.key_wrap_id))
        .collect();

    store
        .write_transaction(move |store| {
            store.delete_table_rows_in_tx(
                local_recipient_key::schema::LOCAL_RECIPIENT_KEYS,
                local_recipient_keys,
            )?;
            store.delete_table_rows_in_tx(key_wrap::schema::KEY_WRAPS, key_wrap_row_keys)?;
            for event_id in &event_ids_to_purge {
                purging::purge_event_storage_in_tx(store, event_id)?;
            }
            Ok(())
        })
        .map_err(|err| format!("purge retired recipient material tx: {err}"))
}

fn source_secret_material(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    source_secret_id: EventId,
) -> Result<[u8; 32], String> {
    let bytes = event_schema::event_bytes(store, &source_secret_id)
        .map_err(|err| format!("load source event: {err}"))?
        .ok_or_else(|| "history node source event is missing".to_string())?;
    match bytes.first().copied() {
        Some(local_key_secret::codec::TYPE_LOCAL_KEY_SECRET) => {
            let event = local_key_secret::codec::decode(&bytes)?;
            if event.workspace_id != workspace_id
                || event.removal_frontier_id != removal_frontier_id
            {
                return Err("history node source workspace or frontier mismatch".to_string());
            }
            let row = local_key_secret::schema::get(store, workspace_id, removal_frontier_id)?
                .ok_or_else(|| "history node source key secret is not applied".to_string())?;
            if row.local_key_secret_id != source_secret_id {
                return Err("history node source key secret id mismatch".to_string());
            }
            Ok(row.key_secret)
        }
        Some(local_history_node_secret::codec::TYPE_LOCAL_HISTORY_NODE_SECRET) => {
            let event = local_history_node_secret::codec::decode(&bytes)?;
            if event.workspace_id != workspace_id
                || event.removal_frontier_id != removal_frontier_id
            {
                return Err("history node source workspace or frontier mismatch".to_string());
            }
            let row = local_history_node_secret::schema::get(
                store,
                workspace_id,
                removal_frontier_id,
                event.range_start,
                event.range_width,
                event.event_id_in_minute,
            )?
            .ok_or_else(|| "history node source has been tombstoned".to_string())?;
            if row.local_history_node_secret_id != source_secret_id {
                return Err("history node source id mismatch".to_string());
            }
            Ok(row.node_secret)
        }
        _ => Err("history node source event is not key material".to_string()),
    }
}

fn next_timestamp(store: &Store) -> Result<u64, String> {
    let max_timestamp =
        event_schema::max_timestamp(store).map_err(|err| format!("load max timestamp: {err}"))?;
    logical_clock::next_timestamp(store, max_timestamp)
}

fn key_wrap_event_from_row(row: &key_wrap::types::KeyWrapRow) -> key_wrap::types::KeyWrapEvent {
    key_wrap::types::KeyWrapEvent {
        workspace_id: row.workspace_id,
        created_at_ms: row.created_at_ms,
        removal_frontier_id: row.removal_frontier_id,
        local_key_secret_id: row.local_key_secret_id,
        recipient_key_id: row.recipient_key_id,
        sender_wrap_public_key: row.sender_wrap_public_key,
        nonce: row.nonce,
        ciphertext: row.ciphertext,
    }
}

#[cfg(test)]
mod tests {
    use crate::core::crypto::{self as core_crypto, Ed25519PrivateKey};
    use crate::protocol::event_modules::encryption::removal_frontier;
    use crate::protocol::event_modules::types::{event_id, EventStatus};
    use crate::protocol::Protocol;
    use crate::workers::pipeline_helpers::event_lifecycle;

    use super::*;

    const WORKSPACE: EventId = [1; 32];
    const KEY_SECRET: [u8; 32] = [7; 32];

    /// Build a real signed `removal_frontier` event so dependency context
    /// loading can decode it. Signature verification is real (`decode_signed`
    /// runs ed25519 verify); we sign with a fresh Ed25519 keypair purely to
    /// satisfy decode. The frontier itself is never re-projected here, so the
    /// authority/admin chain remains stubbed to fixed bytes.
    fn build_signed_frontier_record(
        signer_private_key: &Ed25519PrivateKey,
    ) -> crate::protocol::event_modules::types::EventRecord {
        let payload =
            removal_frontier::codec::encode(&removal_frontier::types::RemovalFrontierEvent {
                workspace_id: WORKSPACE,
                created_at_ms: 1,
                authority_admin_id: [9; 32],
                removal_event_ids: Vec::new(),
            })
            .expect("encode frontier");
        let envelope = removal_frontier::codec::sign([8; 32], signer_private_key, payload);
        let bytes = removal_frontier::codec::encode_signed(&envelope);
        removal_frontier::codec::signed_record_from_bytes(bytes).expect("signed record")
    }

    fn seed_local_key_secret(store: &Store) -> (EventId, EventId) {
        let signer_private_key = core_crypto::random_ed25519_private_key();
        let frontier_record = build_signed_frontier_record(&signer_private_key);
        let frontier_id = event_id(&frontier_record.canonical_bytes);

        let output =
            local_key_secret::commands::from_key_secret(WORKSPACE, frontier_id, KEY_SECRET)
                .expect("local key secret");
        let local_key_secret_id = output.value.local_key_secret_id;
        let record = output.events[0].record().clone();
        // Local key secret events normally arrive through the common worker
        // after their frontier dependency is applied. This worker test only
        // exercises history-node derivation, so it short-circuits the prior
        // identity/admin/frontier chain by seeding the frontier event itself
        // as `Applied` (with real signed bytes so dependency context loading
        // can decode it) and the local key secret as `Applied` with its
        // projection row.
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
        (frontier_id, local_key_secret_id)
    }

    #[test]
    fn derive_history_node_purges_retired_event_bytes_after_tombstone() {
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let (frontier_id, local_key_secret_id) = seed_local_key_secret(&store);

        // Derive the parent (root) path node from the seeded local key secret.
        let parent = run(
            &store,
            &protocol,
            Work::DeriveHistoryNode {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                source_secret_id: local_key_secret_id,
                range_start: 0,
                range_width: 8,
                event_id_in_minute: None,
                tombstone_node_id: None,
            },
        )
        .expect("derive parent node");
        let Output::DerivedHistoryNode(parent_report) = parent else {
            panic!("unexpected worker output");
        };
        let parent_id = parent_report
            .local_history_node_secret_id
            .expect("parent id");
        assert_eq!(parent_report.purged_event_bytes, 0);

        // Verify the parent's plaintext node_secret is still on disk before the
        // tombstone child is admitted, so the test exercises the actual
        // forward-secrecy pressure point.
        let pre_purge_bytes = event_schema::event_bytes(&store, &parent_id)
            .expect("parent bytes")
            .expect("parent event present");
        let parent_event =
            local_history_node_secret::codec::decode(&pre_purge_bytes).expect("decode parent");
        assert_ne!(parent_event.node_secret, [0; 32]);
        assert!(
            pre_purge_bytes
                .windows(parent_event.node_secret.len())
                .any(|window| window == parent_event.node_secret),
            "parent canonical bytes must contain the plaintext node secret",
        );

        // Derive the right-half child that retires the parent.
        let child = run(
            &store,
            &protocol,
            Work::DeriveHistoryNode {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                source_secret_id: parent_id,
                range_start: 4,
                range_width: 4,
                event_id_in_minute: None,
                tombstone_node_id: Some(parent_id),
            },
        )
        .expect("derive child node");
        let Output::DerivedHistoryNode(child_report) = child else {
            panic!("unexpected worker output");
        };
        let child_id = child_report.local_history_node_secret_id.expect("child id");
        assert_eq!(child_report.tombstoned_node_id, Some(parent_id));
        assert_eq!(child_report.purged_event_bytes, 1);

        // Retired parent event bytes are gone; the child event remains.
        assert!(
            event_schema::event_bytes(&store, &parent_id)
                .expect("parent bytes lookup")
                .is_none(),
            "retired parent event bytes must be purged",
        );
        assert!(
            event_schema::event_bytes(&store, &child_id)
                .expect("child bytes lookup")
                .is_some(),
            "child event must remain as the durable record of supersession",
        );

        // Projection rows reflect the supersession.
        assert!(
            local_history_node_secret::schema::get(&store, WORKSPACE, frontier_id, 0, 8, None)
                .expect("parent row")
                .is_none(),
            "retired parent projection row must be deleted",
        );
        assert!(
            local_history_node_secret::schema::get(&store, WORKSPACE, frontier_id, 4, 4, None)
                .expect("child row")
                .is_some(),
            "child projection row must exist",
        );
    }

    #[test]
    fn derive_history_node_without_tombstone_does_not_purge() {
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let (frontier_id, local_key_secret_id) = seed_local_key_secret(&store);

        let report = run(
            &store,
            &protocol,
            Work::DeriveHistoryNode {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                source_secret_id: local_key_secret_id,
                range_start: 0,
                range_width: 8,
                event_id_in_minute: None,
                tombstone_node_id: None,
            },
        )
        .expect("derive without tombstone");
        let Output::DerivedHistoryNode(report) = report else {
            panic!("unexpected worker output");
        };
        assert_eq!(report.purged_event_bytes, 0);
        assert_eq!(report.tombstoned_node_id, None);
        // The seeded local_key_secret event bytes stay; only retired
        // history node bytes would ever be purged here.
        assert!(event_schema::event_bytes(&store, &local_key_secret_id)
            .expect("seeded event bytes")
            .is_some(),);
    }

    #[test]
    fn derive_message_leaf_is_idempotent_and_returns_leaf_node_secret() {
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let (frontier_id, _local_key_secret_id) = seed_local_key_secret(&store);
        let leaf_nonce = [99; 32];

        let first = run(
            &store,
            &protocol,
            Work::DeriveMessageLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: 17,
                leaf_nonce,
            },
        )
        .expect("first derive");
        let Output::DerivedMessageLeaf(first) = first else {
            panic!("unexpected output");
        };
        let leaf_id = first
            .local_history_node_secret_id
            .expect("first call must produce leaf id");
        assert!(first.leaf_node_secret.is_some());
        // First call writes both minute_node and leaf events.
        assert!(first.admitted_events >= 2);

        // A second derive for the same tuple returns the same leaf id and
        // does not re-admit; the row lookup short-circuits derivation.
        let second = run(
            &store,
            &protocol,
            Work::DeriveMessageLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: 17,
                leaf_nonce,
            },
        )
        .expect("second derive");
        let Output::DerivedMessageLeaf(second) = second else {
            panic!("unexpected output");
        };
        assert_eq!(second.local_history_node_secret_id, Some(leaf_id));
        assert_eq!(second.leaf_node_secret, first.leaf_node_secret);
        assert_eq!(second.admitted_events, 0, "second call must be idempotent");
    }

    #[test]
    fn derive_message_leaf_shares_minute_node_across_messages_in_same_minute() {
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let (frontier_id, _local_key_secret_id) = seed_local_key_secret(&store);
        let nonce_a = [11; 32];
        let nonce_b = [22; 32];

        let _first = run(
            &store,
            &protocol,
            Work::DeriveMessageLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: 12_345,
                leaf_nonce: nonce_a,
            },
        )
        .expect("first derive");

        let second = run(
            &store,
            &protocol,
            Work::DeriveMessageLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: 12_500,
                leaf_nonce: nonce_b,
            },
        )
        .expect("second derive");
        let Output::DerivedMessageLeaf(second) = second else {
            panic!("unexpected output");
        };
        // Only the new leaf is admitted; the minute_node already exists.
        assert_eq!(second.admitted_events, 1);
    }

    #[test]
    fn retire_deleted_message_leaf_purges_only_the_leaf() {
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let (frontier_id, _local_key_secret_id) = seed_local_key_secret(&store);
        let leaf_nonce = [55; 32];

        let derived = run(
            &store,
            &protocol,
            Work::DeriveMessageLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: 60_000, // unix_minute = 1
                leaf_nonce,
            },
        )
        .expect("derive");
        let Output::DerivedMessageLeaf(derived) = derived else {
            panic!("unexpected output");
        };
        let leaf_id = derived.local_history_node_secret_id.expect("leaf id");

        // Look up the minute_node id so the test can assert it survives.
        let unix_minute =
            crate::protocol::event_modules::content::message::types::unix_minute_for(60_000);
        let minute_row = local_history_node_secret::schema::get(
            &store,
            WORKSPACE,
            frontier_id,
            unix_minute,
            1,
            None,
        )
        .expect("minute row")
        .expect("minute must exist after derive");
        let minute_id = minute_row.local_history_node_secret_id;

        assert!(event_schema::event_bytes(&store, &leaf_id)
            .expect("leaf bytes")
            .is_some());
        assert!(event_schema::event_bytes(&store, &minute_id)
            .expect("minute bytes")
            .is_some());

        let retired = run(
            &store,
            &protocol,
            Work::RetireDeletedMessageLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: 60_000,
                leaf_nonce,
            },
        )
        .expect("retire");
        let Output::RetiredDeletedMessageLeaf(retired) = retired else {
            panic!("unexpected output");
        };
        assert_eq!(retired.leaf_id, Some(leaf_id));
        assert_eq!(retired.purged_event_bytes, 1);

        assert!(event_schema::event_bytes(&store, &leaf_id)
            .expect("leaf bytes after retire")
            .is_none());
        // The minute_node and its canonical bytes survive.
        assert!(event_schema::event_bytes(&store, &minute_id)
            .expect("minute bytes after retire")
            .is_some());
        assert!(local_history_node_secret::schema::get(
            &store,
            WORKSPACE,
            frontier_id,
            unix_minute,
            1,
            None,
        )
        .expect("minute row after retire")
        .is_some());
        // The leaf's projection row is gone.
        assert!(local_history_node_secret::schema::get_leaf(
            &store,
            WORKSPACE,
            frontier_id,
            unix_minute,
            leaf_nonce,
        )
        .expect("leaf row after retire")
        .is_none());
    }
}

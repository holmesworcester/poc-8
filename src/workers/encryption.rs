//! Encryption worker.
//!
//! Projection records shared key-wrap facts; this worker performs the bounded
//! active step that can follow from those facts. It opens wraps only when the
//! matching local recipient private material is present, then admits the
//! resulting local key-secret event through the common event worker.
//!
//! History-node derivation is the worker's other responsibility, but the
//! algorithmic work — KDF descent, ancestor lookup, leaf/sibling materialization
//! — lives in `local_history_node_secret::{schema,commands}`. This worker is
//! a thin coordinator: look up the closest ancestor, hand it to the right
//! command, admit the emitted records.

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

use local_history_node_secret::types::TRIE_LEAF_BIT_DEPTH;
#[cfg(test)]
use local_history_node_secret::types::bit_at;

pub const TIME_TREE_ROOT_WIDTH: u64 =
    local_history_node_secret::commands::ROOT_TIME_TREE_WIDTH;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    DeriveKeySecrets {
        batch_size: usize,
    },
    RotateRecipientKey {
        workspace_id: EventId,
    },
    /// Idempotently derive (or look up) the per-event leaf for one
    /// `(workspace_id, removal_frontier_id, created_at_ms, event_id_in_minute)`
    /// tuple. Senders call this before authoring an event so the canonical
    /// event can name the leaf id; receivers call it after admission blocks
    /// on the named leaf so dependency unblock can let the event project.
    /// `event_id_in_minute` is the deterministic 32-byte coordinate computed
    /// by the event-type's `event_id_in_minute_derived()`.
    DeriveEventLeaf {
        workspace_id: EventId,
        removal_frontier_id: EventId,
        created_at_ms: u64,
        event_id_in_minute: EventId,
    },
    /// Retire one deleted event's per-event leaf by walking the tree from the
    /// closest retained ancestor down to the leaf, materializing splits at
    /// every level so siblings retain implicit cover, then purging the leaf
    /// row and canonical bytes.
    RetireDeletedEventLeaf {
        workspace_id: EventId,
        removal_frontier_id: EventId,
        created_at_ms: u64,
        event_id_in_minute: EventId,
    },
    /// Scan a bounded batch of admitted message, reaction, and file events
    /// and derive their per-event leaves. This is the receiver-side wiring.
    DrainPendingMessageLeaves {
        batch_size: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    DerivedKeySecrets(DeriveReport),
    RotatedRecipientKey(RotateRecipientKeyReport),
    DerivedEventLeaf(DeriveEventLeafReport),
    RetiredDeletedEventLeaf(RetireDeletedEventLeafReport),
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
pub struct DeriveEventLeafReport {
    pub local_history_node_secret_id: Option<EventId>,
    pub leaf_node_secret: Option<crate::core::crypto::XChaCha20Poly1305Key>,
    pub admitted_events: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetireDeletedEventLeafReport {
    pub leaf_id: Option<EventId>,
    pub admitted_events: usize,
    pub purged_event_bytes: usize,
    pub materialized_internal_rows: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RetiredRecipientKey {
    recipient_key_id: EventId,
    local_recipient_key_id: EventId,
}

pub fn run<R: EventRegistry>(store: &Store, registry: &R, work: Work) -> Result<Output, String> {
    match work {
        Work::DeriveKeySecrets { batch_size } => {
            derive_key_secrets(store, registry, batch_size).map(Output::DerivedKeySecrets)
        }
        Work::RotateRecipientKey { workspace_id } => {
            rotate_recipient_key(store, registry, workspace_id).map(Output::RotatedRecipientKey)
        }
        Work::DeriveEventLeaf {
            workspace_id,
            removal_frontier_id,
            created_at_ms,
            event_id_in_minute,
        } => derive_event_leaf(
            store,
            registry,
            workspace_id,
            removal_frontier_id,
            created_at_ms,
            event_id_in_minute,
        )
        .map(Output::DerivedEventLeaf),
        Work::RetireDeletedEventLeaf {
            workspace_id,
            removal_frontier_id,
            created_at_ms,
            event_id_in_minute,
        } => retire_deleted_event_leaf(
            store,
            registry,
            workspace_id,
            removal_frontier_id,
            created_at_ms,
            event_id_in_minute,
        )
        .map(Output::RetiredDeletedEventLeaf),
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

    purge_retired_recipient_material(store, workspace_id, &retired)
        .map_err(|err| format!("purge retired recipient material: {err}"))?;

    Ok(report)
}

/// Find the closest ancestor for `(unix_minute, event_id_in_minute)` and
/// hand it to `commands::derive_leaf_from_ancestor`. The command emits one
/// or many records depending on the ancestor shape; admission inserts them
/// in dependency order. The returned leaf id and secret come from the
/// command output.
fn derive_event_leaf<R: EventRegistry>(
    store: &Store,
    registry: &R,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    created_at_ms: u64,
    event_id_in_minute: EventId,
) -> Result<DeriveEventLeafReport, String> {
    if event_id_in_minute.iter().all(|byte| *byte == 0) {
        return Err("derive_event_leaf requires non-zero event_id_in_minute".to_string());
    }
    let unix_minute =
        crate::protocol::event_modules::content::message::types::unix_minute_for(created_at_ms);

    if let Some(existing) = local_history_node_secret::schema::get_leaf(
        store,
        workspace_id,
        removal_frontier_id,
        unix_minute,
        event_id_in_minute,
    )? {
        return Ok(DeriveEventLeafReport {
            local_history_node_secret_id: Some(existing.local_history_node_secret_id),
            leaf_node_secret: Some(existing.node_secret),
            admitted_events: 0,
        });
    }

    let ancestor = local_history_node_secret::schema::closest_ancestor(
        store,
        workspace_id,
        removal_frontier_id,
        unix_minute,
        event_id_in_minute,
        false,
    )?;
    let output = local_history_node_secret::commands::derive_leaf_from_ancestor(
        local_history_node_secret::commands::DeriveLeafFromAncestor {
            workspace_id,
            removal_frontier_id,
            ancestor,
            unix_minute,
            event_id_in_minute,
        },
    )?;
    let leaf_id = output.value.leaf_id;
    let leaf_secret = output.value.leaf_secret;
    let admitted = worker::run(
        store,
        registry,
        worker::AdmitAndDrain {
            output,
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("admit local history node secret leaf: {err}"))?;

    Ok(DeriveEventLeafReport {
        local_history_node_secret_id: Some(leaf_id),
        leaf_node_secret: Some(leaf_secret),
        admitted_events: admitted.admitted.inserted_events,
    })
}

/// Retire one event's leaf by handing the closest non-leaf ancestor and the
/// surviving leaf coordinates in this minute to
/// `commands::retire_leaf_from_ancestor`. After admission, exact-delete the
/// leaf row and purge its canonical bytes.
///
/// TODO(disappearing-messages): whole-minute retirement is a separate
/// future flow. The time-tree shape supports it: walk the time tree, split
/// as needed so the expired range is covered by a small set of internal
/// nodes, then tombstone those internals (one tombstone per covering node,
/// not one per minute). The current implementation only handles per-event
/// leaf retirement; whole-minute (or whole-range) retirement will land
/// later behind a separate `Work` variant.
fn retire_deleted_event_leaf<R: EventRegistry>(
    store: &Store,
    registry: &R,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    created_at_ms: u64,
    event_id_in_minute: EventId,
) -> Result<RetireDeletedEventLeafReport, String> {
    let unix_minute =
        crate::protocol::event_modules::content::message::types::unix_minute_for(created_at_ms);
    let Some(leaf_row) = local_history_node_secret::schema::get_leaf(
        store,
        workspace_id,
        removal_frontier_id,
        unix_minute,
        event_id_in_minute,
    )?
    else {
        return Ok(RetireDeletedEventLeafReport::default());
    };
    let leaf_id = leaf_row.local_history_node_secret_id;
    let mut report = RetireDeletedEventLeafReport {
        leaf_id: Some(leaf_id),
        ..RetireDeletedEventLeafReport::default()
    };

    let ancestor = local_history_node_secret::schema::closest_ancestor(
        store,
        workspace_id,
        removal_frontier_id,
        unix_minute,
        event_id_in_minute,
        true,
    )?;
    let survivor_coords: Vec<EventId> =
        local_history_node_secret::schema::list_leaves_in_minute(
            store,
            workspace_id,
            removal_frontier_id,
            unix_minute,
        )?
        .into_iter()
        .filter(|row| row.event_id_prefix != event_id_in_minute)
        .map(|row| row.event_id_prefix)
        .collect();

    let output = local_history_node_secret::commands::retire_leaf_from_ancestor(
        local_history_node_secret::commands::RetireLeafFromAncestor {
            workspace_id,
            removal_frontier_id,
            ancestor,
            unix_minute,
            event_id_in_minute,
            survivor_coords,
        },
    )?;
    let admitted = worker::run(
        store,
        registry,
        worker::AdmitAndDrain {
            output,
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("admit retire records: {err}"))?;
    report.admitted_events += admitted.admitted.inserted_events;

    // Purge the leaf canonical bytes and exact-delete the leaf row.
    let purged = store
        .write_transaction(|store| purging::purge_event_storage_in_tx(store, &leaf_id))
        .map_err(|err| format!("purge deleted event leaf bytes: {err}"))?;
    if purged {
        report.purged_event_bytes += 1;
    }
    store
        .delete_table_rows(
            local_history_node_secret::schema::LOCAL_HISTORY_NODE_SECRETS,
            vec![local_history_node_secret::schema::local_history_node_secret_key(
                workspace_id,
                removal_frontier_id,
                unix_minute,
                1,
                TRIE_LEAF_BIT_DEPTH,
                event_id_in_minute,
            )],
        )
        .map_err(|err| format!("delete leaf projection row: {err}"))?;
    Ok(report)
}

fn drain_pending_message_leaves<R: EventRegistry>(
    store: &Store,
    registry: &R,
    batch_size: usize,
) -> Result<DrainPendingLeavesReport, String> {
    use crate::protocol::event_modules::content::{file, message, reaction};

    let mut report = DrainPendingLeavesReport::default();
    let blocked_pairs = store
        .table_rows_with_key_prefix(event_schema::BLOCKED_EVENTS_BY_MISSING_DEP, &[], batch_size)
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
        let (workspace_id, removal_frontier_id, created_at_ms, leaf_id, event_id_in_minute) =
            match bytes.first().copied() {
                Some(message::codec::TYPE_SIGNED_MESSAGE) => {
                    let envelope = match message::codec::decode_signed(&bytes) {
                        Ok(envelope) => envelope,
                        Err(_) => continue,
                    };
                    let event = match message::codec::decode(&envelope.payload) {
                        Ok(event) => event,
                        Err(_) => continue,
                    };
                    let coord = event.event_id_in_minute_derived();
                    (
                        event.workspace_id,
                        event.removal_frontier_id,
                        event.created_at_ms,
                        event.local_history_node_secret_id,
                        coord,
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
                    let coord = event.event_id_in_minute_derived();
                    (
                        event.workspace_id,
                        event.removal_frontier_id,
                        event.created_at_ms,
                        event.local_history_node_secret_id,
                        coord,
                    )
                }
                Some(file::codec::TYPE_SIGNED_FILE) => {
                    let envelope = match file::codec::decode_signed(&bytes) {
                        Ok(envelope) => envelope,
                        Err(_) => continue,
                    };
                    let event = match file::codec::decode(&envelope.payload) {
                        Ok(event) => event,
                        Err(_) => continue,
                    };
                    let coord = event.event_id_in_minute_derived();
                    (
                        event.workspace_id,
                        event.removal_frontier_id,
                        event.created_at_ms,
                        event.local_history_node_secret_id,
                        coord,
                    )
                }
                _ => continue,
            };
        report.scanned_events += 1;
        if local_key_secret::schema::get(store, workspace_id, removal_frontier_id)?.is_none() {
            continue;
        }
        if event_schema::has_event(store, &leaf_id)
            .map_err(|err| format!("look up leaf event: {err}"))?
        {
            continue;
        }
        let derived = derive_event_leaf(
            store,
            registry,
            workspace_id,
            removal_frontier_id,
            created_at_ms,
            event_id_in_minute,
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
    fn derive_event_leaf_is_idempotent_and_returns_leaf_node_secret() {
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let (frontier_id, _local_key_secret_id) = seed_local_key_secret(&store);
        let event_id_in_minute = [99; 32];

        let first = run(
            &store,
            &protocol,
            Work::DeriveEventLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: 17,
                event_id_in_minute,
            },
        )
        .expect("first derive");
        let Output::DerivedEventLeaf(first) = first else {
            panic!("unexpected output");
        };
        let leaf_id = first
            .local_history_node_secret_id
            .expect("first call must produce leaf id");
        assert!(first.leaf_node_secret.is_some());
        assert!(first.admitted_events >= 1);

        let second = run(
            &store,
            &protocol,
            Work::DeriveEventLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: 17,
                event_id_in_minute,
            },
        )
        .expect("second derive");
        let Output::DerivedEventLeaf(second) = second else {
            panic!("unexpected output");
        };
        assert_eq!(second.local_history_node_secret_id, Some(leaf_id));
        assert_eq!(second.leaf_node_secret, first.leaf_node_secret);
        assert_eq!(second.admitted_events, 0, "second call must be idempotent");
    }

    #[test]
    fn derive_event_leaf_reaches_same_secret_via_root_walk() {
        // Walking from the workspace root through ~63 time-tree splits and
        // one trie split must reproduce the same leaf secret as a direct
        // BLAKE3 keyed-hash derivation. This is the "O(280) hashes" property.
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let (frontier_id, _local_key_secret_id) = seed_local_key_secret(&store);
        let event_id_in_minute = [0xab; 32];
        let created_at_ms: u64 = 7 * 60_000;

        let report = run(
            &store,
            &protocol,
            Work::DeriveEventLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms,
                event_id_in_minute,
            },
        )
        .expect("derive");
        let Output::DerivedEventLeaf(report) = report else {
            panic!("unexpected");
        };
        let leaf_secret = report.leaf_node_secret.expect("leaf secret");

        // Replay the chain directly from the workspace key secret. The KDF
        // info layout matches `local_history_node_secret::commands::*_split_info_bytes`.
        let mut current_secret = KEY_SECRET;
        let mut current_start = 0u64;
        let mut current_width = TIME_TREE_ROOT_WIDTH;
        let target_minute = created_at_ms / 60_000;
        while current_width > 1 {
            let half = current_width / 2;
            let mid = current_start + half;
            let (child_side, child_start) = if target_minute < mid {
                (0u8, current_start)
            } else {
                (1u8, mid)
            };
            let mut info = Vec::with_capacity(8 + 8 + 1 + 8 + 8);
            info.extend_from_slice(&current_start.to_be_bytes());
            info.extend_from_slice(&current_width.to_be_bytes());
            info.push(child_side);
            info.extend_from_slice(&child_start.to_be_bytes());
            info.extend_from_slice(&half.to_be_bytes());
            current_secret = crypto::blake3_keyed_hash(
                &current_secret,
                local_history_node_secret::commands::TIME_SPLIT_DOMAIN,
                &info,
            );
            current_start = child_start;
            current_width = half;
        }
        let leaf_side = bit_at(&event_id_in_minute, 0);
        let mut info = Vec::with_capacity(2 + 32 + 1 + 2 + 32);
        info.extend_from_slice(&0u16.to_be_bytes()); // parent_bit_depth = 0
        info.extend_from_slice(&[0; 32]); // parent_event_id_prefix masked to depth 0
        info.push(leaf_side);
        info.extend_from_slice(&TRIE_LEAF_BIT_DEPTH.to_be_bytes());
        info.extend_from_slice(&event_id_in_minute);
        let recomputed = crypto::blake3_keyed_hash(
            &current_secret,
            local_history_node_secret::commands::TRIE_SPLIT_DOMAIN,
            &info,
        );
        assert_eq!(recomputed, leaf_secret);
    }

    #[test]
    fn sparse_delete_materializes_log_n_internals_not_n_leaves() {
        // Author N events in the same minute as fresh leaves (no internals
        // materialized), then retire ONE. The materialized rows after
        // retire must scale with O(log #minutes + log #events_in_minute),
        // not with N. With TIME_TREE_ROOT_WIDTH = 2^63, the time-tree
        // contribution is O(64). The trie contribution should be O(log N).
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let (frontier_id, _) = seed_local_key_secret(&store);
        const N: usize = 16;
        let coords: Vec<EventId> = (0u8..N as u8).map(|byte| [byte ^ 0xa5; 32]).collect();
        for coord in &coords {
            let _ = run(
                &store,
                &protocol,
                Work::DeriveEventLeaf {
                    workspace_id: WORKSPACE,
                    removal_frontier_id: frontier_id,
                    created_at_ms: 60_000,
                    event_id_in_minute: *coord,
                },
            )
            .expect("derive leaf");
        }
        let pre_rows = local_history_node_secret::schema::list_for_workspace(&store, WORKSPACE)
            .expect("pre rows");
        assert_eq!(pre_rows.len(), N, "every fresh send admits exactly one leaf row");
        for row in &pre_rows {
            assert!(
                local_history_node_secret::types::is_leaf_row(row),
                "every pre-delete row must be a leaf",
            );
        }

        // Retire the first leaf.
        let report = run(
            &store,
            &protocol,
            Work::RetireDeletedEventLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: 60_000,
                event_id_in_minute: coords[0],
            },
        )
        .expect("retire");
        let Output::RetiredDeletedEventLeaf(report) = report else {
            panic!("unexpected output");
        };
        assert_eq!(report.purged_event_bytes, 1);

        let post_rows = local_history_node_secret::schema::list_for_workspace(&store, WORKSPACE)
            .expect("post rows");
        let leaf_count = post_rows
            .iter()
            .filter(|row| local_history_node_secret::types::is_leaf_row(row))
            .count();
        assert_eq!(
            leaf_count,
            N - 1,
            "exactly one leaf retired; surviving leaf rows persist",
        );
        // Time-tree internals + minute_node + sibling time-tree internals
        // are bounded by O(log range_width). With ROOT_WIDTH = 2^63, that
        // is at most ~125 rows even for a maximally-deep walk. Trie
        // internals scale with O(log N) ~ log2(16) = 4 unique divergence
        // depths, each producing 2 internals (descend + sibling) = 8
        // trie rows. Bound the total at 200 to be conservative; what
        // matters is that it does NOT scale with N (so increasing N
        // would not blow this up).
        let internal_row_count = post_rows.len() - leaf_count;
        let time_tree_bound = 2 * 64 + 4; // 64 levels * 2 children + slack
        let trie_bound = 2 * (N as f64).log2().ceil() as usize + 4;
        assert!(
            internal_row_count <= time_tree_bound + trie_bound,
            "internal row count {internal_row_count} must be O(log range + log N), bound {}",
            time_tree_bound + trie_bound,
        );

        // Assert the deleted leaf cannot be looked up.
        assert!(
            local_history_node_secret::schema::get_leaf(
                &store,
                WORKSPACE,
                frontier_id,
                60_000 / 60_000,
                coords[0],
            )
            .expect("lookup")
            .is_none(),
            "deleted leaf row must be gone",
        );
    }

    #[test]
    fn delete_does_not_materialize_adjacent_minute_node_rows() {
        // Spec invariant: deleting an event in minute M must NOT materialize
        // the adjacent minute_nodes at (M-1, 1) or (M+1, 1). They stay
        // implicit under the materialized time-tree internal at width=2.
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let (frontier_id, _) = seed_local_key_secret(&store);
        let coord_a = [0xaa; 32];
        let coord_b = [0xbb; 32];
        // Two events in minute 100 so retire has a surviving sibling to
        // cover.
        for coord in [coord_a, coord_b] {
            let _ = run(
                &store,
                &protocol,
                Work::DeriveEventLeaf {
                    workspace_id: WORKSPACE,
                    removal_frontier_id: frontier_id,
                    created_at_ms: 100 * 60_000,
                    event_id_in_minute: coord,
                },
            )
            .expect("derive leaf");
        }
        let _ = run(
            &store,
            &protocol,
            Work::RetireDeletedEventLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: 100 * 60_000,
                event_id_in_minute: coord_a,
            },
        )
        .expect("retire");

        let rows = local_history_node_secret::schema::list_for_workspace(&store, WORKSPACE)
            .expect("rows");
        // Adjacent minute_nodes (range_width=1, bit_depth=0) at minute 99 or 101
        // must not exist.
        for adjacent in [99u64, 101u64] {
            assert!(
                local_history_node_secret::schema::get_minute_node(
                    &store,
                    WORKSPACE,
                    frontier_id,
                    adjacent,
                )
                .expect("lookup")
                .is_none(),
                "minute_node at adjacent minute {adjacent} must NOT be materialized",
            );
        }
        // Sanity: minute_node at M=100 IS materialized.
        assert!(
            local_history_node_secret::schema::get_minute_node(
                &store,
                WORKSPACE,
                frontier_id,
                100,
            )
            .expect("lookup")
            .is_some(),
            "minute_node at M=100 must be materialized after delete",
        );
        let _ = rows;
    }

    #[test]
    fn cover_summary_after_sparse_delete_is_logarithmic() {
        // The cover_summary length is O(materialized_rows) by construction
        // (each row contributes COVER_SUMMARY_ROW_LEN bytes). After
        // deleting 1 of N events in a minute, the materialized row count
        // is bounded by O(log range_width + log N), so cover_summary
        // length stays bounded too.
        use local_history_node_secret::schema::{cover_summary, COVER_SUMMARY_ROW_LEN};
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let (frontier_id, _) = seed_local_key_secret(&store);
        const N: usize = 32;
        let coords: Vec<EventId> = (0u8..N as u8).map(|byte| [byte ^ 0x77; 32]).collect();
        for coord in &coords {
            let _ = run(
                &store,
                &protocol,
                Work::DeriveEventLeaf {
                    workspace_id: WORKSPACE,
                    removal_frontier_id: frontier_id,
                    created_at_ms: 60_000,
                    event_id_in_minute: *coord,
                },
            )
            .expect("derive leaf");
        }
        let _ = run(
            &store,
            &protocol,
            Work::RetireDeletedEventLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: 60_000,
                event_id_in_minute: coords[0],
            },
        )
        .expect("retire");

        let summary = cover_summary(&store, WORKSPACE).expect("cover_summary");
        let header_len = b"topo cover summary v3".len() + 4;
        let row_count = (summary.len() - header_len) / COVER_SUMMARY_ROW_LEN;
        assert_eq!(
            (summary.len() - header_len) % COVER_SUMMARY_ROW_LEN,
            0,
            "cover_summary row encoding length must be {COVER_SUMMARY_ROW_LEN} bytes",
        );
        // Surviving leaves (N-1) plus log-bounded internals.
        let log_n = (N as f64).log2().ceil() as usize;
        let bound = (N - 1) + 2 * 64 + 4 + 2 * log_n + 4;
        assert!(
            row_count <= bound,
            "cover_summary row count {row_count} must be O(N + log range + log N), bound {bound}",
        );

        // Determinism: a second compute returns the same bytes.
        let again = cover_summary(&store, WORKSPACE).expect("cover_summary again");
        assert_eq!(summary, again);
    }
}

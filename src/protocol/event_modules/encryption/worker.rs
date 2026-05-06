//! Encryption worker.
//!
//! Projection records shared key-wrap facts; this worker performs the bounded
//! active step that can follow from those facts. It opens wraps only when the
//! matching local recipient private material is present, then admits the
//! resulting local key-secret event through the common event worker.

use crate::core::crypto;
use crate::core::store::Store;
use crate::protocol::clock;
use crate::protocol::event_modules::identity::{endpoint, endpoint_shared};
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::{self, EventRegistry};

use super::{
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
        tombstone_node_id: Option<EventId>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    DerivedKeySecrets(DeriveReport),
    RotatedRecipientKey(RotateRecipientKeyReport),
    DerivedHistoryNode(DeriveHistoryNodeReport),
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HistoryNodeJob {
    workspace_id: EventId,
    removal_frontier_id: EventId,
    source_secret_id: EventId,
    range_start: u64,
    range_width: u64,
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
                tombstone_node_id,
            },
        )
        .map(Output::DerivedHistoryNode),
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

    for old_key in old_active {
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
    }

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
    Ok(DeriveHistoryNodeReport {
        local_history_node_secret_id: Some(local_history_node_secret_id),
        tombstoned_node_id: job.tombstone_node_id,
        admitted_events: admitted.admitted.inserted_events,
    })
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
) -> Result<Vec<recipient_key::types::RecipientKeyRow>, String> {
    let local_keys = local_recipient_key::schema::list_for_workspace(store, workspace_id)?;
    let mut active = Vec::new();
    for row in recipient_key::schema::list_for_workspace(store, workspace_id)? {
        if row.endpoint_shared_id != endpoint_shared_id {
            continue;
        }
        if !local_keys
            .iter()
            .any(|candidate| candidate.recipient_key == row.recipient_key)
        {
            continue;
        }
        if recipient_key_tombstone::schema::get(store, workspace_id, row.recipient_key_id)?
            .is_some()
        {
            continue;
        }
        active.push(row);
    }
    Ok(active)
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
    clock::next_timestamp(store, max_timestamp)
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

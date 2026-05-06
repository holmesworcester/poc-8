//! Encryption worker.
//!
//! Projection records shared key-wrap facts; this worker performs the bounded
//! active step that can follow from those facts. It opens wraps only when the
//! matching local recipient private material is present, then admits the
//! resulting local key-secret event through the common event worker.

use crate::core::crypto;
use crate::core::store::Store;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::{self, EventRegistry};

use super::{key_wrap, local_key_secret, local_recipient_key, recipient_key};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    DeriveKeySecrets { batch_size: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    DerivedKeySecrets(DeriveReport),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeriveReport {
    pub scanned_key_wraps: usize,
    pub derived_key_secrets: usize,
    pub failed_key_wraps: usize,
    pub admitted_events: usize,
}

pub fn run<R: EventRegistry>(store: &Store, registry: &R, work: Work) -> Result<Output, String> {
    match work {
        Work::DeriveKeySecrets { batch_size } => {
            derive_key_secrets(store, registry, batch_size).map(Output::DerivedKeySecrets)
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

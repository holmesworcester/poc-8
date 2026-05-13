//! Read-only views over invite-accepted rows.
//!
//! Scope: counts and per-endpoint enumeration for the identity CLI.
//! Mutations to `INVITES_ACCEPTED` happen in the projector when the
//! local endpoint accepts an invite; queries here only read.

use crate::core::store::Store;
use crate::protocol::event_modules::identity::endpoint::types::EndpointId;
use crate::protocol::event_modules::types::EventId;

use super::schema::{decode_invite_accepted_row, INVITES_ACCEPTED};

pub fn invite_accepted_count(store: &Store) -> Result<usize, String> {
    store
        .table_row_count(INVITES_ACCEPTED)
        .map_err(|err| format!("count invite_accepted rows: {err}"))
}

pub fn accepted_workspace_ids(
    store: &Store,
    accepted_endpoint_id: EndpointId,
) -> Result<Vec<EventId>, String> {
    store
        .table_rows_with_key_prefix(INVITES_ACCEPTED, &accepted_endpoint_id, usize::MAX)
        .map_err(|err| format!("load accepted invites: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_invite_accepted_row(&key, &value).map(|row| row.workspace_id))
        .collect()
}

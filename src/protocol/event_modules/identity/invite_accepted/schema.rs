//! Schema and rows for local invite acceptance.
//!
//! `identity.invites_accepted` is a durable local read model. It is not synced,
//! and it is not evidence that the shared invite row was valid or that membership
//! completed. It says this endpoint accepted a link naming a workspace/invite and
//! that replay can find the scoped local invite-secret event used by connection
//! bootstrap.

use crate::core::store::{Schema, Store, TableName, TableRow};
use crate::protocol::event_modules::identity::endpoint::types::EndpointId;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::{Reader, Writer};

use super::types::{InviteAcceptedEvent, InviteAcceptedRow};

pub const INVITES_ACCEPTED: TableName = TableName::new("identity.invites_accepted");

pub const SCHEMAS: &[Schema] = &[Schema::durable_row_table(
    "identity.invites_accepted.v1",
    INVITES_ACCEPTED,
)];

pub fn invite_accepted_key(
    accepted_endpoint_id: EndpointId,
    workspace_id: EventId,
    invite_event_id: EventId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(96);
    key.extend_from_slice(&accepted_endpoint_id);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&invite_event_id);
    key
}

pub fn invite_accepted_row(
    invite_accepted_event_id: EventId,
    event: &InviteAcceptedEvent,
) -> TableRow {
    TableRow {
        table: INVITES_ACCEPTED,
        key: invite_accepted_key(
            event.accepted_endpoint_id,
            event.workspace_id,
            event.invite_event_id,
        ),
        value: encode_invite_accepted_value(invite_accepted_event_id, event),
    }
}

pub fn decode_invite_accepted_row(key: &[u8], value: &[u8]) -> Result<InviteAcceptedRow, String> {
    if key.len() != 96 {
        return Err("invite_accepted row key is malformed".to_string());
    }
    let mut accepted_endpoint_id = [0; 32];
    accepted_endpoint_id.copy_from_slice(&key[..32]);
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[32..64]);
    let mut invite_event_id = [0; 32];
    invite_event_id.copy_from_slice(&key[64..96]);

    let mut reader = Reader::new(value, "invite_accepted row");
    let invite_accepted_event_id = reader.id()?;
    let invite_secret_event_id = reader.id()?;
    let bootstrap_hash = reader.id()?;
    reader.finish()?;
    Ok(InviteAcceptedRow {
        accepted_endpoint_id,
        workspace_id,
        invite_event_id,
        invite_accepted_event_id,
        invite_secret_event_id,
        bootstrap_hash,
    })
}

/// Per-endpoint accepted-workspace list.
///
/// This view is duplicated in `queries.rs` for CLI/reporting callers
/// but stays here for the connection transit projector, which the
/// boundary rule excludes from the projector-pure constraint but still
/// forbids from calling `queries::` directly.
pub fn accepted_workspace_ids(
    store: &Store,
    accepted_endpoint_id: crate::protocol::event_modules::identity::endpoint::types::EndpointId,
) -> Result<Vec<EventId>, String> {
    store
        .table_rows_with_key_prefix(INVITES_ACCEPTED, &accepted_endpoint_id, usize::MAX)
        .map_err(|err| format!("load accepted invites: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_invite_accepted_row(&key, &value).map(|row| row.workspace_id))
        .collect()
}

fn encode_invite_accepted_value(
    invite_accepted_event_id: EventId,
    event: &InviteAcceptedEvent,
) -> Vec<u8> {
    let mut out = Writer::with_capacity(96);
    out.id(&invite_accepted_event_id);
    out.id(&event.invite_secret_event_id);
    out.id(&event.bootstrap_hash);
    out.finish()
}

#[cfg(test)]
mod tests {
    use crate::core::store::Store;

    use super::*;

    fn event() -> InviteAcceptedEvent {
        InviteAcceptedEvent {
            workspace_id: [1; 32],
            invite_event_id: [2; 32],
            invite_secret_event_id: [3; 32],
            bootstrap_hash: [4; 32],
            accepted_endpoint_id: [5; 32],
        }
    }

    /// Invariant: invite acceptance rows decode to the exact local provenance
    /// tuple needed to replay the accepted endpoint/workspace/invite binding.
    #[test]
    fn invite_accepted_row_decodes_to_projected_shape() {
        let row = invite_accepted_row([9; 32], &event());

        assert_eq!(row.table, INVITES_ACCEPTED);
        assert_eq!(row.key, invite_accepted_key([5; 32], [1; 32], [2; 32]));
        assert_eq!(
            decode_invite_accepted_row(&row.key, &row.value).expect("decode row"),
            InviteAcceptedRow {
                accepted_endpoint_id: [5; 32],
                workspace_id: [1; 32],
                invite_event_id: [2; 32],
                invite_accepted_event_id: [9; 32],
                invite_secret_event_id: [3; 32],
                bootstrap_hash: [4; 32],
            }
        );
    }

    /// Invariant: replaying the same local acceptance event is idempotent at the
    /// read-model row boundary.
    #[test]
    fn duplicate_invite_accepted_row_insert_is_idempotent() {
        let row = invite_accepted_row([9; 32], &event());
        let store = Store::open_memory_with_schemas(SCHEMAS).expect("open store");

        assert_eq!(
            store
                .insert_table_rows(vec![row.clone()])
                .expect("insert row"),
            1
        );
        assert_eq!(
            store
                .insert_table_rows(vec![row])
                .expect("insert duplicate"),
            0
        );
    }
}

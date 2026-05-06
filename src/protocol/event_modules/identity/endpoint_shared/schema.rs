//! Schema and row helpers for endpoint-shared projections.
//!
//! The shared row is keyed by `workspace_id || endpoint_shared_id`. The
//! membership row is keyed by `endpoint_id || workspace_id` so command preflight
//! can reject joining the same workspace twice from one endpoint.

use crate::core::store::{Schema, Store, TableName, TableRow};
use crate::protocol::event_modules::identity::endpoint::types::EndpointId;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::{Reader, Writer};
use std::collections::HashSet;

use super::codec;
use super::types::{EndpointMembershipRow, EndpointSharedEvent, EndpointSharedRow};

pub const ENDPOINT_SHARED: TableName = TableName::new("identity.endpoint_shared");
pub const ENDPOINT_MEMBERSHIPS: TableName = TableName::new("identity.endpoint_memberships");

pub const SCHEMAS: &[Schema] = &[
    Schema::durable_row_table("identity.endpoint_shared.v1", ENDPOINT_SHARED),
    Schema::durable_row_table("identity.endpoint_memberships.v1", ENDPOINT_MEMBERSHIPS),
];

pub fn endpoint_shared_key(workspace_id: EventId, endpoint_shared_id: EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&endpoint_shared_id);
    key
}

pub fn endpoint_membership_key(endpoint_id: EndpointId, workspace_id: EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&endpoint_id);
    key.extend_from_slice(&workspace_id);
    key
}

impl super::commands::EndpointMembershipRead for Store {
    fn endpoint_membership(
        &self,
        endpoint_id: EndpointId,
        workspace_id: EventId,
    ) -> Result<Option<Vec<u8>>, String> {
        self.table_row(
            ENDPOINT_MEMBERSHIPS,
            &endpoint_membership_key(endpoint_id, workspace_id),
        )
        .map_err(|err| format!("load endpoint membership: {err}"))
    }
}

pub fn endpoint_shared_rows(
    endpoint_shared_id: EventId,
    device_invite_id: EventId,
    event: &EndpointSharedEvent,
) -> Result<Vec<TableRow>, String> {
    Ok(vec![
        endpoint_shared_row(endpoint_shared_id, device_invite_id, event)?,
        endpoint_membership_row(endpoint_shared_id, device_invite_id, event),
    ])
}

pub fn endpoint_shared_row(
    endpoint_shared_id: EventId,
    device_invite_id: EventId,
    event: &EndpointSharedEvent,
) -> Result<TableRow, String> {
    Ok(TableRow {
        table: ENDPOINT_SHARED,
        key: endpoint_shared_key(event.workspace_id, endpoint_shared_id),
        value: encode_endpoint_shared_value(device_invite_id, event)?,
    })
}

pub fn endpoint_membership_row(
    endpoint_shared_id: EventId,
    device_invite_id: EventId,
    event: &EndpointSharedEvent,
) -> TableRow {
    TableRow {
        table: ENDPOINT_MEMBERSHIPS,
        key: endpoint_membership_key(event.endpoint_id, event.workspace_id),
        value: encode_endpoint_membership_value(endpoint_shared_id, device_invite_id, event),
    }
}

pub fn decode_endpoint_shared_row(key: &[u8], value: &[u8]) -> Result<EndpointSharedRow, String> {
    if key.len() != 64 {
        return Err("endpoint shared row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut endpoint_shared_id = [0; 32];
    endpoint_shared_id.copy_from_slice(&key[32..64]);

    let mut reader = Reader::new(value, "endpoint shared row");
    let created_at_ms = reader.u64()?;
    let endpoint_id = reader.id()?;
    let signing_public_key = reader.id()?;
    let user_authority_event_id = reader.id()?;
    let device_invite_id = reader.id()?;
    let device_name =
        codec::decode_device_name(reader.slice(super::types::ENDPOINT_DEVICE_NAME_BYTES)?)?;
    reader.finish()?;

    Ok(EndpointSharedRow {
        workspace_id,
        endpoint_shared_id,
        created_at_ms,
        endpoint_id,
        signing_public_key,
        user_authority_event_id,
        device_invite_id,
        device_name,
    })
}

pub fn decode_endpoint_membership_row(
    key: &[u8],
    value: &[u8],
) -> Result<EndpointMembershipRow, String> {
    if key.len() != 64 {
        return Err("endpoint membership row key is malformed".to_string());
    }
    let mut endpoint_id = [0; 32];
    endpoint_id.copy_from_slice(&key[..32]);
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[32..64]);

    let mut reader = Reader::new(value, "endpoint membership row");
    let endpoint_shared_id = reader.id()?;
    let user_authority_event_id = reader.id()?;
    let device_invite_id = reader.id()?;
    let signing_public_key = reader.id()?;
    let created_at_ms = reader.u64()?;
    reader.finish()?;

    Ok(EndpointMembershipRow {
        endpoint_id,
        workspace_id,
        endpoint_shared_id,
        user_authority_event_id,
        device_invite_id,
        signing_public_key,
        created_at_ms,
    })
}

pub fn workspace_ids_for_endpoint(
    store: &Store,
    endpoint_id: EndpointId,
) -> Result<Vec<EventId>, String> {
    store
        .table_rows_with_key_prefix(ENDPOINT_MEMBERSHIPS, &endpoint_id, usize::MAX)
        .map_err(|err| format!("load endpoint memberships: {err}"))?
        .into_iter()
        .map(|(key, value)| {
            decode_endpoint_membership_row(&key, &value).map(|row| row.workspace_id)
        })
        .collect()
}

pub fn mutual_workspace_ids(
    store: &Store,
    local_endpoint: EndpointId,
    remote_endpoint: EndpointId,
) -> Result<Vec<EventId>, String> {
    let remote = workspace_ids_for_endpoint(store, remote_endpoint)?
        .into_iter()
        .collect::<HashSet<_>>();
    let mut workspaces = workspace_ids_for_endpoint(store, local_endpoint)?
        .into_iter()
        .filter(|workspace_id| remote.contains(workspace_id))
        .collect::<Vec<_>>();
    workspaces.sort();
    workspaces.dedup();
    Ok(workspaces)
}

fn encode_endpoint_shared_value(
    device_invite_id: EventId,
    event: &EndpointSharedEvent,
) -> Result<Vec<u8>, String> {
    let device_name = codec::encode_device_name(&event.device_name)?;
    let mut out =
        Writer::with_capacity(8 + 32 + 32 + 32 + 32 + super::types::ENDPOINT_DEVICE_NAME_BYTES);
    out.u64(event.created_at_ms);
    out.id(&event.endpoint_id);
    out.id(&event.signing_public_key);
    out.id(&event.user_authority_event_id);
    out.id(&device_invite_id);
    out.raw(&device_name);
    Ok(out.finish())
}

fn encode_endpoint_membership_value(
    endpoint_shared_id: EventId,
    device_invite_id: EventId,
    event: &EndpointSharedEvent,
) -> Vec<u8> {
    let mut out = Writer::with_capacity(32 + 32 + 32 + 32 + 8);
    out.id(&endpoint_shared_id);
    out.id(&event.user_authority_event_id);
    out.id(&device_invite_id);
    out.id(&event.signing_public_key);
    out.u64(event.created_at_ms);
    out.finish()
}

#[cfg(test)]
mod tests {
    use crate::core::store::Store;

    use super::*;

    fn event() -> EndpointSharedEvent {
        EndpointSharedEvent {
            created_at_ms: 77,
            workspace_id: [1; 32],
            user_authority_event_id: [2; 32],
            endpoint_id: [3; 32],
            signing_public_key: [6; 32],
            device_name: "phone".to_string(),
        }
    }

    // Invariant: endpoint shared rows decode to projected shapes.
    #[test]
    fn endpoint_shared_rows_decode_to_projected_shapes() {
        let rows = endpoint_shared_rows([4; 32], [5; 32], &event()).expect("rows");

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].table, ENDPOINT_SHARED);
        assert_eq!(rows[0].key, endpoint_shared_key([1; 32], [4; 32]));
        assert_eq!(rows[1].table, ENDPOINT_MEMBERSHIPS);
        assert_eq!(rows[1].key, endpoint_membership_key([3; 32], [1; 32]));

        assert_eq!(
            decode_endpoint_shared_row(&rows[0].key, &rows[0].value).expect("decode shared"),
            EndpointSharedRow {
                workspace_id: [1; 32],
                endpoint_shared_id: [4; 32],
                created_at_ms: 77,
                endpoint_id: [3; 32],
                signing_public_key: [6; 32],
                user_authority_event_id: [2; 32],
                device_invite_id: [5; 32],
                device_name: "phone".to_string(),
            }
        );
        assert_eq!(
            decode_endpoint_membership_row(&rows[1].key, &rows[1].value)
                .expect("decode membership"),
            EndpointMembershipRow {
                endpoint_id: [3; 32],
                workspace_id: [1; 32],
                endpoint_shared_id: [4; 32],
                user_authority_event_id: [2; 32],
                device_invite_id: [5; 32],
                signing_public_key: [6; 32],
                created_at_ms: 77,
            }
        );
    }

    // Invariant: duplicate membership insert is idempotent.
    #[test]
    fn duplicate_membership_insert_is_idempotent() {
        let rows = endpoint_shared_rows([4; 32], [5; 32], &event()).expect("rows");
        let store = Store::open_memory_with_schemas(SCHEMAS).expect("open store");

        assert_eq!(
            store
                .insert_table_rows(vec![rows[1].clone()])
                .expect("insert membership"),
            1
        );
        assert_eq!(
            store
                .insert_table_rows(vec![rows[1].clone()])
                .expect("insert duplicate membership"),
            0
        );
    }

    // Invariant: duplicate membership with different join fact rejects.
    #[test]
    fn duplicate_membership_with_different_join_fact_rejects() {
        let first = endpoint_shared_rows([4; 32], [5; 32], &event()).expect("first rows");
        let second = endpoint_shared_rows([44; 32], [55; 32], &event()).expect("second rows");
        let store = Store::open_memory_with_schemas(SCHEMAS).expect("open store");

        assert_eq!(
            store
                .insert_table_rows(vec![first[1].clone()])
                .expect("insert membership"),
            1
        );
        let err = store
            .insert_table_rows(vec![second[1].clone()])
            .expect_err("conflicting duplicate membership must reject");

        assert!(
            err.to_string()
                .contains("conflicting row for identity.endpoint_memberships"),
            "{err}"
        );
    }
}

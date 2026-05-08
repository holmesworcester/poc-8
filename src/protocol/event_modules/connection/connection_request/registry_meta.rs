//! Registry-facing admission helpers for connection requests.
//!
//! The protocol registry owns cross-domain transit admission policy. This helper
//! keeps the request lookup beside the request codec so root `mod.rs` can stay a
//! shallow dispatcher.

use crate::core::store::Store;
use crate::protocol::event_modules::identity::{endpoint::types::EndpointId, invite};
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::types::{event_id, EventId, EventRecord};

use super::{codec, types as request_types};
use crate::protocol::event_modules::connection::{schema, types};

pub(crate) fn invite_authorizes_shared_event(
    store: &Store,
    record: &EventRecord,
    local_endpoint: EndpointId,
    sender_endpoint: EndpointId,
    connection_id: types::ConnectionId,
) -> Result<bool, String> {
    let Some(workspace_id) = record.workspace_id else {
        return Ok(false);
    };
    let Some(request) = invite_connection_request(store, connection_id)? else {
        return Ok(false);
    };
    let endpoints_match = (request.from_endpoint == local_endpoint
        && request.to_endpoint == sender_endpoint)
        || (request.from_endpoint == sender_endpoint && request.to_endpoint == local_endpoint);
    if !endpoints_match {
        return Ok(false);
    }
    let Some(bootstrap_hash) =
        invite_secret_bootstrap_hash(store, &request.invite_secret_event_id, workspace_id)?
    else {
        return Ok(false);
    };
    if request.bootstrap_hash != bootstrap_hash {
        return Ok(false);
    }
    Ok(true)
}

fn invite_connection_request(
    store: &Store,
    connection_id: types::ConnectionId,
) -> Result<Option<request_types::RequestEvent>, String> {
    let rows = store
        .table_rows_with_key_prefix(schema::CONNECTION_EVENTS, &[], usize::MAX)
        .map_err(|err| format!("load connection events: {err}"))?;
    for (_, bytes) in rows {
        if !codec::is_request(&bytes) {
            continue;
        }
        let request = codec::decode(&bytes)?;
        let request_id = event_id(&bytes);
        if types::connection_id(&request_id, &request.to_endpoint) == connection_id {
            return Ok(Some(request));
        }
    }
    Ok(None)
}

fn invite_secret_bootstrap_hash(
    store: &Store,
    invite_secret_event_id: &EventId,
    workspace_id: EventId,
) -> Result<Option<EventId>, String> {
    let Some(bytes) = event_schema::event_bytes(store, invite_secret_event_id)
        .map_err(|err| format!("load invite secret event: {err}"))?
    else {
        return Ok(None);
    };
    let invite_secret = invite::codec::decode(&bytes)
        .map_err(|_| "connection invite dependency is not an invite secret event".to_string())?;
    if invite_secret.workspace_id != Some(workspace_id) || invite_secret.invite_event_id.is_none() {
        return Ok(None);
    }
    Ok(Some(invite_secret.bootstrap_hash))
}

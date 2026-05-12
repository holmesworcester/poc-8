//! Connection worker.
//!
//! Inputs: projected `connection.pending_connection_attempts` and
//! `connection.pending_connection_responses`.
//! State: local endpoint key material, connection request/response bytes, invite
//! secret dependencies, and current request-to-connection mappings.
//! Step: retry outbound requests to invite addresses, create/send responses for
//! validated inbound requests, and retire queue rows once the corresponding
//! connection work is complete.
//! Outputs: opaque TCP frames through `transit_out` and ordinary connection
//! response events through the shared event pipeline.
//! Consume: pending attempt rows remain until a connection response projects;
//! pending response rows remain until the response frame is sent.
//! Failure: route failures may be returned or counted according to the caller's
//! policy. Pending rows remain so later daemon turns can retry.

use std::{
    net::SocketAddr,
    str::FromStr,
    thread,
    time::{Duration, Instant},
};

use crate::core::daemon::{StepContext, Worker};
use crate::core::store::Store;
use crate::protocol::event_modules::connection::{
    connection_ephemeral_secret, connection_request, connection_response, schema, transit, types,
};
use crate::protocol::event_modules::identity::{endpoint, invite};
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::types::EventId;
use crate::workers::pipeline_helpers::event_pipeline::{self as pipeline, EventRegistry};
use crate::workers::{transit_out, DaemonWorkerContext};

const PENDING_CONNECTION_LIMIT: usize = 64;
const READY_BATCH: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingConnectionAttempt {
    request_id: EventId,
    addr: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingConnectionResponse {
    request_id: EventId,
    addr: SocketAddr,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnectionReport {
    pub attempts_sent: usize,
    pub attempts_completed: usize,
    pub responses_sent: usize,
    pub failed_attempts: usize,
    pub failed_responses: usize,
    pub sent_events: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    Drain {
        fail_on_route_error: bool,
    },
    DrainUntilConnected {
        request_id: EventId,
        timeout: Duration,
        fail_on_route_error: bool,
    },
}

pub fn run<R>(store: &Store, registry: &R, work: Work) -> Result<ConnectionReport, String>
where
    R: EventRegistry,
{
    match work {
        Work::Drain {
            fail_on_route_error,
        } => drain_connection_work(store, registry, fail_on_route_error),
        Work::DrainUntilConnected {
            request_id,
            timeout,
            fail_on_route_error,
        } => drain_until_connected(store, registry, request_id, timeout, fail_on_route_error),
    }
}

pub(crate) fn daemon_worker<C>() -> Worker<C>
where
    C: DaemonWorkerContext,
{
    Worker {
        name: "connection",
        run: daemon_step::<C>,
    }
}

fn daemon_step<C>(ctx: &mut StepContext<'_, C>) -> Result<(), String>
where
    C: DaemonWorkerContext,
{
    let app = &*ctx.app;
    let report = run(
        app.store(),
        app,
        Work::Drain {
            fail_on_route_error: false,
        },
    )?;
    ctx.report.add("connection_attempts", report.attempts_sent);
    ctx.report
        .add("connection_responses", report.responses_sent);
    ctx.report
        .add("connection_attempts_completed", report.attempts_completed);
    ctx.report
        .add("connection_failed_attempts", report.failed_attempts);
    ctx.report
        .add("connection_failed_responses", report.failed_responses);
    ctx.report.add("connection_sent_events", report.sent_events);
    Ok(())
}

fn drain_connection_work<R>(
    store: &Store,
    registry: &R,
    fail_on_route_error: bool,
) -> Result<ConnectionReport, String>
where
    R: EventRegistry,
{
    let mut report = ConnectionReport::default();
    drain_pending_responses(store, registry, fail_on_route_error, &mut report)?;
    drain_pending_attempts(store, fail_on_route_error, &mut report)?;
    Ok(report)
}

fn drain_until_connected<R>(
    store: &Store,
    registry: &R,
    request_id: EventId,
    timeout: Duration,
    fail_on_route_error: bool,
) -> Result<ConnectionReport, String>
where
    R: EventRegistry,
{
    let start = Instant::now();
    let mut total = ConnectionReport::default();
    while start.elapsed() < timeout {
        let report = drain_connection_work(store, registry, fail_on_route_error)?;
        merge_report(&mut total, report);
        if connection_id_for_request(store, request_id)?.is_some() {
            return Ok(total);
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err("pending connection request did not produce a connection".to_string())
}

fn merge_report(total: &mut ConnectionReport, next: ConnectionReport) {
    total.attempts_sent += next.attempts_sent;
    total.attempts_completed += next.attempts_completed;
    total.responses_sent += next.responses_sent;
    total.failed_attempts += next.failed_attempts;
    total.failed_responses += next.failed_responses;
    total.sent_events += next.sent_events;
}

fn drain_pending_attempts(
    store: &Store,
    fail_on_route_error: bool,
    report: &mut ConnectionReport,
) -> Result<(), String> {
    for attempt in pending_connection_attempts(store, PENDING_CONNECTION_LIMIT)? {
        if let Some(connection_id) = connection_id_for_request(store, attempt.request_id)? {
            remember_connection_route(store, connection_id, attempt.addr)?;
            delete_pending_connection_attempt(store, attempt.request_id)?;
            report.attempts_completed += 1;
            continue;
        }
        let frame = match connection_request_frame(store, attempt) {
            Ok(frame) => frame,
            Err(err) if fail_on_route_error => {
                return Err(format!(
                    "prepare pending connection request {:?}: {err}",
                    attempt.addr
                ));
            }
            Err(_) => {
                report.failed_attempts += 1;
                continue;
            }
        };
        match transit_out::send_frames(store, attempt.addr, vec![frame]) {
            Ok(send) => {
                report.attempts_sent += 1;
                report.sent_events += send.sent_events;
            }
            Err(err) if fail_on_route_error => {
                return Err(format!(
                    "sync pending connection request {:?}: {err}",
                    attempt.addr
                ));
            }
            Err(_) => {
                report.failed_attempts += 1;
            }
        }
    }
    Ok(())
}

fn drain_pending_responses<R>(
    store: &Store,
    registry: &R,
    fail_on_route_error: bool,
    report: &mut ConnectionReport,
) -> Result<(), String>
where
    R: EventRegistry,
{
    for response in pending_connection_responses(store, PENDING_CONNECTION_LIMIT)? {
        let frame = match connection_response_frame(store, registry, response.request_id) {
            Ok(frame) => frame,
            Err(err) if fail_on_route_error => {
                return Err(format!(
                    "prepare pending connection response {:?}: {err}",
                    response.addr
                ));
            }
            Err(_) => {
                report.failed_responses += 1;
                continue;
            }
        };
        match transit_out::send_frames(store, response.addr, vec![frame]) {
            Ok(send) => {
                delete_pending_connection_response(store, response.request_id)?;
                report.responses_sent += 1;
                report.sent_events += send.sent_events;
            }
            Err(err) if fail_on_route_error => {
                return Err(format!(
                    "send pending connection response {:?}: {err}",
                    response.addr
                ));
            }
            Err(_) => {
                report.failed_responses += 1;
            }
        }
    }
    Ok(())
}

fn connection_request_frame(
    store: &Store,
    attempt: PendingConnectionAttempt,
) -> Result<Vec<u8>, String> {
    let request_bytes = connection_event_bytes(store, attempt.request_id)?;
    let request = connection_request::codec::decode(&request_bytes)
        .map_err(|_| "pending connection attempt is not a request event".to_string())?;
    let local = local_endpoint(store)?;
    if local.endpoint != request.from_endpoint {
        return Err("pending connection request sender is not the local endpoint".to_string());
    }
    transit::commands::create_bootstrap(&local, request.to_endpoint, &request_bytes)
}

fn connection_response_frame<R>(
    store: &Store,
    registry: &R,
    request_id: EventId,
) -> Result<Vec<u8>, String>
where
    R: EventRegistry,
{
    if let Some(connection_id) = connection_id_for_request(store, request_id)? {
        return existing_connection_response_frame(store, request_id, connection_id);
    }
    let request = connection_request_for_response(store, request_id)?
        .ok_or_else(|| "missing connection request event".to_string())?;
    let invite_secret = invite_secret_for_response(store, &request.invite_secret_event_id)?;
    let output = connection_response::commands::create_for_request(
        connection_response::commands::CreateForRequest {
            local: local_endpoint(store)?,
            request_id,
            request: &request,
            invite_secret: &invite_secret,
        },
    )?;
    let frame = output.value.bytes.clone();
    pipeline::run(store, registry, output)
        .map_err(|err| format!("record connection response: {err}"))?;
    pipeline::run(
        store,
        registry,
        pipeline::DrainUntilIdle {
            batch_size: READY_BATCH,
        },
    )?;
    Ok(frame)
}

fn existing_connection_response_frame(
    store: &Store,
    request_id: EventId,
    connection_id: types::ConnectionId,
) -> Result<Vec<u8>, String> {
    let response_bytes = connection_event_bytes(store, connection_id)?;
    let response = connection_response::codec::decode(&response_bytes)
        .map_err(|_| "stored connection event is not a response".to_string())?;
    let request = connection_request_for_response(store, request_id)?
        .ok_or_else(|| "missing connection request event".to_string())?;
    let invite_secret = invite_secret_for_response(store, &request.invite_secret_event_id)?;
    let responder_ephemeral =
        responder_ephemeral_for_response(store, &response.responder_ephemeral_secret_event_id)?;
    let local = local_endpoint(store)?;
    if response.from_endpoint != local.endpoint {
        return Err("stored connection response sender is not the local endpoint".to_string());
    }
    let material = connection_response::commands::responder_material(
        request_id,
        &request,
        &invite_secret,
        &local.secret,
        &responder_ephemeral.ephemeral_private_key,
        &response.responder_ephemeral_public_key,
    )?;
    if response.handshake_hash != material.handshake_hash {
        return Err("stored connection response handshake hash does not match".to_string());
    }
    if response.connection_secret != material.connection_secret {
        return Err("stored connection response secret does not match".to_string());
    }
    transit::commands::create_connection_handshake_response(
        local.endpoint,
        request.from_endpoint,
        request_id,
        response.responder_ephemeral_public_key,
        &material.response_key,
        &response_bytes,
    )
}

fn local_endpoint(store: &Store) -> Result<endpoint::types::EndpointKeypair, String> {
    endpoint::commands::local_keypair(store)?.ok_or_else(|| "local endpoint is missing".to_string())
}

fn connection_request_for_response(
    store: &Store,
    request_id: EventId,
) -> Result<Option<connection_request::types::RequestEvent>, String> {
    let Some(bytes) = event_schema::event_bytes(store, &request_id)
        .map_err(|err| format!("load connection request event: {err}"))?
        .or_else(|| connection_event_bytes(store, request_id).ok())
    else {
        return Ok(None);
    };
    connection_request::codec::decode(&bytes).map(Some)
}

fn invite_secret_for_response(
    store: &Store,
    invite_secret_event_id: &EventId,
) -> Result<invite::types::InviteSecretEvent, String> {
    let bytes = event_schema::event_bytes(store, invite_secret_event_id)
        .map_err(|err| format!("load invite secret event: {err}"))?
        .ok_or_else(|| "missing invite secret event".to_string())?;
    invite::codec::decode(&bytes)
        .map_err(|_| "connection dependency is not an invite secret".to_string())
}

fn responder_ephemeral_for_response(
    store: &Store,
    responder_ephemeral_event_id: &EventId,
) -> Result<connection_ephemeral_secret::types::EphemeralSecretEvent, String> {
    let bytes = event_schema::event_bytes(store, responder_ephemeral_event_id)
        .map_err(|err| format!("load responder ephemeral event: {err}"))?
        .ok_or_else(|| "missing responder ephemeral event".to_string())?;
    connection_ephemeral_secret::codec::decode(&bytes)
        .map_err(|_| "connection dependency is not a responder ephemeral".to_string())
}

fn connection_event_bytes(store: &Store, event_id: EventId) -> Result<Vec<u8>, String> {
    store
        .table_row(schema::CONNECTION_EVENTS, &event_id)
        .map_err(|err| format!("load connection event: {err}"))?
        .ok_or_else(|| "unknown connection event".to_string())
}

fn connection_id_for_request(
    store: &Store,
    request_id: EventId,
) -> Result<Option<types::ConnectionId>, String> {
    let Some(bytes) = store
        .table_row(schema::REQUEST_CONNECTIONS, &request_id)
        .map_err(|err| format!("load request connection: {err}"))?
    else {
        return Ok(None);
    };
    types::connection_id_from_bytes(&bytes).map(Some)
}

fn remember_connection_route(
    store: &Store,
    connection_id: types::ConnectionId,
    addr: SocketAddr,
) -> Result<(), String> {
    store
        .insert_table_rows(vec![schema::transport_target_row(connection_id, addr)])
        .map(|_| ())
        .map_err(|err| format!("remember connection route: {err}"))
}

fn pending_connection_attempts(
    store: &Store,
    limit: usize,
) -> Result<Vec<PendingConnectionAttempt>, String> {
    pending_connection_rows(store, schema::PENDING_CONNECTION_ATTEMPTS, limit)?
        .into_iter()
        .map(|(request_id, addr)| Ok(PendingConnectionAttempt { request_id, addr }))
        .collect()
}

fn pending_connection_responses(
    store: &Store,
    limit: usize,
) -> Result<Vec<PendingConnectionResponse>, String> {
    pending_connection_rows(store, schema::PENDING_CONNECTION_RESPONSES, limit)?
        .into_iter()
        .map(|(request_id, addr)| Ok(PendingConnectionResponse { request_id, addr }))
        .collect()
}

fn pending_connection_rows(
    store: &Store,
    table: crate::core::store::TableName,
    limit: usize,
) -> Result<Vec<(EventId, SocketAddr)>, String> {
    let rows = store
        .table_rows_with_key_prefix(table, &[], limit)
        .map_err(|err| format!("load pending connection rows: {err}"))?;
    rows.into_iter()
        .map(|(key, value)| {
            let request_id = event_id_from_bytes(&key)?;
            let text = String::from_utf8(value)
                .map_err(|err| format!("pending connection addr is not utf8: {err}"))?;
            let addr = SocketAddr::from_str(&text)
                .map_err(|err| format!("pending connection addr is invalid: {err}"))?;
            Ok((request_id, addr))
        })
        .collect()
}

fn event_id_from_bytes(bytes: &[u8]) -> Result<EventId, String> {
    bytes
        .try_into()
        .map_err(|_| "event id must be 32 bytes".to_string())
}

fn delete_pending_connection_attempt(store: &Store, request_id: EventId) -> Result<(), String> {
    delete_pending_connection_row(store, schema::PENDING_CONNECTION_ATTEMPTS, request_id)
}

fn delete_pending_connection_response(store: &Store, request_id: EventId) -> Result<(), String> {
    delete_pending_connection_row(store, schema::PENDING_CONNECTION_RESPONSES, request_id)
}

fn delete_pending_connection_row(
    store: &Store,
    table: crate::core::store::TableName,
    request_id: EventId,
) -> Result<(), String> {
    store
        .delete_table_rows(table, vec![request_id.to_vec()])
        .map(|_| ())
        .map_err(|err| format!("delete pending connection row: {err}"))
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::identity::endpoint;
    use crate::protocol::Protocol;

    use super::*;

    #[test]
    fn completed_pending_attempt_becomes_route_and_leaves_queue() {
        let store = Protocol::open_memory_store().expect("open store");
        let local = endpoint::commands::create_local_keypair().value;
        let request_id = [2; 32];
        let connection_id = [3; 32];
        let addr = "127.0.0.1:41000"
            .parse::<SocketAddr>()
            .expect("test socket addr");
        let mut rows = endpoint::projector::local_endpoint(local);
        rows.extend([
            schema::pending_connection_attempt_row(request_id, addr),
            schema::request_connection_row(request_id, connection_id),
        ]);
        store
            .insert_table_rows(rows)
            .expect("insert pending attempt");

        let output = run(
            &store,
            &Protocol::new(),
            Work::Drain {
                fail_on_route_error: true,
            },
        )
        .expect("drain connection work");

        assert_eq!(output.attempts_completed, 1);
        assert_eq!(
            store
                .table_row_count(schema::PENDING_CONNECTION_ATTEMPTS)
                .expect("count pending"),
            0
        );
        assert_eq!(
            store
                .table_row(schema::TRANSPORT_TARGETS, &connection_id)
                .expect("route row"),
            Some(addr.to_string().into_bytes())
        );
    }
}

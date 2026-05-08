//! Event admission worker.
//!
//! Inputs: `canonical.in`.
//! State: durable event rows plus missing-dependency edge indexes.
//! Step: claim up to `limit` canonical records, insert or dedupe each durable
//! event, and decide whether it is ready or blocked.
//! Outputs: `event_modules.ready_events` for ready events and blocker rows for
//! missing dependencies.
//! Consume: accepted and rejected input rows are removed from their input queues;
//! rejected rows are not retried by those queues.
//! Failure: a semantic admission/projection error is returned to the caller
//! after the rejected input row is consumed.
//! Fairness: `Work::Drain { limit }` bounds one call.

use crate::core::daemon::{StepContext, Worker};
use crate::core::network_queues::InboundNetworkRow;
use crate::core::store::Store;
use crate::protocol::event_modules::connection::{
    connection_request, connection_response, types as connection_types,
};
use crate::protocol::event_modules::identity::{self, endpoint::types::EndpointId, invite};
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::sync;
use crate::protocol::event_modules::types::{EventId, EventRecord, ReceiveMetadata};
use crate::workers::pipeline_helpers::event_pipeline::{
    self as pipeline, AdmitReport, EventRegistry, EventWithContext, ProjectionOutput,
    ReceivedRecord,
};
use crate::workers::{schema as worker_schema, DaemonWorkerContext};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    Drain { limit: usize },
}

pub fn run<R>(store: &Store, registry: &R, work: Work) -> Result<AdmitReport, String>
where
    R: EventRegistry,
{
    match work {
        Work::Drain { limit } => {
            let admission = transit_admission_registry(registry);
            pipeline::drain_canonical_in(store, &admission, limit)
        }
    }
}

pub(crate) fn transit_admission_registry<R>(registry: &R) -> TransitAdmissionRegistry<'_, R> {
    TransitAdmissionRegistry { inner: registry }
}

pub(crate) struct TransitAdmissionRegistry<'a, R> {
    inner: &'a R,
}

impl<R> EventRegistry for TransitAdmissionRegistry<'_, R>
where
    R: EventRegistry,
{
    fn record_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        self.inner.record_from_bytes(bytes)
    }

    fn project_network_in(
        &self,
        store: &Store,
        inbound: &InboundNetworkRow,
    ) -> Result<ProjectionOutput, String> {
        self.inner.project_network_in(store, inbound)
    }

    fn record_from_canonical_in(
        &self,
        store: &Store,
        bytes: Vec<u8>,
        receive: Option<ReceiveMetadata>,
        provenance: Option<worker_schema::TransitProvenance>,
    ) -> Result<ReceivedRecord, String> {
        received_record_from_canonical_in(store, self.inner, bytes, receive, provenance)
    }

    fn project_record(
        &self,
        store: &Store,
        event: &EventWithContext<'_>,
    ) -> Result<ProjectionOutput, String> {
        self.inner.project_record(store, event)
    }

    fn post_admission_hook(&self, store: &Store) -> Result<(), String> {
        self.inner.post_admission_hook(store)
    }
}

fn received_record_from_canonical_in<R>(
    store: &Store,
    registry: &R,
    bytes: Vec<u8>,
    receive: Option<ReceiveMetadata>,
    provenance: Option<worker_schema::TransitProvenance>,
) -> Result<ReceivedRecord, String>
where
    R: EventRegistry,
{
    match provenance {
        Some(provenance) => record_from_transit_canonical_in(store, registry, bytes, provenance),
        None => {
            let record = registry.record_from_bytes(bytes)?;
            Ok(match receive {
                Some(receive) => ReceivedRecord::with_receive(record, receive),
                None => ReceivedRecord::new(record),
            })
        }
    }
}

fn record_from_transit_canonical_in<R>(
    store: &Store,
    registry: &R,
    bytes: Vec<u8>,
    provenance: worker_schema::TransitProvenance,
) -> Result<ReceivedRecord, String>
where
    R: EventRegistry,
{
    match provenance.unwrapped_with {
        worker_schema::TransitUnwrap::Bootstrap => {
            if connection_request::codec::is_request(&bytes) {
                let record = connection_request::codec::record_from_bytes(bytes)?;
                return Ok(ReceivedRecord::with_receive(
                    record,
                    ReceiveMetadata::bootstrap_invite(
                        provenance.origin,
                        provenance.local_endpoint,
                        provenance.sender_endpoint,
                        provenance.remember_route,
                    ),
                ));
            }
            if connection_response::codec::is_response(&bytes) {
                let record = connection_response::codec::record_from_bytes(bytes)?;
                return Ok(ReceivedRecord::with_receive(
                    record,
                    ReceiveMetadata::endpoint_receive(
                        provenance.origin,
                        provenance.local_endpoint,
                        provenance.sender_endpoint,
                        provenance.remember_route,
                    ),
                ));
            }
            return Err(
                "endpoint bootstrap transit only carries connection requests or responses"
                    .to_string(),
            );
        }
        worker_schema::TransitUnwrap::InviteBootstrap { workspace_id, .. } => {
            let record = registry.record_from_bytes(bytes)?;
            if !record.scope.is_shared() {
                return Err("invite bootstrap transit only accepts shared events".to_string());
            }
            if record.workspace_id != Some(workspace_id) {
                return Err(
                    "invite bootstrap transit rejected event outside invite workspace".to_string(),
                );
            }
            if !is_identity_bootstrap_event(&record.canonical_bytes)? {
                return Err(
                    "invite bootstrap transit only accepts identity bootstrap events".to_string(),
                );
            }
            return Ok(ReceivedRecord::new(record));
        }
        worker_schema::TransitUnwrap::Connection { connection_id } => {
            if connection_request::codec::is_request(&bytes) {
                return Err("connection transit cannot carry connection requests".to_string());
            }
            if connection_response::codec::is_response(&bytes) {
                return Err("connection transit cannot carry connection responses".to_string());
            }
            if sync::is_connection_scoped_event(&bytes) {
                return sync::inbound_record_from_connection_bytes(connection_id, bytes)
                    .map(ReceivedRecord::new);
            }
        }
    }

    let worker_schema::TransitUnwrap::Connection { connection_id } = provenance.unwrapped_with
    else {
        return Err("transit provenance cannot admit this event".to_string());
    };
    let record = registry.record_from_bytes(bytes)?;
    if !record.scope.is_shared() {
        return Err(
            "connection transit only accepts shared or connection-scoped events".to_string(),
        );
    }
    let workspace_id = record
        .workspace_id
        .ok_or_else(|| "transit shared in requires a workspace".to_string())?;
    let allowed_workspaces = identity::endpoint_shared::schema::mutual_workspace_ids(
        store,
        provenance.local_endpoint,
        provenance.sender_endpoint,
    )?;
    if allowed_workspaces
        .iter()
        .any(|allowed| allowed == &workspace_id)
        || invite_authorizes_shared_event(
            store,
            &record,
            provenance.local_endpoint,
            provenance.sender_endpoint,
            connection_id,
        )?
    {
        Ok(ReceivedRecord::new(record))
    } else {
        Err("transit shared in rejected event outside sender workspace".to_string())
    }
}

pub(crate) fn is_identity_bootstrap_event(bytes: &[u8]) -> Result<bool, String> {
    match bytes.first().copied() {
        Some(identity::workspace::codec::TYPE_WORKSPACE) => Ok(true),
        Some(identity::signed::codec::TYPE_SIGNED) => {
            let envelope = identity::signed::codec::decode(bytes)?;
            Ok(matches!(
                envelope.inner_type,
                identity::admin::codec::TYPE_ADMIN
                    | identity::user_invite::codec::TYPE_USER_INVITE
                    | identity::invite_server::codec::TYPE_INVITE_SERVER
                    | identity::user::codec::TYPE_USER
                    | identity::device_invite::codec::TYPE_DEVICE_INVITE
                    | identity::endpoint_shared::codec::TYPE_ENDPOINT_SHARED
            ))
        }
        _ => Ok(false),
    }
}

fn invite_authorizes_shared_event(
    store: &Store,
    record: &EventRecord,
    local_endpoint: EndpointId,
    sender_endpoint: EndpointId,
    connection_id: connection_types::ConnectionId,
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
    connection_id: connection_types::ConnectionId,
) -> Result<Option<connection_request::types::RequestEvent>, String> {
    let Some(bytes) = connection_response_bytes(store, connection_id)? else {
        return Ok(None);
    };
    let response = connection_response::codec::decode(&bytes)
        .map_err(|_| "connection id does not name a connection event".to_string())?;
    let Some(bytes) = event_schema::event_bytes(store, &response.request_id)
        .map_err(|err| format!("load connection request event: {err}"))?
    else {
        return Ok(None);
    };
    connection_request::codec::decode(&bytes)
        .map(Some)
        .map_err(|_| "connection dependency is not a request event".to_string())
}

fn connection_response_bytes(
    store: &Store,
    connection_id: connection_types::ConnectionId,
) -> Result<Option<Vec<u8>>, String> {
    event_schema::event_bytes(store, &connection_id)
        .map_err(|err| format!("load connection event: {err}"))
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

pub(crate) fn daemon_worker<C>() -> Worker<C>
where
    C: DaemonWorkerContext,
{
    Worker {
        name: "event_admission",
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
            limit: ctx.options.work_limit,
        },
    )
    .map_err(|err| format!("admit canonical in: {err}"))?;
    ctx.report.add("admitted_events", report.inserted_events);
    ctx.report.add("blocked_events", report.blocked_events);
    ctx.report.add("applied_events", report.applied_events);
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::core::store::Store;
    use crate::protocol::event_modules::connection::{
        connection_request, connection_response, types,
    };
    use crate::protocol::event_modules::content::content_event;
    use crate::protocol::event_modules::identity::{endpoint, endpoint_shared, invite, workspace};
    use crate::protocol::event_modules::schema as event_schema;
    use crate::protocol::event_modules::types::{event_id, EventStatus};
    use crate::protocol::Protocol;
    use crate::workers::schema as worker_schema;

    use super::*;

    fn keypair() -> endpoint::types::EndpointKeypair {
        endpoint::commands::create_local_keypair().value
    }

    fn store() -> Store {
        Protocol::open_memory_store().expect("open store")
    }

    fn enqueue_connection_canonical_in(
        store: &Store,
        inner: Vec<u8>,
        local_endpoint: endpoint::types::EndpointId,
        sender_endpoint: endpoint::types::EndpointId,
        connection_id: types::ConnectionId,
    ) {
        store
            .insert_table_rows(vec![worker_schema::transit_canonical_in_row(
                inner,
                worker_schema::TransitProvenance {
                    origin: "127.0.0.1:41001".parse().expect("origin"),
                    local_endpoint,
                    sender_endpoint,
                    remember_route: false,
                    unwrapped_with: worker_schema::TransitUnwrap::Connection { connection_id },
                },
            )])
            .expect("enqueue connection canonical in");
    }

    fn enqueue_bootstrap_canonical_in(
        store: &Store,
        inner: Vec<u8>,
        local_endpoint: endpoint::types::EndpointId,
        sender_endpoint: endpoint::types::EndpointId,
    ) {
        store
            .insert_table_rows(vec![worker_schema::transit_canonical_in_row(
                inner,
                worker_schema::TransitProvenance {
                    origin: "127.0.0.1:41001".parse().expect("origin"),
                    local_endpoint,
                    sender_endpoint,
                    remember_route: false,
                    unwrapped_with: worker_schema::TransitUnwrap::Bootstrap,
                },
            )])
            .expect("enqueue bootstrap canonical in");
    }

    fn enqueue_invite_bootstrap_canonical_in(
        store: &Store,
        inner: Vec<u8>,
        local_endpoint: endpoint::types::EndpointId,
        sender_endpoint: endpoint::types::EndpointId,
        workspace_id: [u8; 32],
        invite_event_id: [u8; 32],
    ) {
        store
            .insert_table_rows(vec![worker_schema::transit_canonical_in_row(
                inner,
                worker_schema::TransitProvenance {
                    origin: "127.0.0.1:41001".parse().expect("origin"),
                    local_endpoint,
                    sender_endpoint,
                    remember_route: false,
                    unwrapped_with: worker_schema::TransitUnwrap::InviteBootstrap {
                        bootstrap_hash: [6; 32],
                        workspace_id,
                        invite_event_id,
                    },
                },
            )])
            .expect("enqueue invite bootstrap canonical in");
    }

    fn add_endpoint_membership(
        store: &Store,
        workspace_id: [u8; 32],
        endpoint_shared_id: [u8; 32],
        endpoint: endpoint::types::EndpointKeypair,
    ) {
        let event = endpoint_shared::types::EndpointSharedEvent {
            created_at_ms: 1,
            workspace_id,
            user_authority_event_id: [44; 32],
            endpoint_id: endpoint.endpoint,
            signing_public_key: endpoint.signing_public_key,
            endpoint_role: endpoint::types::EndpointRole::Device,
            device_name: "test".to_string(),
        };
        store
            .insert_table_rows(vec![endpoint_shared::schema::endpoint_membership_row(
                endpoint_shared_id,
                [45; 32],
                &event,
            )])
            .expect("insert endpoint membership");
    }

    fn add_invite_authorized_connection(
        store: &Store,
        local: endpoint::types::EndpointKeypair,
        remote: endpoint::types::EndpointKeypair,
        workspace_id: [u8; 32],
    ) -> types::ConnectionId {
        let invite_secret =
            invite::types::InviteSecretEvent::scoped([7; 32], workspace_id, [8; 32]);
        let invite_record = invite::codec::record_from_bytes(invite::codec::encode(&invite_secret))
            .expect("invite secret record");
        let invite_secret_event_id = event_id(&invite_record.canonical_bytes);
        let request_bytes =
            connection_request::codec::encode(&connection_request::types::RequestEvent {
                from_endpoint: local.endpoint,
                to_endpoint: remote.endpoint,
                nonce: [9; 32],
                bootstrap_hash: invite_secret.bootstrap_hash,
                invite_secret_event_id,
                from_listen_addr: None,
            });
        let request_id = event_id(&request_bytes);
        let request_record = connection_request::codec::record_from_bytes(request_bytes.clone())
            .expect("connection request record");
        let response_bytes =
            connection_response::codec::encode(&connection_response::types::ResponseEvent {
                from_endpoint: remote.endpoint,
                to_endpoint: local.endpoint,
                request_id,
                traffic_secret: [10; 32],
            });
        let connection_id = event_id(&response_bytes);
        let response_record = connection_response::codec::record_from_bytes(response_bytes.clone())
            .expect("connection response record");
        let rows = vec![
            event_schema::event_row(
                &invite_secret_event_id,
                &invite_record,
                EventStatus::Applied,
            )
            .expect("invite secret event row"),
            event_schema::event_row(&request_id, &request_record, EventStatus::Applied)
                .expect("connection request event row"),
            event_schema::event_row(&connection_id, &response_record, EventStatus::Applied)
                .expect("connection response event row"),
        ];
        store
            .insert_table_rows(rows)
            .expect("insert invite-authorized connection rows");
        connection_id
    }

    fn signed_content_bytes(workspace_id: [u8; 32]) -> Vec<u8> {
        content_event::commands::generate(workspace_id, [8; 32], [9; 32], 1, 1, 8)
            .expect("generate signed content")
            .events[0]
            .record()
            .canonical_bytes
            .clone()
    }

    #[test]
    fn transit_canonical_admission_rejects_local_only_event_from_known_connection() {
        let local = keypair();
        let remote = keypair();
        let connection_id = [3; 32];
        let store = store();
        let local_only = endpoint::commands::create_local_keypair().events[0]
            .record()
            .canonical_bytes
            .clone();
        let local_only_id = event_id(&local_only);
        enqueue_connection_canonical_in(
            &store,
            local_only,
            local.endpoint,
            remote.endpoint,
            connection_id,
        );

        let err = run(&store, &Protocol::new(), Work::Drain { limit: 1 })
            .expect_err("remote local-only event must reject");

        assert!(
            err.contains("connection transit only accepts shared or connection-scoped events"),
            "{err}"
        );
        assert_eq!(
            store
                .table_row_count(worker_schema::CANONICAL_IN)
                .expect("canonical queue count"),
            0,
            "rejected inner bytes must not poison canonical admission"
        );
        assert!(
            !event_schema::has_event(&store, &local_only_id).expect("check event table"),
            "rejected local-only event must not be stored"
        );
    }

    #[test]
    fn bootstrap_transit_rejects_non_shared_identity_event() {
        let local = keypair();
        let remote = keypair();
        let store = store();
        let local_only = endpoint::commands::create_local_keypair().events[0]
            .record()
            .canonical_bytes
            .clone();
        let local_only_id = event_id(&local_only);
        enqueue_bootstrap_canonical_in(&store, local_only, local.endpoint, remote.endpoint);

        let err = run(&store, &Protocol::new(), Work::Drain { limit: 1 })
            .expect_err("bootstrap non-request must reject");

        assert!(
            err.contains(
                "endpoint bootstrap transit only carries connection requests or responses"
            ),
            "{err}"
        );
        assert!(
            !event_schema::has_event(&store, &local_only_id).expect("check event table"),
            "bootstrap transit must not admit unrelated local facts"
        );
    }

    #[test]
    fn invite_bootstrap_transit_admits_identity_event_for_envelope_workspace() {
        // Invariant: invite bootstrap provenance is sufficient for the
        // workspace boundary, but the inner bytes still enter durable admission
        // through the ordinary event pipeline.
        let local = keypair();
        let remote = keypair();
        let store = store();
        let workspace = workspace::commands::create(workspace::commands::CreateWorkspace {
            created_at_ms: 1,
            public_key: [9; 32],
            name: "invite-bootstrap".to_string(),
        })
        .expect("create workspace");
        let record = workspace.events[0].record().clone();
        let workspace_id = workspace.value.workspace_id;
        let event_id = event_id(&record.canonical_bytes);
        enqueue_invite_bootstrap_canonical_in(
            &store,
            record.canonical_bytes,
            local.endpoint,
            remote.endpoint,
            workspace_id,
            [8; 32],
        );

        let admitted = run(&store, &Protocol::new(), Work::Drain { limit: 1 })
            .expect("invite bootstrap workspace should admit");

        assert_eq!(admitted.applied_events, 1);
        assert!(
            event_schema::has_event(&store, &event_id).expect("check event table"),
            "invite bootstrap shared identity event should be stored"
        );
    }

    #[test]
    fn connection_transit_admits_shared_event_only_after_workspace_check() {
        let local = keypair();
        let remote = keypair();
        let connection_id = [3; 32];
        let workspace_id = [7; 32];
        let store = store();
        add_endpoint_membership(&store, workspace_id, [20; 32], local);
        add_endpoint_membership(&store, workspace_id, [21; 32], remote);
        let content = signed_content_bytes(workspace_id);
        let content_id = event_id(&content);
        enqueue_connection_canonical_in(
            &store,
            content,
            local.endpoint,
            remote.endpoint,
            connection_id,
        );

        let admitted = run(&store, &Protocol::new(), Work::Drain { limit: 1 })
            .expect("shared event should admit after workspace check");

        assert_eq!(admitted.blocked_events, 1);
        assert!(
            event_schema::has_event(&store, &content_id).expect("check event table"),
            "shared remote event should enter durable admission"
        );
    }

    #[test]
    fn connection_transit_admits_shared_event_for_invite_authorized_workspace() {
        let local = keypair();
        let remote = keypair();
        let workspace_id = [7; 32];
        let store = store();
        let connection_id = add_invite_authorized_connection(&store, local, remote, workspace_id);
        let content = signed_content_bytes(workspace_id);
        let content_id = event_id(&content);
        enqueue_connection_canonical_in(
            &store,
            content,
            local.endpoint,
            remote.endpoint,
            connection_id,
        );

        let admitted = run(&store, &Protocol::new(), Work::Drain { limit: 1 })
            .expect("invite-authorized shared event should enter admission");

        assert_eq!(admitted.blocked_events, 1);
        assert!(
            event_schema::has_event(&store, &content_id).expect("check event table"),
            "valid invite authority should allow shared workspace events onto the dependency pipeline"
        );
    }

    #[test]
    fn connection_transit_rejects_invite_authorized_event_outside_invite_workspace() {
        let local = keypair();
        let remote = keypair();
        let store = store();
        let connection_id = add_invite_authorized_connection(&store, local, remote, [7; 32]);
        let content = signed_content_bytes([6; 32]);
        let content_id = event_id(&content);
        enqueue_connection_canonical_in(
            &store,
            content,
            local.endpoint,
            remote.endpoint,
            connection_id,
        );

        let err = run(&store, &Protocol::new(), Work::Drain { limit: 1 })
            .expect_err("wrong workspace must reject");

        assert!(
            err.contains("transit shared in rejected event outside sender workspace"),
            "{err}"
        );
        assert!(
            !event_schema::has_event(&store, &content_id).expect("check event table"),
            "invite authority must stay scoped to the invite workspace"
        );
    }

    #[test]
    fn connection_transit_rejects_shared_event_outside_sender_workspace() {
        let local = keypair();
        let remote = keypair();
        let connection_id = [3; 32];
        let store = store();
        let content = signed_content_bytes([7; 32]);
        let content_id = event_id(&content);
        enqueue_connection_canonical_in(
            &store,
            content,
            local.endpoint,
            remote.endpoint,
            connection_id,
        );

        let err = run(&store, &Protocol::new(), Work::Drain { limit: 1 })
            .expect_err("out-of-scope workspace event must reject");

        assert!(
            err.contains("transit shared in rejected event outside sender workspace"),
            "{err}"
        );
        assert!(
            !event_schema::has_event(&store, &content_id).expect("check event table"),
            "out-of-scope remote event must not be stored"
        );
    }
}

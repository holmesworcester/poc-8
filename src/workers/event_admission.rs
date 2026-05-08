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
use crate::core::store::Store;
use crate::workers::pipeline_helpers::event_pipeline::{self as pipeline, AdmitReport, EventRegistry};
use crate::workers::DaemonWorkerContext;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    Drain { limit: usize },
}

pub fn run<R>(store: &Store, registry: &R, work: Work) -> Result<AdmitReport, String>
where
    R: EventRegistry,
{
    match work {
        Work::Drain { limit } => pipeline::drain_canonical_in(store, registry, limit),
    }
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
    use crate::protocol::event_modules::connection::types;
    use crate::protocol::event_modules::content::content_event;
    use crate::protocol::event_modules::identity::{endpoint, endpoint_shared, workspace};
    use crate::protocol::event_modules::schema as event_schema;
    use crate::protocol::event_modules::types::event_id;
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
            err.contains("endpoint bootstrap transit only carries connection requests"),
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

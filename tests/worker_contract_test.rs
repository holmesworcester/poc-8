use std::cell::Cell;

use topo::core::store::Store;
use topo::protocol::event_modules::content::content_event;
use topo::protocol::event_modules::identity::{endpoint, endpoint_shared, workspace};
use topo::protocol::event_modules::schema::{self as event_schema, EventLabel};
use topo::protocol::event_modules::types::{event_id, EventId, EventRecord, EventScope};
use topo::protocol::event_modules::worker::{
    self, CommandOutput, EventRegistry, EventWithContext, ProjectionOutput,
};
use topo::protocol::event_modules::Modules;
use topo::protocol::Protocol;
use topo::workers::schema as worker_schema;
use topo::workers::{dependency_unblock, event_admission, event_projection, sync};

#[test]
fn command_admission_returns_event_ids_for_chaining() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Protocol::open_store(tmp.path().join("worker.db")).unwrap();
    let modules = Modules::new();
    let (workspace_id, endpoint_shared_id, signing_secret) = install_local_content_signer(&store);

    let output = content_event::commands::generate(
        workspace_id,
        endpoint_shared_id,
        signing_secret,
        1,
        3,
        64,
    )
    .unwrap();
    let proposed_ids = output
        .events
        .iter()
        .map(|event| {
            assert_eq!(event.event_id(), event_id(&event.record().canonical_bytes));
            event.event_id()
        })
        .collect::<Vec<_>>();
    let (_, report) = worker::run(&store, &modules, output).unwrap();

    assert_eq!(report.event_ids, proposed_ids);
    for event_id in report.event_ids {
        assert!(event_schema::has_shared_event(&store, &event_id).unwrap());
    }
}

fn install_local_content_signer(store: &Store) -> (EventId, EventId, [u8; 32]) {
    let local = endpoint::commands::create_local_keypair().value;
    store
        .insert_table_rows(endpoint::projector::local_endpoint(local))
        .expect("insert local endpoint");
    let workspace_id = [1; 32];
    let endpoint_shared_id = [2; 32];
    let device_invite_id = [3; 32];
    let event = endpoint_shared::types::EndpointSharedEvent {
        created_at_ms: 1,
        workspace_id,
        user_authority_event_id: [4; 32],
        endpoint_id: local.endpoint,
        signing_public_key: local.signing_public_key,
        endpoint_role: endpoint::types::EndpointRole::Device,
        device_name: "worker".to_string(),
    };
    store
        .insert_table_rows(vec![endpoint_shared::schema::endpoint_membership_row(
            endpoint_shared_id,
            device_invite_id,
            &event,
        )])
        .expect("insert local membership");
    (workspace_id, endpoint_shared_id, local.signing_secret)
}

#[test]
fn worker_fetches_dependency_records_and_labels_before_projection() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Protocol::open_store(tmp.path().join("context.db")).unwrap();

    let dep_bytes = b"dep".to_vec();
    let child_bytes = b"child".to_vec();
    let dep_id = event_id(&dep_bytes);
    let child_id = event_id(&child_bytes);
    let registry = ContextRegistry {
        dep_id,
        child_id,
        dep_bytes: dep_bytes.clone(),
        child_bytes: child_bytes.clone(),
        child_saw_context: Cell::new(false),
    };

    let child = registry.record_for(child_bytes).unwrap();
    let (_, child_report) = worker::run(
        &store,
        &registry,
        CommandOutput::with_events((), vec![child]),
    )
    .unwrap();
    assert_eq!(child_report.blocked_events, 1);
    assert_eq!(child_report.applied_events, 0);

    let dep = registry.record_for(dep_bytes).unwrap();
    let (_, dep_report) =
        worker::run(&store, &registry, CommandOutput::with_events((), vec![dep])).unwrap();
    assert_eq!(dep_report.applied_events, 1);

    let drain = worker::run(&store, &registry, worker::DrainUntilIdle { batch_size: 10 }).unwrap();
    assert_eq!(drain.applied_events, 1);
    assert!(registry.child_saw_context.get());
}

#[test]
fn event_pipeline_workers_claim_and_consume_explicit_queues() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Protocol::open_store(tmp.path().join("explicit-queues.db")).unwrap();

    let dep_bytes = b"queued-dep".to_vec();
    let child_bytes = b"queued-child".to_vec();
    let dep_id = event_id(&dep_bytes);
    let child_id = event_id(&child_bytes);
    let registry = ContextRegistry {
        dep_id,
        child_id,
        dep_bytes: dep_bytes.clone(),
        child_bytes: child_bytes.clone(),
        child_saw_context: Cell::new(false),
    };

    let child = registry.record_for(child_bytes).unwrap();
    store
        .insert_table_rows(vec![worker_schema::canonical_in_row(child, None)])
        .expect("enqueue child canonical in");
    let child_admission =
        event_admission::run(&store, &registry, event_admission::Work::Drain { limit: 1 })
            .expect("admit queued child");
    assert_eq!(child_admission.blocked_events, 1);
    assert_eq!(
        store
            .table_row_count(worker_schema::CANONICAL_IN)
            .expect("count canonical in"),
        0,
        "admission consumes claimed canonical in rows"
    );

    let dep = registry.record_for(dep_bytes).unwrap();
    store
        .insert_table_rows(vec![worker_schema::canonical_in_row(dep, None)])
        .expect("enqueue dep canonical in");
    let dep_admission =
        event_admission::run(&store, &registry, event_admission::Work::Drain { limit: 1 })
            .expect("admit queued dependency");
    assert_eq!(dep_admission.applied_events, 1);
    assert_eq!(
        store
            .table_row_count(worker_schema::RECENTLY_VALID_EVENTS)
            .expect("count recently valid"),
        1,
        "projection writes recently-valid unblock input"
    );

    let unblock = dependency_unblock::run(&store, dependency_unblock::Work::Drain { limit: 1 })
        .expect("unblock child");
    assert_eq!(unblock.unblocked_events, 1);
    assert_eq!(
        store
            .table_row_count(worker_schema::RECENTLY_VALID_EVENTS)
            .expect("count recently valid after unblock"),
        0,
        "dependency unblock consumes recently-valid rows"
    );

    let projected = event_projection::run(
        &store,
        &registry,
        event_projection::Work::Drain { limit: 1 },
    )
    .expect("project child");
    assert_eq!(projected.applied_events, 1);
    assert!(registry.child_saw_context.get());
}

#[test]
fn canonical_in_rejects_are_consumed_and_do_not_poison_later_work() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Protocol::open_store(tmp.path().join("rejected-event-in.db")).unwrap();

    let bad_bytes = b"bad-event-in".to_vec();
    let good_bytes = b"good-event-in".to_vec();
    let registry = RejectThenAcceptRegistry {
        bad_id: event_id(&bad_bytes),
        good_id: event_id(&good_bytes),
        bad_bytes: bad_bytes.clone(),
        good_bytes: good_bytes.clone(),
        good_applied: Cell::new(false),
    };

    let bad = registry.record_for(bad_bytes).unwrap();
    store
        .insert_table_rows(vec![worker_schema::canonical_in_row(bad, None)])
        .expect("enqueue rejected canonical in");
    let err = event_admission::run(&store, &registry, event_admission::Work::Drain { limit: 1 })
        .expect_err("bad event should reject");
    assert!(err.contains("intentional projection reject"), "{err}");
    assert_eq!(
        store
            .table_row_count(worker_schema::CANONICAL_IN)
            .expect("count canonical in after reject"),
        0,
        "rejected canonical in rows must be consumed"
    );

    let good = registry.record_for(good_bytes).unwrap();
    store
        .insert_table_rows(vec![worker_schema::canonical_in_row(good, None)])
        .expect("enqueue good canonical in");
    let report = event_admission::run(&store, &registry, event_admission::Work::Drain { limit: 1 })
        .expect("good event should not be blocked by rejected input");
    assert_eq!(report.applied_events, 1);
    assert!(registry.good_applied.get());
}

#[test]
fn sync_worker_consumes_applied_shared_event_queue() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Protocol::open_store(tmp.path().join("sync-index-queue.db")).unwrap();
    let modules = Modules::new();

    let output = workspace::commands::create(workspace::commands::CreateWorkspace {
        created_at_ms: 1,
        public_key: [9; 32],
        name: "queue-index".to_string(),
    })
    .unwrap();
    worker::run(&store, &modules, output).expect("admit shared event");
    assert_eq!(
        store
            .table_row_count(worker_schema::APPLIED_SHARED_EVENTS)
            .expect("count sync index queue"),
        1
    );

    let index = topo::protocol::event_modules::sync::SyncIndex::default();
    let output = sync::run(&store, &index, sync::Work::DrainIndex { limit: 16 })
        .expect("drain sync index queue");
    let sync::Output::Indexed(report) = output else {
        panic!("sync worker returned non-index output");
    };
    assert_eq!(report.indexed_events, 1);
    assert_eq!(
        store
            .table_row_count(worker_schema::APPLIED_SHARED_EVENTS)
            .expect("count sync index queue after drain"),
        0
    );
}

#[test]
fn admit_and_drain_admits_command_output_then_drains_ready_events() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Protocol::open_store(tmp.path().join("admit-and-drain.db")).unwrap();

    let dep_bytes = b"admit-drain-dep".to_vec();
    let child_bytes = b"admit-drain-child".to_vec();
    let dep_id = event_id(&dep_bytes);
    let child_id = event_id(&child_bytes);
    let registry = ContextRegistry {
        dep_id,
        child_id,
        dep_bytes: dep_bytes.clone(),
        child_bytes: child_bytes.clone(),
        child_saw_context: Cell::new(false),
    };

    let child = registry.record_for(child_bytes).unwrap();
    let (_, child_report) = worker::run(
        &store,
        &registry,
        CommandOutput::with_events((), vec![child]),
    )
    .unwrap();
    assert_eq!(child_report.blocked_events, 1);

    let dep = registry.record_for(dep_bytes).unwrap();
    let report = worker::run(
        &store,
        &registry,
        worker::AdmitAndDrain {
            output: CommandOutput::with_events("dependency".to_string(), vec![dep]),
            batch_size: 10,
        },
    )
    .unwrap();

    assert_eq!(report.value, "dependency");
    assert_eq!(report.admitted.applied_events, 1);
    assert_eq!(report.drained.applied_events, 1);
    assert!(registry.child_saw_context.get());
}

#[test]
fn drain_ready_batch_applies_only_one_batch() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Protocol::open_store(tmp.path().join("batch.db")).unwrap();

    let registry = BatchRegistry::new();
    let child_events = registry
        .child_bytes
        .iter()
        .map(|bytes| registry.record_for(bytes.clone()).unwrap())
        .collect::<Vec<_>>();

    let (_, blocked) = worker::run(
        &store,
        &registry,
        CommandOutput::with_events((), child_events),
    )
    .unwrap();
    assert_eq!(blocked.blocked_events, 2);
    assert_eq!(registry.children_applied.get(), 0);

    let dep = registry.record_for(registry.dep_bytes.clone()).unwrap();
    let (_, dep_report) =
        worker::run(&store, &registry, CommandOutput::with_events((), vec![dep])).unwrap();
    assert_eq!(dep_report.applied_events, 1);
    assert_eq!(registry.children_applied.get(), 0);

    let first = worker::run(&store, &registry, worker::DrainReadyBatch { batch_size: 1 }).unwrap();
    assert_eq!(first.applied_events, 1);
    assert_eq!(registry.children_applied.get(), 1);

    let second = worker::run(&store, &registry, worker::DrainReadyBatch { batch_size: 1 }).unwrap();
    assert_eq!(second.applied_events, 1);
    assert_eq!(registry.children_applied.get(), 2);
}

#[test]
fn worker_never_surfaces_failed_projection_as_dependency_context() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Protocol::open_store(tmp.path().join("invalid-context.db")).unwrap();

    let gate_bytes = b"gate".to_vec();
    let bad_dep_bytes = b"bad-dep".to_vec();
    let child_bytes = b"child-after-bad-dep".to_vec();
    let gate_id = event_id(&gate_bytes);
    let bad_dep_id = event_id(&bad_dep_bytes);
    let child_id = event_id(&child_bytes);
    let registry = ValidDependencyContextRegistry {
        gate_id,
        bad_dep_id,
        child_id,
        gate_bytes: gate_bytes.clone(),
        bad_dep_bytes: bad_dep_bytes.clone(),
        child_bytes: child_bytes.clone(),
        child_saw_context: Cell::new(false),
    };

    let bad_dep = registry.record_for(bad_dep_bytes).unwrap();
    let child = registry.record_for(child_bytes).unwrap();
    let (_, blocked_report) = worker::run(
        &store,
        &registry,
        CommandOutput::with_events((), vec![child, bad_dep]),
    )
    .unwrap();
    assert_eq!(blocked_report.blocked_events, 2);
    assert_eq!(blocked_report.applied_events, 0);

    let gate = registry.record_for(gate_bytes).unwrap();
    let (_, gate_report) = worker::run(
        &store,
        &registry,
        CommandOutput::with_events((), vec![gate]),
    )
    .unwrap();
    assert_eq!(gate_report.applied_events, 1);

    let err = worker::run(&store, &registry, worker::DrainUntilIdle { batch_size: 10 })
        .expect_err("invalid dependency projection must fail");
    assert!(
        err.contains("bad dependency rejected by projector"),
        "{err}"
    );

    let statuses = event_schema::status_counts(&store).expect("status counts");
    assert_eq!(statuses.applied, 1, "only the gate event should apply");
    assert_eq!(statuses.ready, 1, "failed dependency should remain ready");
    assert_eq!(
        statuses.blocked, 1,
        "child should remain blocked on bad dep"
    );
    assert_eq!(statuses.blocked_edges, 1);
    assert!(
        !registry.child_saw_context.get(),
        "child projector must not receive failed dependency in context"
    );
    assert!(!event_schema::event_is_applied(&store, &bad_dep_id).unwrap());
    assert!(!event_schema::event_is_applied(&store, &child_id).unwrap());
}

struct ContextRegistry {
    dep_id: EventId,
    child_id: EventId,
    dep_bytes: Vec<u8>,
    child_bytes: Vec<u8>,
    child_saw_context: Cell<bool>,
}

struct BatchRegistry {
    dep_id: EventId,
    dep_bytes: Vec<u8>,
    child_ids: Vec<EventId>,
    child_bytes: Vec<Vec<u8>>,
    children_applied: Cell<usize>,
}

impl BatchRegistry {
    fn new() -> Self {
        let dep_bytes = b"batch-dep".to_vec();
        let child_bytes = vec![b"batch-child-a".to_vec(), b"batch-child-b".to_vec()];
        let dep_id = event_id(&dep_bytes);
        let child_ids = child_bytes
            .iter()
            .map(|bytes| event_id(bytes))
            .collect::<Vec<_>>();
        Self {
            dep_id,
            dep_bytes,
            child_ids,
            child_bytes,
            children_applied: Cell::new(0),
        }
    }

    fn record_for(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        if bytes == self.dep_bytes {
            return Ok(EventRecord {
                timestamp: 1,
                body_len: bytes.len(),
                canonical_bytes: bytes,
                dependencies: Vec::new(),
                workspace_id: None,
                scope: EventScope::Shared,
            });
        }
        if self.child_bytes.iter().any(|candidate| candidate == &bytes) {
            return Ok(EventRecord {
                timestamp: 2,
                body_len: bytes.len(),
                canonical_bytes: bytes,
                dependencies: vec![self.dep_id],
                workspace_id: None,
                scope: EventScope::Shared,
            });
        }
        Err("unknown batch event".to_string())
    }
}

struct ValidDependencyContextRegistry {
    gate_id: EventId,
    bad_dep_id: EventId,
    child_id: EventId,
    gate_bytes: Vec<u8>,
    bad_dep_bytes: Vec<u8>,
    child_bytes: Vec<u8>,
    child_saw_context: Cell<bool>,
}

struct RejectThenAcceptRegistry {
    bad_id: EventId,
    good_id: EventId,
    bad_bytes: Vec<u8>,
    good_bytes: Vec<u8>,
    good_applied: Cell<bool>,
}

impl ContextRegistry {
    fn record_for(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        if bytes == self.dep_bytes {
            return Ok(EventRecord {
                timestamp: 1,
                body_len: bytes.len(),
                canonical_bytes: bytes,
                dependencies: Vec::new(),
                workspace_id: None,
                scope: EventScope::Shared,
            });
        }
        if bytes == self.child_bytes {
            return Ok(EventRecord {
                timestamp: 2,
                body_len: bytes.len(),
                canonical_bytes: bytes,
                dependencies: vec![self.dep_id],
                workspace_id: None,
                scope: EventScope::Shared,
            });
        }
        Err("unknown test event".to_string())
    }
}

impl ValidDependencyContextRegistry {
    fn record_for(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        if bytes == self.gate_bytes {
            return Ok(EventRecord {
                timestamp: 1,
                body_len: bytes.len(),
                canonical_bytes: bytes,
                dependencies: Vec::new(),
                workspace_id: None,
                scope: EventScope::Shared,
            });
        }
        if bytes == self.bad_dep_bytes {
            return Ok(EventRecord {
                timestamp: 2,
                body_len: bytes.len(),
                canonical_bytes: bytes,
                dependencies: vec![self.gate_id],
                workspace_id: None,
                scope: EventScope::Shared,
            });
        }
        if bytes == self.child_bytes {
            return Ok(EventRecord {
                timestamp: 3,
                body_len: bytes.len(),
                canonical_bytes: bytes,
                dependencies: vec![self.bad_dep_id],
                workspace_id: None,
                scope: EventScope::Shared,
            });
        }
        Err("unknown test event".to_string())
    }
}

impl RejectThenAcceptRegistry {
    fn record_for(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        if bytes == self.bad_bytes || bytes == self.good_bytes {
            return Ok(EventRecord {
                timestamp: 1,
                body_len: bytes.len(),
                canonical_bytes: bytes,
                dependencies: Vec::new(),
                workspace_id: None,
                scope: EventScope::Shared,
            });
        }
        Err("unknown reject test event".to_string())
    }
}

impl EventRegistry for ContextRegistry {
    fn record_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        self.record_for(bytes)
    }

    fn project_record(
        &self,
        _store: &Store,
        event: &EventWithContext<'_>,
    ) -> Result<ProjectionOutput, String> {
        if event.context.event_id == self.dep_id {
            return Ok(ProjectionOutput::labels(vec![EventLabel {
                event_id: self.child_id,
                label: b"dep-applied".to_vec(),
            }]));
        }
        if event.context.event_id == self.child_id {
            assert_eq!(
                event
                    .context
                    .dependency(&self.dep_id)
                    .expect("dependency context")
                    .canonical_bytes,
                self.dep_bytes
            );
            assert!(event.context.has_label(b"dep-applied"));
            self.child_saw_context.set(true);
            return Ok(ProjectionOutput::default());
        }
        Err("unknown projection".to_string())
    }
}

impl EventRegistry for BatchRegistry {
    fn record_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        self.record_for(bytes)
    }

    fn project_record(
        &self,
        _store: &Store,
        event: &EventWithContext<'_>,
    ) -> Result<ProjectionOutput, String> {
        if event.context.event_id == self.dep_id {
            return Ok(ProjectionOutput::default());
        }
        if self.child_ids.contains(&event.context.event_id) {
            self.children_applied
                .set(self.children_applied.get().saturating_add(1));
            return Ok(ProjectionOutput::default());
        }
        Err("unknown batch projection".to_string())
    }
}

impl EventRegistry for ValidDependencyContextRegistry {
    fn record_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        self.record_for(bytes)
    }

    fn project_record(
        &self,
        _store: &Store,
        event: &EventWithContext<'_>,
    ) -> Result<ProjectionOutput, String> {
        if event.context.event_id == self.gate_id {
            assert!(event.context.dependencies.is_empty());
            return Ok(ProjectionOutput::default());
        }
        if event.context.event_id == self.bad_dep_id {
            assert_eq!(
                event
                    .context
                    .dependency(&self.gate_id)
                    .expect("gate dependency")
                    .canonical_bytes,
                self.gate_bytes
            );
            return Err("bad dependency rejected by projector".to_string());
        }
        if event.context.event_id == self.child_id {
            self.child_saw_context.set(true);
            panic!("child must remain blocked until bad dependency is applied");
        }
        Err("unknown projection".to_string())
    }
}

impl EventRegistry for RejectThenAcceptRegistry {
    fn record_from_bytes(&self, bytes: Vec<u8>) -> Result<EventRecord, String> {
        self.record_for(bytes)
    }

    fn project_record(
        &self,
        _store: &Store,
        event: &EventWithContext<'_>,
    ) -> Result<ProjectionOutput, String> {
        if event.context.event_id == self.bad_id {
            return Err("intentional projection reject".to_string());
        }
        if event.context.event_id == self.good_id {
            self.good_applied.set(true);
            return Ok(ProjectionOutput::default());
        }
        Err("unknown reject projection".to_string())
    }
}

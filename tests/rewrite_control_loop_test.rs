#[path = "../src/control_loop.rs"]
mod control_loop;

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use control_loop::{
    Config, ConnectionId, ControlLoop, ControlLoopBackend, DueJob, EventId, JobOutcome, NetworkWake,
};

#[derive(Debug, Clone)]
struct ToyEvent {
    module: &'static str,
    deps: Vec<EventId>,
}

#[derive(Debug, Default)]
struct ToyPipeline {
    events: BTreeMap<EventId, ToyEvent>,
    ready: VecDeque<EventId>,
    blocked: BTreeSet<EventId>,
    applied: BTreeSet<EventId>,
    projected_modules: Vec<&'static str>,
    due_jobs: VecDeque<DueJob>,
    pending_connections: VecDeque<ConnectionId>,
}

impl ToyPipeline {
    fn insert_event(&mut self, id: EventId, module: &'static str, deps: Vec<EventId>) {
        self.events.insert(id, ToyEvent { module, deps });
        if self.deps_are_applied(id) {
            self.ready.push_back(id);
        } else {
            self.blocked.insert(id);
        }
    }

    fn applied_ids(&self) -> Vec<EventId> {
        self.applied.iter().copied().collect()
    }

    fn deps_are_applied(&self, id: EventId) -> bool {
        self.events
            .get(&id)
            .expect("event exists")
            .deps
            .iter()
            .all(|dep| self.applied.contains(dep))
    }

    fn unblock_ready_dependents(&mut self) {
        let became_ready: Vec<EventId> = self
            .blocked
            .iter()
            .copied()
            .filter(|id| self.deps_are_applied(*id))
            .collect();

        for id in became_ready {
            self.blocked.remove(&id);
            self.ready.push_back(id);
        }
    }
}

impl ControlLoopBackend for ToyPipeline {
    type Error = String;

    fn drain_ready(&mut self, limit: usize) -> Result<usize, Self::Error> {
        let mut projected = 0;

        for _ in 0..limit {
            let Some(id) = self.ready.pop_front() else {
                break;
            };
            if self.applied.contains(&id) {
                continue;
            }

            let event = self
                .events
                .get(&id)
                .ok_or_else(|| "missing event".to_string())?;
            if !event.deps.iter().all(|dep| self.applied.contains(dep)) {
                self.blocked.insert(id);
                continue;
            }

            self.applied.insert(id);
            self.projected_modules.push(event.module);
            projected += 1;
        }

        self.unblock_ready_dependents();
        Ok(projected)
    }

    fn due_jobs(&mut self, limit: usize) -> Result<Vec<DueJob>, Self::Error> {
        Ok((0..limit)
            .filter_map(|_| self.due_jobs.pop_front())
            .collect())
    }

    fn run_due_job(&mut self, job: DueJob) -> Result<JobOutcome, Self::Error> {
        if job.module == "toy_emit" {
            let id = event_id(job.payload.first().copied().unwrap_or(0));
            self.insert_event(id, "job_emitted", Vec::new());
            Ok(JobOutcome::emitted_events(1))
        } else {
            Ok(JobOutcome::no_op())
        }
    }

    fn pending_outbox_connections(
        &mut self,
        limit: usize,
    ) -> Result<Vec<ConnectionId>, Self::Error> {
        Ok((0..limit)
            .filter_map(|_| self.pending_connections.pop_front())
            .collect())
    }
}

#[derive(Debug, Default)]
struct ToyNetwork {
    woken_connections: Vec<ConnectionId>,
}

impl NetworkWake for ToyNetwork {
    type Error = String;

    fn wake_connection_sender(&mut self, connection_id: &[u8]) -> Result<(), Self::Error> {
        self.woken_connections.push(connection_id.to_vec());
        Ok(())
    }
}

fn event_id(byte: u8) -> EventId {
    [byte; 32]
}

fn config_with_fuel(ready_event_fuel: usize) -> Config {
    Config {
        ready_event_fuel,
        due_job_fuel: 8,
        outbox_connection_fuel: 8,
        max_idle_ticks: 16,
    }
}

#[test]
fn run_until_idle_projects_blocked_dependent_after_dependency_arrives() {
    let dep = event_id(1);
    let child = event_id(2);

    let mut pipeline = ToyPipeline::default();
    pipeline.insert_event(child, "dependent", vec![dep]);
    pipeline.insert_event(dep, "dependency", Vec::new());

    let mut control_loop = ControlLoop::new(pipeline, ToyNetwork::default(), config_with_fuel(16));
    assert_eq!(control_loop.config().ready_event_fuel, 16);

    let summary = control_loop.run_until_idle().expect("run control loop");
    let (pipeline, _, _) = control_loop.into_parts();

    assert_eq!(summary.projected_events, 2);
    assert_eq!(pipeline.applied_ids(), vec![dep, child]);
    assert_eq!(pipeline.projected_modules, vec!["dependency", "dependent"]);
}

#[test]
fn fuel_limits_bound_ready_work_and_require_another_tick() {
    let mut pipeline = ToyPipeline::default();
    pipeline.insert_event(event_id(1), "toy", Vec::new());
    pipeline.insert_event(event_id(2), "toy", Vec::new());
    pipeline.insert_event(event_id(3), "toy", Vec::new());

    let mut control_loop = ControlLoop::new(pipeline, ToyNetwork::default(), config_with_fuel(2));

    let first = control_loop.tick_once().expect("first tick");
    let (pipeline, network, config) = control_loop.into_parts();
    assert_eq!(first.projected_events, 2);
    assert_eq!(pipeline.applied_ids(), vec![event_id(1), event_id(2)]);

    let mut control_loop = ControlLoop::new(pipeline, network, config);
    let second = control_loop.tick_once().expect("second tick");
    let (pipeline, _, _) = control_loop.into_parts();

    assert_eq!(second.projected_events, 1);
    assert_eq!(
        pipeline.applied_ids(),
        vec![event_id(1), event_id(2), event_id(3)]
    );
}

#[test]
fn control_loop_does_not_know_event_type_semantics() {
    let mut pipeline = ToyPipeline::default();
    pipeline.insert_event(event_id(1), "workspace", Vec::new());
    pipeline.insert_event(event_id(2), "message", Vec::new());
    pipeline.insert_event(event_id(3), "unknown_future_module", Vec::new());

    let mut control_loop = ControlLoop::new(pipeline, ToyNetwork::default(), config_with_fuel(16));

    control_loop.run_until_idle().expect("run control loop");
    let (pipeline, _, _) = control_loop.into_parts();

    assert_eq!(
        pipeline.projected_modules,
        vec!["workspace", "message", "unknown_future_module"]
    );
    assert_eq!(
        pipeline.applied_ids(),
        vec![event_id(1), event_id(2), event_id(3)]
    );
}

#[test]
fn due_job_can_emit_event_without_control_loop_semantics() {
    let mut pipeline = ToyPipeline::default();
    pipeline
        .due_jobs
        .push_back(DueJob::new("toy_emit", "emit_ready", vec![7]));

    let mut control_loop = ControlLoop::new(pipeline, ToyNetwork::default(), config_with_fuel(16));

    let summary = control_loop.run_until_idle().expect("run control loop");
    let (pipeline, _, _) = control_loop.into_parts();

    assert_eq!(summary.due_jobs_ran, 1);
    assert_eq!(summary.emitted_events, 1);
    assert_eq!(pipeline.applied_ids(), vec![event_id(7)]);
    assert_eq!(pipeline.projected_modules, vec!["job_emitted"]);
}

#[test]
fn tick_wakes_network_senders_for_pending_outbox_connections() {
    let mut pipeline = ToyPipeline::default();
    pipeline.pending_connections.push_back(b"conn-a".to_vec());
    pipeline.pending_connections.push_back(b"conn-b".to_vec());

    let mut control_loop = ControlLoop::new(pipeline, ToyNetwork::default(), config_with_fuel(16));

    let summary = control_loop.tick_once().expect("tick");
    let (_, network, _) = control_loop.into_parts();

    assert_eq!(summary.projected_events, 0);
    assert_eq!(summary.woken_senders, 2);
    assert_eq!(
        network.woken_connections,
        vec![b"conn-a".to_vec(), b"conn-b".to_vec()]
    );
}

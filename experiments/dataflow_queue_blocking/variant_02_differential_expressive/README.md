# Variant 02: Differential-expressive queue blocking

Purpose: show a richer kernel DSL that stays close to Differential Dataflow's
mental model while remaining small enough to audit. Modules declare input
collections, derived collections, arrangements, and rules. Queue-like behavior
falls out of dataflow boundaries rather than from hidden runtime queues.

This variant does not depend on Timely or Differential Dataflow. The toy in
`differential_kernel.py` is a runnable sketch of the same boundaries.

## Ownership

The module owns semantic collections:

- `events`: canonical event facts, keyed by `event_id`.
- `depends_on`: declared dependency edges `(event_id, dep_id)`.
- `applied`: event ids whose projector has committed.
- `connection_workspace`: connection membership facts.
- `fuel_budget`: control-loop fuel admitted for one tick.

The module derives queue and boundary collections:

- `missing_dep`: dependency edges whose `dep_id` is not in `applied`.
- `blocked_by_event`: the durable wait edge `(blocked_by_event_id, event_id)`.
- `blocked`: reduction of missing deps by `event_id`.
- `ready`: events not applied and with no remaining blockers.
- `unblock`: stream of wait edges removed by an applied dependency.
- `outbox`: `(connection_id, event_id)` rows to be sent by a sender owner.

The control loop owns scheduling and fuel. It does not own dependency policy,
workspace policy, or projector semantics.

## DSL shape

The module declaration in `differential_kernel.py` records the intended kernel
surface. In compact form:

```text
arrange depends_on by event_id as deps_by_event
arrange depends_on by dep_id as deps_by_dep
arrange blocked_by_event by blocked_by_event_id as blockers_by_dep
arrange outbox by connection_id as outbox_by_connection

missing_dep(dep_id, event_id) =
  depends_on(event_id, dep_id)
    .anti_join(applied(dep_id))

blocked_by_event(dep_id, event_id) =
  missing_dep(dep_id, event_id)

blocked(event_id, count) =
  missing_dep(dep_id, event_id)
    .reduce(count by event_id)

ready(event_id) =
  events(event_id)
    .anti_join(blocked(event_id))
    .anti_join(applied(event_id))

unblock(dep_id, event_id, time) =
  blocked_by_event@previous(dep_id, event_id)
    .anti_join(blocked_by_event@current(dep_id, event_id))
    .join(ready(event_id))

outbox(connection_id, event_id) =
  applied(event_id)
    .join(events by event_id -> workspace_id)
    .join(connection_workspace by workspace_id -> connection_id)
```

`missing_dep` is the key anti-join: dependency presence is not enough. A
dependent event waits until the dependency is applied, so a present but
unprojected dependency still blocks.

## Dependency cascade

The toy uses this concrete cascade:

```text
A
B depends on A
C depends on B
D depends on C
```

If `B`, `C`, and `D` arrive before `A`, the dataflow contains these wait rows:

```text
blocked_by_event(A, B)
blocked_by_event(B, C)
blocked_by_event(C, D)
```

After `A` arrives, `A` is ready but `B` is still blocked until `A` is applied.
With one unit of fuel per tick:

```text
tick 1: apply A, remove blocked_by_event(A, B), ready(B), outbox(conn, A)
tick 2: apply B, remove blocked_by_event(B, C), ready(C), outbox(conn, B)
tick 3: apply C, remove blocked_by_event(C, D), ready(D), outbox(conn, C)
tick 4: apply D, outbox(conn, D)
```

This is the useful boundary: unblocking is incremental and bounded. The
control loop may discover new `ready` rows inside a tick, but each applied event
spends one explicit fuel unit.

## Time and frontier metadata

The toy attaches a logical time to every input batch and every apply iteration:

```text
epoch.iteration
```

An input batch advances `epoch` and derives collections at `iteration = 0`.
Each fuel-spending apply step increments `iteration`. The exported frontier
records:

- `input_epoch`: latest input/tick epoch observed.
- `completed_iteration`: latest derivation iteration completed in that epoch.
- `ready_count`: ready events left for future ticks.
- `blocked_count`: events still blocked by at least one dependency.
- `pending_event_count`: events present but not applied.

This is only metadata in the toy, but it marks where a real Timely-style
frontier would live.

## Running

From the worktree root:

```sh
python3 experiments/dataflow_queue_blocking/variant_02_differential_expressive/differential_kernel.py --trace
python3 -m unittest discover -s experiments/dataflow_queue_blocking/variant_02_differential_expressive -p 'test_*.py'
```

The script prints the cascade summaries and, with `--trace`, the differential
change trace for facts and derived collections.

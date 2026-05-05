# Universal Worker Plan

## Contract

A worker is a synchronous, bounded step scheduled round-robin over explicit
inputs.

```text
claim input -> read owned context -> mutate owned state -> write output queues/events -> ack input
```

Rules:

- Workers never call other workers as control flow.
- Workers communicate by writing another worker's named input queue, status
  index, or event ingress.
- All shared, connection-scoped, and local events use the same admission,
  blocking, projection, and dependency-wake path. Scope controls distribution,
  not pipeline membership.
- Commands may be synchronous event builders. If a UI/CLI/RPC action needs
  daemon-owned context, it registers an intent for a worker to resolve.

Every worker doc should state:

```text
Inputs:
State:
Step:
Outputs:
Ack:
Failure:
Fairness:
```

## Current Workers

- `event_admission`: consumes `event_modules.event_ingress`, inserts/dedupes
  canonical events, performs the initial dependency check, and writes
  `event_modules.ready_events` or blocker indexes.
- `event_projection`: consumes `event_modules.ready_events`, loads dependency
  context, runs projectors, writes read models/module queues, marks events
  applied, and writes `event_modules.recently_valid_events` plus
  `event_modules.applied_shared_events` for shared events.
- `dependency_wake`: consumes `event_modules.recently_valid_events`, clears
  missing-dependency edges, and writes newly unblocked events to
  `event_modules.ready_events`.
- `sync_index`: consumes `event_modules.applied_shared_events` and updates the
  process-local negentropy/hash state. It may rebuild from durable shared-event
  indexes on cold start, but warm operation has an explicit queue.
- `sync_protocol`: consumes `sync.inbound_events` and explicit sync-start
  requests, uses the sync index for compare/have/need decisions, writes sync
  protocol events through event ingress, and writes durable send ids to
  `connection.outbox`.
- `connection_ingress`: consumes inbound transport frames from
  `core.network.inbound`, unwraps/authenticates connection traffic, writes
  normal scoped events through event ingress, and returns same-route outbound
  network rows.
- `connection_egress`: consumes `connection.outbox`, loads event bytes,
  enforces route/scope/workspace policy, wraps transit frames, and writes
  outbound transport rows.
- `events`, `connection`, and `sync`: compatibility facades that keep existing
  CLI/test call sites synchronous while delegating to the explicit workers
  above. New worker behavior should be added to the explicit worker modules, not
  hidden in these facades.

## Remaining Target Workers

- `local_intents`: consumes UI/CLI/RPC intents that need daemon-owned context,
  queries narrow context, runs command builders, writes `event_ingress`, and
  writes intent results.
- `tcp_receive`: reads sockets, strips only transport framing, and writes inbound
  transport frames.
- `tcp_send`: consumes outbound transport frames and writes bytes to sockets. It
  only handles transport-frame ack/retry bookkeeping; send success/failure is not
  a semantic event because sync/eventual consistency handles delivery.

## Migration Plan

1. Keep existing behavior compiling while moving worker implementations into
   this folder. Done.
2. Add `event_ingress`, `recently_valid`, and `applied_shared_events` queues
   with boundary tests for claim/ack behavior. Done.
3. Split `events.rs` into admission, projection, and dependency-wake workers.
   Done for named worker entrypoints; the compatibility facade still preserves
   existing synchronous command semantics.
4. Split connection ingress/egress so the named workers own inbound frame
   interpretation and outbox route exchange. Done at the worker boundary; the
   compatibility facade still owns CLI/daemon orchestration.
5. Split sync index maintenance from sync protocol work. Done.
6. Route daemon and CLI/frontend actions through fast command builders plus
   `event_ingress`, or through `local_intents` when daemon-owned context is
   required.
7. Add the round-robin scheduler over the named worker inputs and remove direct
   worker-to-worker calls.
8. Commit the completed work on the same worktree branch before handoff or
   review.

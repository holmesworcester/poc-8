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

## Target Workers

- `local_intents`: consumes UI/CLI/RPC intents that need daemon-owned context,
  queries narrow context, runs command builders, writes `event_ingress`, and
  writes intent results.
- `event_admission`: consumes `event_ingress`, inserts/dedupes canonical
  events, performs the initial dependency check, and writes either
  `ready_events` or blocker indexes.
- `event_projection`: consumes `ready_events`, loads dependency context, runs
  projectors, writes read models/module queues, marks events applied, writes
  `recently_valid`, and writes `applied_shared_events` for applied shared
  events.
- `dependency_wake`: consumes `recently_valid`, clears missing-dependency
  edges, and writes newly unblocked events to `ready_events`.
- `connection_ingress`: consumes inbound transport frames, unwraps/authenticates
  connection traffic, and writes normal scoped events to `event_ingress`,
  including connection request/ack, received sync events, and received shared
  events.
- `sync_index`: consumes `applied_shared_events` and updates persistent sync
  index rows plus rebuildable in-memory negentropy/hash state.
- `sync_protocol`: consumes `sync.inbound_events` and `sync_start_requests`,
  uses the sync index for compare/have/need decisions, writes sync events to
  `event_ingress`, and writes durable send requests to `connection.outbox`.
- `connection_egress`: consumes `connection.outbox`, loads event bytes, enforces
  route/scope/workspace policy, wraps transit frames, and writes outbound
  transport frames.
- `tcp_receive`: reads sockets, strips only transport framing, and writes inbound
  transport frames.
- `tcp_send`: consumes outbound transport frames and writes bytes to sockets. It
  only handles transport-frame ack/retry bookkeeping; send success/failure is not
  a semantic event because sync/eventual consistency handles delivery.

## Migration Plan

1. Keep existing behavior compiling while moving worker implementations into
   this folder.
2. Add durable `event_ingress`, `recently_valid`, and `applied_shared_events`
   queues with boundary tests for claim/ack/failure behavior.
3. Split `events.rs` into admission, projection, and dependency-wake workers.
4. Split connection ingress/egress so connection no longer directly drives sync,
   ready draining, or outbox draining.
5. Split sync index maintenance from sync protocol work.
6. Route daemon and CLI/frontend actions through fast command builders plus
   `event_ingress`, or through `local_intents` when daemon-owned context is
   required.
7. Add the round-robin scheduler over the named worker inputs and remove direct
   worker-to-worker calls.
8. Commit the completed work on the same worktree branch before handoff or
   review.

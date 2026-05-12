# Universal Worker Plan

## Fact Graph View

The system is a fact graph. Canonical event ids are fact node ids; dependencies
are graph edges; receive/provenance metadata is local edge context; projected
rows are read models or worker input queues derived from accepted facts.

Commands, projectors, and workers are the safe implementation surfaces for that
graph:

- Commands build proposed facts from explicit inputs.
- Projectors are pure fact-to-row derivations over loaded graph context.
- Workers claim bounded queue facts, run commands or boundary codecs, admit new
  facts, and write the next explicit queue.

No worker should hide semantic state that could instead be an event fact,
dependency, projection row, or queue row.

## Contract

A worker is a synchronous, bounded step over explicit inputs.

```text
claim input -> read owned context -> mutate owned state -> write output queues/events -> consume input
```

Rules:

- Scheduled worker steps never call other scheduled worker steps as control
  flow. Compatibility facades may compose worker turns for finite CLI/test
  calls, but new ongoing behavior belongs in explicit worker modules and daemon
  scheduling.
- Workers communicate by writing another worker's named input queue, status
  index, or canonical in.
- All shared, connection-scoped, and local events use the same admission,
  blocking, projection, and dependency unblock path. Scope controls distribution,
  not pipeline membership.
- Commands may be synchronous event builders. If a UI/CLI/RPC action needs
  daemon-owned context, it registers an intent for a worker to resolve.

Every worker doc should state:

```text
Inputs:
State:
Step:
Outputs:
Consume:
Failure:
Fairness:
```

## How Workers Run

Workers are run by explicit synchronous call sites:

- CLI commands call command builders and enqueue/admit the resulting event
  records for local command effects.
- The worker catalog owns ongoing protocol operation. It exports named daemon
  worker objects. The current core scheduler calls each step once per tick in
  round-robin order; the workers themselves are not "round-robin workers."
- Compatibility facades in `common::event_pipeline` provide bounded command/test
  behavior over the explicit worker modules. Long-lived network behavior belongs
  to daemon workers.

Core does not know protocol meaning. It only owns the loop:

```text
for worker in workers:
  worker.run(one bounded Work item)
```

The daemon's current worker catalog is:

```text
transit_in
event_admission
event_projection
dependency_unblock
encryption
content_purge
sync
transit_out
```

Fairness is local to each call: each `Work` variant has a batch limit or a
single route/frame boundary.

## Current Workers

- `transit_in`: accepts daemon or finite-listener TCP streams and consumes raw
  `core.network.inbound` frames. It runs the protocol transit projector,
  unwraps/authenticates transport envelopes using explicit local context, and
  feeds recovered inner bytes to the common admission pipeline with provenance.
  It does not create connection responses; connection bootstrap work is queued
  for the `connection` worker. Ordinary sync responses are queued for
  `transit_out` and sent on routed connections in later worker turns.
- `event_admission`: consumes `canonical.in` rows. It inserts/dedupes events,
  performs the initial dependency check, keeps receive metadata beside blocked
  received events, and writes `event_modules.ready_events` or blocker indexes.
  Transit provenance is checked here before unwrapped bytes can become ordinary
  pipeline events.
- `event_projection`: consumes `event_modules.ready_events`, loads dependency
  context, runs projectors, writes read models/module queues, marks events
  applied, and writes `event_modules.recently_valid_events` plus
  `event_modules.applied_shared_events` for shared events.
- `dependency_unblock`: consumes `event_modules.recently_valid_events`, clears
  missing-dependency edges, and writes newly unblocked events to
  `event_modules.ready_events`.
- `encryption`: consumes encryption-domain queues. It drains `key_wrap`'s
  projected pending unwrap rows to create local-only key-secret events through
  the common pipeline, then derives pending per-message/file content leaves
  once those local secrets exist.
- `content_purge`: consumes worker-owned local retention work and deletes local
  payload bytes after durable semantic events preserve what peers need to know.
  It is not a protocol deletion event and does not authorize remote erasure.
- `connection`: consumes projected pending connection attempts and responses.
  It retries invite-address connection requests, creates connection response
  events for validated inbound requests, sends handshake frames through
  `transit_out`, and retires rows once a connection response projects or a
  response frame is delivered. This is the long-term home for peer-selection,
  connection-count, retry/backoff, and stale-connection policy.
- `sync`: consumes `event_modules.applied_shared_events`, `sync.in`, and
  explicit sync-start requests. It catches up the protocol-owned warm sync
  index before responding, calls sync commands for compare/have/need decisions,
  writes sync protocol events through canonical in, and writes durable send ids to
  `transit.out`. Inbound sync work is authorized by the receiving connection id.
  The daemon drains inbound sync work before starting new compares.
  Invite-scoped routes poll from both endpoints so either side can discover new
  workspace history. Plain connections use deterministic endpoint ordering to
  avoid duplicate starters.
- `transit_out`: consumes `transit.out`, loads queued event bytes, enforces
  route/scope/workspace policy, wraps transit frames, and writes outbound
  transport rows. It also provides the direct opaque-frame send helper used by
  the `connection` worker, but it does not own connection retry policy.
  Established-route sends drain by connection, then coalesce frames by socket
  address so multiple routes to one daemon cost one accepted TCP stream per
  outbound pass.
- `common::event_pipeline` is not a daemon worker. It provides the shared
  admission/projection/block-unblock machinery and finite command/test helpers
  over the explicit workers above. Connection bootstrap is ordinary projected
  state: request projection queues attempts/responses, the `connection` worker
  decides what to dial or answer, and inbound responses still enter through
  transit in and event admission.

## Runtime Boundaries Outside This Folder

- CLI commands are synchronous call sites. They build command output, admit
  events, run selected worker steps, and format results.
- The core daemon runner is the long-lived caller. The selected protocol gives
  it the bounded worker objects to call each tick.
- Core TCP owns socket reads/writes and length-prefix framing. It hands opaque
  network rows to transit workers and never interprets protocol bytes.
- There is no intent worker in this tree. Commands that need daemon-owned
  context should become durable intent rows for a worker to resolve.

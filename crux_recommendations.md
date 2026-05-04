# Crux Recommendations For poc-8

## Summary

The best fit is to put Crux around the kernel control loop, then split the
current pipeline into pure planners plus explicit shell effects. Do not make
each fact module its own Crux app, and do not turn canonical protocol facts into
Crux events. In Crux terms, `Event` should mean the input to `App::update`;
Topo's canonical, content-addressed records should be called facts.

Recommended shape:

```text
CLI/TCP/SQLite shell
  -> KernelMsg
  -> Crux KernelApp update(model, msg)
  -> pure pipeline planners
  -> pure event modules
  -> typed Store/Network/Rng/Clock/Stdout effects
  -> shell interpreters
  -> StoreReply/NetworkReply/etc back into KernelMsg
```

The immediate value is not that Crux provides a magic scheduler. The value is
that it gives a typed `Message -> Command<Effect, Message>` boundary. That
boundary makes IO visible, testable, and hard to accidentally smuggle into
domain modules.

## Terminology

Use Crux's vocabulary for Crux concepts:

- **Crux App**: the `crux_core::App` implementation around the kernel loop.
- **Crux Event**: the input message passed to `App::update`.
- **Crux Command**: the value returned by `update` to drive follow-up work.
- **Crux Effect**: a shell operation requested by a Crux command.
- **Crux Model**: the state owned by the Crux app.

Use Topo vocabulary for the event-sourced substrate:

- **Topo Intent**: a domain request from CLI, jobs, or projection output that
  decides one or more facts. This replaces the overloaded "Topo command" term.
- **Topo Fact**: a canonical, content-addressed domain/protocol record. This is
  what older docs and code call an event.
- **FactId**: `BLAKE3(canonical_fact_bytes)`.
- **CanonicalFactBytes**: the canonical bytes hashed into a `FactId`.
- **FactModule**: a module that owns fact codecs, intent deciders, projectors,
  tables, and queries.
- **FactProjector**: a deterministic transform from fact plus context to
  projection output.
- **Projection**: rows, labels, emitted facts, outbox intents, and purges.

The intended flow is:

```text
Crux Event
  -> Topo Intent
  -> Topo Facts
  -> Fact admission/projection
  -> Projection
  -> Crux Effects
```

Avoid bare `Command` in Topo APIs. Reserve `Command` for Crux and use `Intent`
for Topo domain requests.

## Post-Crux Rules

These are the rules the codebase should enforce once Crux is introduced.

### Naming Rules

- Use Crux names only for Crux concepts: `App`, `Event`, `Command`, `Effect`,
  `Model`, and `Operation`.
- Use Topo names for the substrate: `Intent`, `Fact`, `FactId`,
  `CanonicalFactBytes`, `FactRecord`, `FactModule`, and `FactProjector`.
- Do not introduce new bare `EventRecord`, `Command`, or `Operation` types in
  Topo modules. If an old name remains during migration, document it as a
  compatibility alias and remove it quickly.

### Boundary Rules

- `main.rs` is shell glue only: parse CLI, dispatch Crux events, interpret
  effects, print output, and set process exit status.
- `network.rs` owns TCP mechanics only: connect, listen, frame, read, write,
  buffering, and backpressure.
- `store.rs` owns storage mechanics only: transactions, table access,
  migrations, and effect interpretation.
- The Crux app owns runtime orchestration: ordering, continuations, bounded
  drains, shell replies, and follow-up Crux events.
- Fact modules own protocol/domain semantics: codecs, intent deciders,
  dependency declarations, projector logic, table declarations, and module-owned
  context request semantics.
- Core/kernel code may route through a module registry, but must not import
  concrete connection, sync, content, or identity modules directly.

### IO Rules

- Pure planners, intent deciders, and fact projectors must not open SQLite,
  read/write sockets, call RNG, read clocks, print, or spawn tasks.
- Any required IO must be represented as a typed Crux effect.
- Use `Command::request_from_shell` when later work depends on the shell reply.
- Use `Command::notify_shell` only for fire-and-forget effects where failure
  does not affect correctness.
- Shell interpreters must feed replies back as Crux events; they must not call
  fact module logic directly.

### Context Rules

- Every projector receives a core default context: parsed fact, immediate
  dependency facts, labels, and generic origin metadata.
- If more state is needed, first add explicit dependency fields or labels.
- Custom typed context is allowed only for module-owned read models that are too
  large or index-shaped for bounded deps/labels.
- Prefer custom job context over custom projector context for large indexed
  responders. Negentropy compare/have/need response generation should be a sync
  job because it needs summaries, bucket ids, presence checks, event bytes,
  batching, and backpressure.
- Connection and bootstrap validation should use first-level deps, labels, and
  origin metadata unless a future design proves those are insufficient.
- The core may route custom projector/job context requests/results, but it must
  not inspect module-specific fields.

### Projection Rules

- Fact projection returns declarative output only: rows, labels, emitted facts,
  outbox intents, and purges.
- Projectors do not write transport bytes. Sending happens through outbox or
  transit facts interpreted by shell/network effects.
- Projectors do not recursively drain ready work. The Crux app/control loop owns
  bounded drain scheduling.
- Emitted facts are normal facts: canonical bytes, normal fact ids, admission,
  dependency checks, and projection.

### Scheduler And Job Rules

- Jobs are not background threads that call modules directly. They are Crux
  events plus typed store/network/clock effects.
- The kernel should run a bounded rotating scheduler over work lanes such as
  `ReadyFacts`, `Outbox`, `InboundBytes`, `Timers`, and `ModuleJobs`.
- A `SchedulerWake` Crux event advances the scheduler cursor and asks the shell
  to claim bounded work from one lane. Reserve `TimerFired` for actual
  wall-clock timers:

```rust
enum WorkLane {
    ReadyFacts,
    Outbox,
    InboundBytes,
    Timers,
    ModuleJobs,
    SyncIndexCatchup,
    SyncResponders,
}

enum StoreOperation {
    ClaimWork { lane: WorkLane, limit: usize },
}
```

- The store shell owns atomic claim, lease, retry, backoff, and mark-done
  mechanics.
- The Crux model owns fairness cursor, per-lane budgets, and whether to schedule
  another tick.
- Fact modules own module-job meaning. A module job should be a registered
  planner that returns intents, facts, projections, outbox work, or a reschedule
  request.
- Indexed responder work, such as negentropy compare/have/need responses, should
  be processed as module jobs rather than inside fact projectors.
- Do not write an unbounded `while queues_not_empty { drain_everything(); }`
  loop. Every unit of work must be bounded by rows, bytes, or time and must
  return control to the Crux app.

The intended flow is:

```text
Crux Event::SchedulerWake
  -> StoreEffect::ClaimWork(lane, limit)
  -> Crux Event::StoreReply(ClaimedWork)
  -> dispatch claimed work through fact registry
  -> Store/Network/Clock/Rng effects
  -> mark done/retry/reschedule
  -> optional follow-up SchedulerWake
```

### Testing Rules

- Pure module tests should assert intent-to-facts and fact-to-projection behavior
  without constructing a real store or socket.
- Crux transcript tests should drive Crux events, inspect emitted effects,
  resolve shell requests with fake replies, and assert the exact continuation
  sequence.
- Boundary tests should fail if `main.rs` imports store, pipeline, control-loop,
  network protocol, or concrete fact modules.
- Guardrail searches should check that fact projectors and planners do not use
  `rusqlite`, `TcpStream`, `TcpListener`, RNG, clock, or stdout directly.
- Existing black-box CLI/network tests remain the proof that the real shell
  interpreters still work end to end.
- Sync tests should assert that responder work is deferred while the negentropy
  cursor is behind, then processed after `SyncIndexCatchup` advances it.

### Migration Rules

- Migrate one public workflow at a time behind Crux, starting with `generate`.
- The facade step may wrap old behavior, but every follow-up step should remove
  ambient `Store` and network access from planners and modules.
- A migration step is incomplete without realistic tests for the new boundary.
- Do not leave parallel old/new implementations of the same concern. Retire the
  old path in the same commit that proves the new path.
- Treat compile-only scaffolding as unfinished work.

## What The Prototypes Showed

Six standalone Crux prototypes were used to compare shapes. Their throwaway
crates have been removed; the durable output is this summary plus the real
`poc-8` implementation and tests.

| Experiment | Result | What it proves | Main limitation |
| --- | --- | --- | --- |
| `01_facade_wrap_pipeline` | `2 passed` | Crux can wrap the current store -> drain -> print flow and make the ordering explicit. | Decouples the CLI, but does not make the pipeline/event modules IO-less. |
| `02_pure_planner_effects` | `2 passed` | A pure planner can return Store, Network, and Drain plan steps; Crux turns them into typed effects. | Uses notify-only effects, so completion/error paths are not modeled. |
| `03_module_deciders` | `4 passed` | Event-module-like deciders/projectors can stay deterministic and separate from Crux messages. | Needs real event ids, admission status, and apply failure semantics. |
| `04_effect_shell` | `2 passed` | Explicit Store/TCP/RNG/Clock/Stdout operations can be interpreted by a fake shell with transcript tests. | Adds boilerplate for operation/reply enums and `From<Request<_>>` implementations. |
| `05_sync_state_machine` | `2 passed` | Crux can orchestrate protocol messages while a pure connection/sync state machine owns transitions. | The prototype is single-peer and omits retries, backoff, and backpressure. |
| `06_test_harness_guardrails` | `4 passed` | Fake shell transcript tests and dependency-drain invariants can constrain LLM edits. | Runtime invariant checks are not full formal proofs. |

## Recommended Architecture

### 1. Use Crux For Kernel Orchestration

Create a `KernelApp` around the current `pipeline` and `control_loop`
responsibilities:

```rust
pub enum KernelMsg {
    Cli(CliCommand),
    FrameReceived { origin: Addr, bytes: Vec<u8> },
    DrainReady,
    Store(StoreReply),
    Network(NetworkReply),
    Rng(RngReply),
    Clock(ClockReply),
}

pub struct KernelModel {
    pub draining: bool,
    pub active_streams: ActiveStreams,
    pub last_error: Option<String>,
}
```

Crux `update` should decide what happens next and return typed effects. It
should not open SQLite, read sockets, generate randomness, or print.

### 2. Make IO Explicit With Operation Enums

Prefer explicit Crux operations over `Store` traits in core code:

```rust
pub enum StoreOperation {
    LoadMaxTimestamp,
    AdmitRecords { records: Vec<EventRecord> },
    LoadReadyBatch { limit: usize },
    ApplyProjection { event_id: EventId, projection: Projection },
    LoadIngressContext { origin: Addr, transit: Vec<u8> },
    LoadSyncContext { connection_id: EventId },
}

impl crux_core::capability::Operation for StoreOperation {
    type Output = StoreReply;
}
```

This is stronger than passing a read trait because a trait can hide IO anywhere.
With effects, every store lookup is visible in tests and every reply has to be
handled explicitly.

Use `Command::request_from_shell` when later work depends on the reply. Use
`Command::notify_shell` only for fire-and-forget operations such as logging or
best-effort notifications.

### 3. Split Pipeline Into Plan And Continue Functions

Current functions such as `pipeline::ingest_frame(&Store, ...)` need store
context. In the Crux shape, split them:

```rust
fn plan_ingest_frame(origin: Addr, bytes: Vec<u8>) -> StoreOperation;

fn continue_ingest_frame(ctx: IngressContext) -> Result<PipelinePlan, Error>;
```

The first function asks the shell for context. The second function is pure and
returns a plan:

```rust
pub struct PipelinePlan {
    pub store: Vec<StoreOperation>,
    pub network: Vec<NetworkOperation>,
    pub follow_up: Vec<KernelMsg>,
}
```

This is the main migration needed to make `pipeline.rs` IO-less.

### 4. Keep Event Modules Below Crux

Event modules should become pure domain components:

```rust
fn decode(bytes: &[u8]) -> Result<TypedEvent, DecodeError>;
fn dependencies(event: &TypedEvent) -> Vec<EventId>;
fn decide(command: Command, context: ModuleContext) -> Result<Vec<CanonicalEvent>, Rejection>;
fn project(event: TypedEvent, context: ProjectionContext) -> Result<Projection, ProjectionError>;
```

Crux messages can carry canonical bytes or event ids, but canonical events
should not become Crux messages. Otherwise the app loop turns into a giant
protocol dispatcher and Crux starts owning the domain vocabulary.

### 5. Use Cursor-Driven Negentropy Jobs

Negentropy should be a module-owned derived index over applied shared facts, not
state that every shared-fact projector updates directly. Shared fact projectors
should not know that negentropy exists.

The recommended flow is:

```text
shared Topo Fact applied
  -> facts table records apply_seq

sync index catch-up job
  -> reads applied shared facts where apply_seq > cursor
  -> updates sync/negentropy index rows
  -> advances cursor in the same transaction

compare/have/need fact projected
  -> validates default deps, labels, origin, and connection shape
  -> writes deterministic sync_work row with required_index_seq

sync responder job
  -> waits until negentropy cursor >= required_index_seq
  -> queries sync/negentropy indexes with bounded budget
  -> emits response facts and/or outbox intents
  -> marks sync_work done/retry/reschedule
```

The generic pipeline only needs to assign an apply order and expose applied
shared facts to module jobs. It must not know buckets, summaries, or negentropy
math.

```rust
struct AppliedSharedFact {
    apply_seq: u64,
    fact_id: FactId,
    scope: FactScope,
    workspace_id: Option<WorkspaceId>,
    canonical_len: usize,
    bucket: u8,
    fingerprint: [u8; 32],
}

struct NegentropyCursor {
    scope_key: SyncScopeKey,
    last_indexed_apply_seq: u64,
}
```

Sync work rows are module-owned queue rows:

```rust
enum SyncWorkKind {
    CompareResponse { remote_summary: Summary },
    HaveResponse { ids: Vec<FactId> },
    NeedResponse { ids: Vec<FactId> },
}

struct SyncWork {
    work_id: WorkId,
    trigger_fact_id: FactId,
    connection_id: ConnectionId,
    required_index_seq: u64,
    kind: SyncWorkKind,
    status: WorkStatus,
}
```

The sync responder job receives custom job context, not custom projector context:

```rust
enum SyncWorkContext {
    CompareResponse {
        local_summary: Summary,
        ids_by_differing_bucket: Vec<(BucketId, Vec<FactId>)>,
        connection_scope: ConnectionScope,
    },
    HaveResponse {
        presence: Vec<(FactId, bool)>,
        connection_scope: ConnectionScope,
    },
    NeedResponse {
        fact_bytes: Vec<(FactId, CanonicalFactBytes)>,
        unavailable: Vec<FactId>,
        connection_scope: ConnectionScope,
    },
}
```

Important invariants:

- Use `apply_seq`, not timestamps, for negentropy cursor order.
- Advance negentropy index rows and cursor in one transaction.
- Make index updates idempotent, e.g. unique `(scope_key, fact_id)` rows.
- Do not process `sync_work` until the relevant cursor has reached
  `required_index_seq`.
- Recheck connection/workspace authorization before returning bytes for
  `NeedResponse`.
- Prefer per-workspace indexes and aggregate for a connection's allowed scopes,
  rather than maintaining per-connection indexes.

This replaces the earlier custom-projector-context idea for negentropy
responders. The custom context still exists, but at the job boundary where large
indexed reads, batching, retries, and backpressure belong.

### 6. Model Sync And Connection Session Flow Explicitly

The sync and connection modules should expose transition functions like:

```rust
fn step(state: SyncState, input: SyncInput) -> Transition<SyncState, SyncAction>;
```

Crux should map `SyncAction::SendFrame` into a `NetworkOperation`; the state
machine should not write TCP frames itself. This fits the current rule that the
network layer owns framing and transport mechanics, while protocol semantics
belong below the kernel.

Do not force every sync helper into a state machine. Set reconciliation helpers
such as "which buckets differ?" or "which ids are missing?" should stay as plain
pure functions. The state-machine shape is for session memory and phase logic:
handshake state, current connection id, pending requested ids, frames in flight,
retry counters, `more` frames, close behavior, and drain completion.

## Migration Plan

1. Add a `kernel` or `app` module with `KernelMsg`, `KernelModel`,
   `KernelEffect`, and shell operation enums. Keep it thin at first.

2. Wrap one existing CLI flow with Crux as a facade. `generate` is the best
   first candidate: generate records, admit records, drain ready, print output.
   This proves the shell loop and output formatting without touching sync.

3. Move `main.rs` behind the shell boundary. `main.rs` should parse args,
   dispatch `KernelMsg::Cli`, interpret effects, and print output. It should
   stop importing `Store`, `pipeline`, `control_loop`, `network`, and
   `event_modules` directly.

4. Convert `pipeline.rs` functions from `&Store` callers into pure planners
   plus continuation functions that consume DTO context loaded by store effects.

5. Refactor event module commands so they do not call `Store` directly.
   Commands should decide canonical events or projections from explicit
   context. Admission, apply, and module-row writes should be shell effects.

6. Move connection and sync flow control into pure state machines. Crux remains
   the outer orchestrator; the state machines own protocol transition logic.

7. Implement sync/negentropy as cursor-driven module jobs: apply shared facts
   with `apply_seq`, run `SyncIndexCatchup`, then process compare/have/need
   responder work only once the cursor reaches each work row's required
   frontier.

8. Add guardrail tests before broad migration. Include transcript tests for
   effects, boundary tests that fail if `main.rs` imports kernel internals, and
   dependency-drain invariant tests.

## Testing Strategy

Use three layers of tests:

1. Pure unit tests for event modules and planners. These should not construct a
   `Store`, bind TCP, call RNG, or read the clock.

2. Crux transcript tests with fake shell interpreters. Drive a `KernelMsg`, pull
   emitted effects, resolve requests with fake replies, and assert the exact
   effect/reply sequence.

3. Black-box CLI/network tests for the real shell. Keep the existing sync tests,
   but after migration they should exercise shell interpreters rather than
   direct CLI access to kernel internals.

Useful permanent guardrails:

```text
rg "topo::store::Store|topo::pipeline|topo::control_loop|topo::event_modules" src/main.rs
rg "crate::store::Store|rusqlite|TcpStream|TcpListener" src/event_modules
rg "crate::store::Store|TcpStream|TcpListener" src/pipeline.rs
```

Those searches should be empty, except for documented shell/interpreter files.

## Risks And Tradeoffs

- Crux adds boilerplate. Every shell operation needs an `Operation`, reply type,
  effect wrapper, and interpreter case.

- Effect ordering must be intentional. Independent `Command`s may run
  concurrently; use request continuations when later effects depend on earlier
  replies.

- The first facade migration can hide old coupling. It is useful for proving the
  shell boundary, but it should not be mistaken for the final architecture.

- Store context DTOs need careful design. If they are too broad, the core sees a
  database-shaped snapshot. If they are too narrow, the update loop gets noisy.

- Apply semantics need to be precise. Projection should happen only after the
  shell confirms admission/apply status, unless the operation is explicitly
  speculative and reversible.

## Decision

Adopt Crux incrementally, but aim for the `02_pure_planner_effects` plus
`04_effect_shell` pattern as the target. Use `01_facade_wrap_pipeline` only as
the first compatibility step. Use `03_module_deciders` to guide event-module
refactors, `05_sync_state_machine` for connection/sync flow, and
`06_test_harness_guardrails` for permanent tests.

The north star is simple: most `poc-8` code should be plain functions over
plain data. Crux should sit at the boundary where those functions request IO.

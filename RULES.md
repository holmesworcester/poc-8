# Rewrite Rules

## Commands Live In Event Modules

Commands belong under `event_modules`, alongside the event types, codecs,
projectors, queries, and module-owned tables they operate on.

CLI, RPC, jobs, and other adapters should dispatch into module commands instead
of constructing canonical event bytes directly. Adapters own input/output shape;
event modules own protocol and domain semantics.

The intended shape is:

```text
event_modules/<domain>/<module>/commands.rs
  command(ctx, input, writer) -> CommandOutput

event_modules/<domain>/<module>/codec.rs
  Event <-> CanonicalEventBytes

event_modules/<domain>/<module>/projector.rs
  EventWithContext -> Projection
```

## Event Writes Return Event IDs

The substrate should expose an event writer API that returns the event id from
the write path, including after projection, so commands can chain writes without
re-querying or inferring ids from projected state.

Use two levels of write API:

```text
append_event(bytes) -> Admission {
  event_id,
  status: Ready | Blocked { blocked_by } | Duplicate { status },
}

append_apply(bytes) -> WriteResult {
  event_id,
  status: Applied | AlreadyApplied | Blocked { blocked_by },
  emitted: Vec<EventId>,
}
```

Commands that need a prior event to be semantically present before constructing
the next event should use `append_apply` and require an applied result:

```text
let workspace = writer.append_apply(workspace::create(...))?.require_applied()?;

let account = writer.append_apply(account::create(
  workspace.workspace_id,
  workspace.event_id,
  username,
))?.require_applied()?;
```

Commands that intentionally create pending work, such as accepting an invite
before the invite event has synced, may use `append_event` or accept a blocked
`append_apply` result and surface that event id as pending.

## Apply Only The Command's Own Chain

Commands must not call a broad `drain_until_idle` loop to make chaining work.
That applies unrelated ready events and makes command behavior depend on ambient
queue state.

For command chaining, apply exactly the event the command just wrote, in order,
inside the command transaction. The global control loop remains responsible for
draining unrelated ready work.

## Ownership Boundary

The event writer owns storage mechanics:

- transactions
- canonical event admission
- dependency checks
- projection apply
- labels
- outbox rows
- emitted event ingestion
- returned event ids

Module commands own semantic construction:

- what command input means
- which state queries are required
- which canonical events to create
- how to interpret `Applied`, `AlreadyApplied`, or `Blocked`

All state mutation still goes through canonical events and projectors.

## Event Modules Use The Clean Contract

Event modules must target the new kernel contract directly. Do not introduce
compatibility adapters for old `state`, `runtime`, queue, or transport APIs.
If an existing module depends on old core machinery, refactor the module until
the dependency is gone.

The module shape is:

```text
event module =
  codec
  deps
  projector
  tables
  commands/queries where needed
```

The universal contract is:

```text
CanonicalBytes -> Event
Event -> Vec<EventId>
(Event, Context) -> Projection

Projection =
  rows
  labels
  outbox
  emitted_events
  purges
```

Event modules must not:

- import `crate::runtime`
- import old `crate::state` internals
- know queue table names or pipeline phase names
- start jobs or drive the control loop
- perform transactions
- call global drain/apply functions
- write SQLite directly, except for data-only table declarations if that
  remains the chosen schema representation
- know transport implementation details

Event modules may:

- decode and encode canonical event bytes
- declare dependencies
- declare owned tables and indexes
- query through a narrow read context
- append events through a narrow writer from commands
- return declarative projector output: rows, labels, outbox operations,
  emitted events, and purges

Strict checks should stay true:

```text
rg "crate::runtime" src/event_modules
rg "crate::state" src/event_modules
rg "rusqlite|Transaction" src/event_modules
```

These should return no matches unless a match is explicitly documented as a
data-only schema declaration.

## Sync And Connection Are Event Modules

Sync and connection protocol logic must not be custom code hidden in the CLI,
network transport, runtime loop, or kernel. It must be expressed as properly
decoupled event modules along the same lines as the structured modules in
`poc-8/src/event_modules`.

This includes:

- connection setup and supporting connection events
- connection metadata and observed/self addresses
- key, invite, and bootstrap protocol events
- sync compare/have/need events
- dep-aware negentropy events and tree/cache maintenance
- request/response behavior that can be represented as event emission

The kernel may:

- admit canonical events
- compute event ids
- check dependencies
- apply pure projector output
- enqueue outbox rows
- receive framed event bytes
- send framed event bytes
- schedule bounded work

The kernel must not:

- contain a bespoke sync coordinator
- contain connection protocol state machines
- inspect sync ranges or negentropy trees except through module-declared tables
- special-case have/need/compare behavior outside event modules
- bypass event admission for protocol messages
- use side-channel protocol messages when an event can express the fact

The network layer owns only transport mechanics: framing, wrapping, sending,
receiving, buffering, and backpressure. It does not own sync or connection
semantics.

## Realness Bar

Functional tests and demos must exercise the production boundary they claim to
prove. Do not call a shortcut and name it sync, network, auth, storage, or CLI
if the real path would cross a different boundary.

Use these rules:

- Functional tests are black-box by default. They should drive the public
  `topo` binary and assert observable behavior.
- CLI tests run the actual `topo` binary.
- Networking tests use real networking through the CLI. If a test claims sync,
  transport, or multi-node behavior, it must move bytes across real sockets with
  production framing and the same outbox/inbox adapters used by the CLI.
- Sync tests move canonical event bytes through outbox, wire frames, receive,
  ingest, and project. They must not copy rows from another database.
- The only normal exceptions are pure functional projector tests and module
  command tests. Projector tests may assert declarative projection output.
  Command tests may use a fake writer/read context to prove event construction,
  status interpretation, and command chaining. These tests are useful local
  checks, but they do not prove product functionality; feature completion must
  be proven by black-box tests through the public boundary with real networking
  when networking is involved.
- Static boundary tests are allowed. They may scan source text or public module
  structure to enforce architectural rules, but they are not functional proof.
- Harnesses may create temp directories, spawn processes, choose ports, and
  assert output. They must not create kernel tables or apply domain semantics.
- Toy adapters are allowed only for small unit tests that name the fake
  explicitly, such as projector math or scheduler ordering. They are not
  acceptable evidence for end-to-end behavior.
- If a feature is not real yet, say so in the command name, test name, or
  documentation. Prefer deleting fake coverage over keeping a test that certifies
  the wrong boundary.
- A passing test should fail if the production codec, queue, network frame,
  database adapter, or projector path is broken.

## CLI Contract Decoupling

CLI behavior and CLI tests should express product contracts, not core
implementation contracts. The CLI surface should be stable enough that the old
core and new kernel can both satisfy the same user-visible tests while internal
queues, projection phases, and storage layout change underneath.

CLI tests should cover:

- workspace creation and joining
- messages, reactions, and deletions
- file send and save
- invite flows
- multi-node sync and transport behavior
- observable output, exit codes, and durable user-visible state

CLI tests must not depend on:

- internal queue names
- internal table names
- projection phase names
- exact sync round internals
- whether an event became ready through one queue or another
- whether storage is backed by the old state modules or the new kernel

The CLI test harness may spawn processes, allocate temp directories, choose
ports, and assert command output. It must not create kernel tables, insert rows,
copy databases, simulate sync, or decode private storage layout.

Prefer stable machine-readable CLI outputs for tests where ambiguity matters:

```text
topo status --json
topo events list --json
topo workspace list --json
topo message list --json
topo file list --json
topo daemon status --json
```

The success criterion is that realistic CLI tests can run unchanged against the
old core and the replacement kernel.

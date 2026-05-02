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

Do not create `event.rs` files in event modules. The typed event struct belongs
in `codec.rs` with the canonical encode/decode logic. Commands belong in
`commands.rs`.

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
- declare owned tables, indexes, and storage class (`durable`, `memory`, or
  `temp`)
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
- deterministic connection-scoped send-intent events
- dep-aware negentropy events and tree/cache maintenance
- request/response behavior that can be represented as event emission

The kernel may:

- admit canonical events
- compute event ids
- check dependencies
- apply pure projector output
- enqueue outbox rows
- receive framed transit bytes
- execute `TransportSend { target, bytes }` effects by packing
  module-produced bytes into TCP frames and writing sockets
- schedule bounded work

The kernel must not:

- contain a bespoke sync coordinator
- contain connection protocol state machines
- create transit blobs, choose transit encryption/padding/key rules, or decide
  which events are authorized on a connection
- inspect sync ranges or negentropy trees except through module-declared tables
- contain negentropy, compare/have/need, or sync-range vocabulary in
  `pipeline.rs`, `control_loop.rs`, or `network.rs`
- special-case have/need/compare behavior outside event modules
- bypass event admission for protocol messages
- use side-channel protocol messages when an event can express the fact

The network layer owns only transport mechanics: TCP framing, sending,
receiving, buffering, and backpressure to concrete targets such as `(ip, port)`
or socket ids. It does not own sync, connection, transit wrapping, or
authorization semantics.

Connection-scoped protocol events are real canonical events. Their
`connection_id` must be inside their canonical bytes, and their id is the normal
`BLAKE3(canonical_event_bytes)`. They may be transient, but they still use the
same codec/projector/outbox rules as other events.

Durable data events are not pushed to peers on creation. Durable data transfer
is queued only through deterministic connection-scoped send intent, e.g.
`SendEvent(connection_id, inner_event_id)`, usually emitted in response to a
`NeedId` event. The outbox dedupes this deterministic intent by
`(connection_id, send_event_id)`. The connection/transit module projects that
intent into a transit blob and returns a `TransportSend { target, bytes }`
effect; the kernel only frames and writes those bytes.

`TransportSend.target` is a transport route, not a semantic connection id. Use
an address or socket target such as `(ip, port)` or `socket_id`. If a module
starts from `connection_id`, it must resolve that connection to a transport
target before emitting the effect.

## No Fake Or Placeholder Encryption

Never implement fake, placeholder, pass-through, XOR, reversible toy, or
"encrypted in name only" encryption.

If a path requires confidentiality, integrity, authentication, forward secrecy,
or key erasure, use a real reviewed cryptographic construction through a
well-maintained library and document the exact primitive, nonce/key rules,
associated data, and failure behavior. If the real construction is not ready,
leave the feature unimplemented and make the boundary explicit.

Code, tests, CLI output, table names, event names, and docs must not call bytes
encrypted, sealed, secret, private, wrapped, or protected unless the production
path actually enforces the claimed property. A framing function may be called a
frame. It must not be called encryption.

Tests must not prove crypto behavior with fake keys, fake ciphers, identity
transforms, or deterministic toy encryption. They may use deterministic test
vectors for real cryptographic primitives. They may use fakes only below the
cryptographic boundary, such as a fake transport that carries already-encrypted
bytes without inspecting or transforming them.

When real encryption is added, required tests include:

- round-trip tests against real test vectors
- tamper rejection for ciphertext, nonce, associated data, and key id
- wrong-key rejection
- nonce uniqueness or misuse-resistance checks, depending on the primitive
- boundary tests proving plaintext does not cross storage, wire, or log surfaces
  that claim encryption
- restart/retry tests for key lookup, rotation, revocation, and expiry behavior

## Realness Bar

Functional tests and demos must exercise the production boundary they claim to
prove. Do not call a shortcut and name it sync, network, auth, storage, or CLI
if the real path would cross a different boundary.

Do not stop working at a partial, fake, or merely scaffolded result. A task is
not complete until the claimed behavior is real through the production boundary,
proven with an appropriate black-box test, and any remaining fake or missing
piece is either removed or explicitly marked out of scope. If the real result
cannot be completed in the current branch, stop claiming the feature works and
leave a concrete blocker instead of passing placeholder coverage.

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

## Fresh Minimal Rewrite Guardrails

The fresh rewrite starts from `plan.md` and `RULES.md` only. Add code back only
when it serves the minimal black-box path:

```text
topo --db PATH connect IP PORT
topo --db PATH generate NUM_EVENTS EVENT_SIZE_BYTES
topo --db PATH sync
```

A read-only `count`/`status` command is allowed solely so black-box tests can
assert eventual convergence and measure sync-start to all-counted time.

Keep the kernel boring:

- `network` owns TCP, frame boundaries, connection attempts, and byte IO only.
- `store` owns durable bytes, peer addresses, and generic event-set reads/writes
  only.
- `event_modules/content` owns content event construction, codec, and projection.
- `event_modules/sync` owns all negentropy, compare/have/need/range decisions,
  connection-scoped sync events, and sync jobs.

The kernel should be a pleasure to read: small files, direct control flow,
plain names, and no hidden protocol cleverness. A reader should understand the
kernel as an executor, durable byte store, and TCP byte mover without learning
the content or sync protocols. All real domain and protocol logic belongs in
event modules.

Do not put sync protocol vocabulary or decisions in core files. In particular,
`store`, `network`, and CLI glue may not decide what a negentropy range means,
when to split a range, which ids are needed, or which events satisfy a sync
request. They may only call event-module functions and move returned bytes.

Do not put transit wrapping in `network`, `store`, CLI glue, or sync modules.
Connection/transit modules create transit blobs; the kernel creates only generic
TCP frames around module-produced bytes.

Event modules stay directory-shaped:

```text
event_modules/<name>/commands.rs
event_modules/<name>/codec.rs
event_modules/<name>/projector.rs
event_modules/<name>/queries.rs   # only when needed
event_modules/<name>/mod.rs
```

Never create `event.rs`.

Functional proof for this rewrite means black-box CLI tests that spawn the real
`topo` binary, use real TCP sockets, start `sync`, wait through the CLI-observed
event count, and report both events/s and MiB/s for perf cases.

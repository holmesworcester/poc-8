# Topo rewrite

I want to rewrite topo with clarity on:

* interfaces
* the invariants they guarantee
* decoupling
* realms of responsibility (and *non* responsibility)
* event-based networking
* what crucial design decisions contributors and agents must take not to break 

See appendix for documentation style rules and references.

# Connection Bootstrap Simplification

Bootstrap for identity invites is now ordinary connection establishment. The
invite link gives the acceptor enough local authority to create a connection
request and enough routing information to dial the invite address. It does not
open a separate invite-key sync lane, and bootstrap never carries workspace
identity ancestry.

The causal graph is:

```text
invite link -> local invite_secret
local transit endpoint + initiator ephemeral -> request transcript
invite private key + invite id + request transcript -> signed connection_request
connection_request + responder endpoint + responder ephemeral -> connection_response
connection_response -> ordinary connection transit/sync
ordinary sync -> workspace identity ancestry and pending join facts converge
```

There is no cycle: identity ancestry can depend on ordinary sync after the
connection response, but connection establishment does not depend on identity
ancestry. The connection response event id is the connection id. The response
stores the connection secret derived from the invite secret, signed request
transcript, initiator ephemeral key, responder ephemeral key, and responder
static endpoint key; subsequent connection transit decrypts by loading that
response event.

Identity invite acceptance first establishes the connection, then records a
local `invite_accepted` fact and admits the proposed user/device join facts.
Those join facts may remain blocked until ordinary connection sync brings in
their remote dependencies. The inviter learns them through the same normal
connection sync path.

The invite address is the only bootstrap route until peer discovery exists. The
stored local invite-secret event includes the invite link address, so the local
connection-request projector can write a durable pending connection attempt
row. Received connection requests with an advertised daemon address project a
durable pending connection response row. The `connection` worker drains those
queues: it retries normal connection requests to invite addresses, creates
connection responses for validated inbound requests, sends handshake frames via
`transit_out`, and records the invite address as the initial route once a
connection response projects. It is not peer discovery, not route negotiation,
not an invite ancestry exchange, and not a special sync round.

The connection worker is also the future policy home for peer selection,
connection-count targets, retry/backoff, stale connection cleanup, and route
choice once peer discovery exists. Transit workers stay at the byte boundary:
`transit_in` unwraps/authenticates inbound frames into canonical events, and
`transit_out` wraps/sends opaque outbound frames.

Normal sync is one-way per transit-out send. Incoming sync frames are admitted
and projected into `sync.in`; the sync worker later queues responses, and
`transit_out` sends them on routed connections. `transit_out` still drains and
wraps per connection, but coalesces all frames for the same socket address into
one TCP stream per outbound pass so multiple workspace routes to the same
daemon do not build an accept backlog. Same-stream replies are reserved for the
connection handshake response only.

# Content Key Wrap Derivation

Key sharing is an ordinary event/dependency graph, not a manual side channel.
A signed `key_wrap` event is shared. Its projector validates signer membership,
removal frontier, and recipient key against dependency context, then writes:

```text
key_wrap row
key_secret_commitment row
pending_key_unwrap row
```

The projector never opens ciphertext and never creates local secret facts. The
`pending_key_unwrap` row is the explicit worker queue. The encryption worker
drains that queue, opens the wrap only if matching local recipient private
material exists, and admits the resulting `local_key_secret` as a normal
local-only event through the common event pipeline. Once that local-only event
applies, the normal dependency-unblock worker wakes any encrypted content
events that were blocked on the secret. No test or daemon path should need to
run `key-derive` to make progress; `key-derive` is only a bounded diagnostic or
offline worker invocation.

# Identity/Auth Graph Port Plan

This branch ports the latest `poc-7` identity and auth graph behavior into
`poc-8`, but the implementation must be a `poc-8`-native translation. `poc-7`
is a behavior reference only. `poc-8` module boundaries, storage shape,
command/projector split, CLI locality, and worker rules are authoritative.

The worktree for this task is:

```text
/home/holmes/poc-8-identity-auth-graph
branch: codex/poc8-identity-auth-graph
```

Do not implement this in the main `/home/holmes/poc-8` worktree.

## Active Branch TODOs

- Before merge, bring current `master` into this branch and adapt any local
  workers to the newer worker organization model from master.
- Deletion forward secrecy still requires real encrypted message/reaction
  events plus durable purge of obsolete event bytes and local secrets after
  durable deletion/frontier facts preserve semantic state.

### Design note: file descriptor `root_hash` is plaintext

In the encrypted file shape, `filename` and `mime` ride in an authenticated
ciphertext slot keyed by the parent message's content key; `root_hash` (the
BLAKE3 root of the per-slice ciphertexts) is left plaintext in the descriptor's
canonical bytes.

**Reasoning**: encrypting `root_hash` would force the slice projector to call
decrypt before BAO verification, which violates the "projectors do not do
crypto" rule (`event_module_projectors_do_not_do_transit_or_crypto_work`).
With `root_hash` plaintext, the slice projector reads it from the descriptor's
clear-text fields and verifies slice ciphertext directly, no decryption
needed at projection time.

**Why the leak is benign here**: `root_hash = blake3(ciphertext)` does not
itself reveal plaintext; it is at most an offline-verifier for guesses
combined with a recovered key. Pre-delete, the ciphertext is on disk too, so
`root_hash` adds no information. Post-delete, the entire file event is
purged through `content_purge`, including `root_hash`, so the
forward-secrecy property still holds against an on-disk attacker.

**Alternatives considered**: (a) seal `root_hash` and have the slice projector
decrypt the descriptor — clean from a leak perspective, but breaks the
projector boundary. (b) duplicate `root_hash` into every slice's canonical
bytes — preserves the boundary but inflates per-slice canonical bytes by 32
and creates a content-id encoding circle to reason about. The current shape
is the right tradeoff for this threat model.

### Design note: encrypted file slice proof slots

The multi-slice file proof slot fix is copied from poc-7 commit
`a064aa97 Fix atomic bao file sends and large-send RSS`, translated to
poc-8's encrypted slice shape. A full slice's ciphertext, not its plaintext,
is capped at 256 KiB; the per-slice plaintext budget is therefore
`256 KiB - XChaCha20-Poly1305 tag`. That keeps every full-slice BAO range
aligned after encryption, so the fixed proof slot remains
`ciphertext budget + BAO overhead` instead of growing unpredictably for
off-boundary ranges. The descriptor still records plaintext `slice_bytes`, and
the slice projector derives the ciphertext range as `slice_bytes + tag`.

The coarse performance bisect points at `1b1992a Move daemon to explicit
worker pipeline`. The small benchmark was `generate-deps 1000 1`: its direct
parent `59d2b02` ran in about `0.09s` (~11.1k events/s), while `1b1992a` ran
in about `2.43-2.47s` (~405 events/s), and later heads stayed around the same
speed. The likely mechanism is that command admission stopped processing a
proposed event batch in one transaction and instead enqueued through
`canonical.in`, then drained via `event_admission::run(... limit: 1)` once per
proposed event. That adds per-event queue encode/decode and transaction
overhead. This is a coarse common-pipeline benchmark, not the exact encrypted
message perf harness, but it is enough to identify the first likely throughput
cliff.

## Scope

In scope:

- `workspace`
- `signed`
- `user_invite`
- `device_invite`
- `user`
- `endpoint_secret`
- `endpoint_shared`
- `admin`
- `invite_secret`
- `invite_accepted`
- command flows for workspace creation, user invite creation, user invite
  acceptance, device-link invite creation, device-link acceptance, and admin
  grant
- local-only events for endpoint private keys and invite/bootstrap secrets
- explicit duplicate-join rejection when one endpoint tries to join the same
  workspace twice

Out of scope:

- `tenant`
- `peer_shared` as a concept or module name
- key history
- key sharing
- key rotation
- key request or key repair
- content encryption
- content-key bootstrap
- iroh
- p7 transport runtime, p7 peering runtime, or p7 SQL projection pipeline

Do not pull key-history or key-sharing implementation into this slice. If a
latest p7 identity event contains a `key_history_event_id` field, either omit
that field in the p8 event shape or keep it only as an inert/reserved zero field
if an explicit compatibility decision requires it. It must not become a
dependency in this slice.

All crypto in this slice must be real production crypto. Signed auth events must
use real signature primitives and real verification; local secret or private-key
events must store actual secret material for the primitive they claim. Do not add
placeholder signatures, mock cryptographic checks, deterministic toy keys, fake
encryption, or TODO paths that pass auth until a future crypto implementation.
If a real primitive is not decided or not ready, leave that behavior out of
scope instead of scaffolding it.

Reusable cryptographic primitives and hash helpers belong in
`src/core/crypto.rs`. Identity event modules should call core crypto helpers for
hashing, signing, verification, nonce generation, encryption, or KDF operations
instead of defining primitive implementations locally. Event modules still own
their semantic context: which canonical bytes are signed, what signer dependency
is allowed, and what associated data or purpose string is passed to core crypto.

Follow the `poc-6/core/crypto.py` simplification pattern: expose a small core
facade around real primitives (`hash`, Ed25519 `sign`/`verify`, X25519 public
key derivation, nonce generation, and X25519+XChaCha20-Poly1305
`encrypt`/`decrypt`) instead of spreading library-specific crypto calls through
event modules. Keep the facade honest: every helper name must match a real
cryptographic property it enforces.

## Concept Mapping

`poc-8` identity scope is `workspace + endpoint`. There is no tenant layer.
This is intentional: a daemon/endpoint may host at most one instance of a given
workspace. If an endpoint tries to join a workspace it has already joined, the
command returns an explicit error.

Map p7 concepts as follows:

```text
p7 workspace       -> p8 workspace
p7 tenant          -> removed
p7 recorded_by     -> endpoint-scoped row-key prefix or command context
p7 peer_shared     -> p8 endpoint_shared
p7 peer_secret     -> p8 endpoint-local secret/private-key event
p7 invite_secret   -> p8 local-only invite/bootstrap secret event
p7 invite_accepted -> p8 local-only acceptance/provenance event
```

The p8 `invite_accepted` event preserves the p6/p7 projector pattern without
restoring p7 transport-trust machinery. Invite creation records the creator's
scoped `invite_secret` so the creator can decrypt future accept traffic. Invite
acceptance records the acceptor's scoped `invite_secret` and a deterministic
`invite_accepted` event in the same command output. `invite_accepted` depends on
that local secret event, carries no raw secret, and projects
`identity.invites_accepted`. It is acceptance/provenance for the out-of-band link,
not shared membership, route creation, or proof that the shared invite row has
already been received.

Target identity chain:

```text
workspace
  -> user_invite
  -> user
  -> device_invite
  -> endpoint_shared
```

Target admin chain:

```text
workspace or existing admin authority
  -> admin
```

The precise admin authority rule should come from latest p7 behavior, translated
into p8 dependency/context checks.

## Endpoint Transport Keys Versus Signing Keys

Every local endpoint has two independent key identities:

- `endpoint_id`: the X25519 public key used for connection/transit identity and
  route binding.
- `signing_public_key`: the Ed25519 public key used to authorize signed shared
  events once an endpoint is a workspace member.

These keys must not be treated as interchangeable. A signed envelope's
`signer_public_key` is an Ed25519 signing key. When a projector validates an
endpoint-authorized identity action, it must compare the envelope signer key to
the signer endpoint's `signing_public_key`, never to the signer endpoint's
`endpoint_id`.

The bug fixed on this branch was exactly that confusion:

- `user_invite` admin-endpoint authorization compared
  `envelope.signer_public_key` to the signer endpoint's transport
  `endpoint_id`.
- `device_invite` endpoint-shared authorization made the same comparison.
- The earlier tests masked the bug by constructing endpoint fixtures where the
  transport id and signing key were both Ed25519-derived bytes.

The implemented fix is:

- `identity/user_invite/projector.rs` now validates admin-endpoint signed
  invites against `signer_endpoint.signing_public_key`.
- `identity/device_invite/projector.rs` now validates endpoint-shared signed
  device invites against `signer.signing_public_key`.
- Projector fixtures now keep transport endpoint ids distinct from signing
  public keys.
- `user_invite` includes a regression test proving a transport endpoint key
  cannot authorize a signed user invite.
- `device_invite` keeps the wrong-key rejection test on the endpoint-shared
  path, now with distinct transport/signing fixture material.

Test rule: auth projector tests must not use a fixture where `endpoint_id` and
`signing_public_key` are equal unless the test is explicitly about malformed or
adversarial identity data. Equal fixture keys hide exactly the class of bug this
section describes.

## Module Layout

Each imported event family should live under the identity domain and follow the
p8 leaf-module shape:

```text
src/protocol/event_modules/identity/<event>/
  mod.rs
  types.rs
  codec.rs
  commands.rs      # only when the event has creation logic
  projector.rs     # only when the event projects rows
  schema.rs        # only when the event owns rows
  queries.rs       # only for read-only reporting/CLI surfaces
  cli.rs           # only when this leaf owns CLI commands
  cli_tests.rs     # for CLI tests owned by this leaf
```

Domain root files should aggregate only shared identity concerns:

```text
src/protocol/event_modules/identity/
  mod.rs
  cli.rs           # only for commands that truly span child modules
  schema.rs        # only if shared identity rows are cleaner at domain scope
  queries.rs       # only for read-only domain reporting
  worker.rs        # only if active identity-domain queued work is needed
```

Prefer the tightest owner. A command for one event type belongs in that event's
leaf `cli.rs`, not the identity root. The root `cli.rs` exists only for
cross-child workflows that do not have a clear primary event owner.

## Storage Translation

Translate p7 projection tables into p8 row tables with explicit binary row keys.
Do not recreate p7's broad SQL schema, `valid_events`, `recorded_events`,
tenant rows, or projector queue model.

Likely row families:

- `identity.workspaces`: keyed by `workspace_id`
- `identity.users`: keyed by `workspace_id + user_id`
- `identity.user_invites`: keyed by `workspace_id + user_invite_id`
- `identity.device_invites`: keyed by `workspace_id + device_invite_id`
- `identity.endpoint_shared`: keyed by `workspace_id + endpoint_shared_id`
- `identity.endpoint_memberships`: keyed by `endpoint_id + workspace_id`
- `identity.admins`: keyed by `workspace_id + admin_id`
- `identity.invite_secrets`: local-only, keyed by invite/bootstrap secret hash
- `identity.endpoint_secrets`: local-only, keyed by endpoint id
- `identity.invites_accepted`: local-only acceptance/provenance rows, keyed by
  `accepted_endpoint_id + workspace_id + invite_event_id`

Rows should use `Schema::durable_row_table` or `Schema::memory_row_table` as
appropriate. Memory rows are in-process `Store` maps, not SQLite TEMP tables.
If another process or a restarted daemon must observe a row, it is durable.
Table names belong in `schema.rs`; row constructors and row decoders belong in
that module scope.

Duplicate join rule:

- command preflight checks `(endpoint_id, workspace_id)`
- if a row already exists, return an explicit duplicate-workspace error
- admitting the exact same previously-created event remains idempotent
- creating a second join for the same endpoint/workspace is rejected

## Codecs And Records

Port p7 event fields by semantic behavior, not by p7 file shape. Each codec
constructs its `EventRecord`; other files do not build `EventRecord` literals.

Each leaf event should have:

- fixed tags and deterministic canonical encoding
- `decode` that rejects malformed/trailing bytes
- `record_from_bytes` that declares scope and immediate dependencies
- dependency fields matching p7 auth structure, minus explicit out-of-scope key
  history/key-sharing dependencies

Signed wrappers should expose the signer event id as a dependency and preserve
enough inner metadata for the projector/registry to resolve the semantic signer
type.

Signature codecs and tests should use real keys/signatures. Tests may use fixed
test vectors or deterministic fixture keys for repeatability, but the signing
and verification operations themselves must be the production primitive.

## Projector Translation

Projectors stay pure row producers:

- decode current event
- inspect immediate dependency records and generic event context
- validate direct fields and authority relationship
- return `ProjectionOutput` rows/labels

Projectors must not:

- query storage directly
- write SQL directly
- emit commands or events
- call workers
- perform transport, transit, or crypto side effects beyond validation of
  explicit event fields

Any p7 projector behavior that depended on SQL lookups or emitted follow-up
work must become one of:

- an explicit event dependency
- a command preflight read through a narrow trait
- a row written by an earlier projection and consumed by a command or worker
- a narrow context loaded outside projector logic and passed into the pure
  projection boundary

## Command Flows

Commands return `CommandOutput<T>` with proposed events. They do not mutate
storage. They may read narrow context through traits or domain helpers.

Planned command flows:

1. `create_workspace`
   - ensure or create local endpoint secret event
   - emit shared workspace root
   - emit bootstrap user invite/user/device or equivalent latest-p7 creator
     chain, translated without tenant/key-history
   - emit endpoint_shared for the creator endpoint
   - emit initial admin if latest p7 grants creator admin

2. `create_user_invite`
   - require local endpoint/user/admin authority
   - emit `user_invite`
   - emit local invite secret/bootstrap secret event
   - return invite link material

3. `accept_user_invite`
   - parse invite link
   - ensure or create local endpoint secret event
   - preflight duplicate `(endpoint_id, workspace_id)` membership
   - emit local `invite_accepted`
   - emit `user`
   - emit `endpoint_shared`
   - project endpoint/workspace membership through normal admission

4. `create_device_invite`
   - require current user/endpoint authority
   - emit `device_invite`
   - emit local invite secret/bootstrap secret event
   - return device-link invite material

5. `accept_device_invite`
   - parse device invite link
   - ensure or create local endpoint secret event
   - preflight duplicate `(endpoint_id, workspace_id)` membership
   - emit local `invite_accepted`
   - emit `endpoint_shared` bound to the existing user

6. `grant_admin`
   - require translated p7 admin authority
   - emit `admin`

## Bootstrap Boundary

Use p6 only for the bootstrap shape lesson:

- invite link carries out-of-band bootstrap/contact/secret material
- shared invite event carries durable authorization facts
- no placeholder ids such as `PENDING` or `SELF`
- no direct projection-table inserts
- no forced projection calls

Do not import iroh or p7 peering. p8 connection/bootstrap remains the network
boundary. Identity modules produce and consume authorization facts; connection
modules own opaque TCP/transit mechanics.

## Receive, Blocking, Signing, And Bootstrap Connections

Transit in is not a second event pipeline. It unwraps/authenticates network
frames and writes valid inner event bytes into `canonical.in`. The common event
pipeline owns parse, dependency blocking, projection, and status transitions.
Event admission rejects remote local-only events and unauthorized
transit/provenance shapes, but it does not decide whether a content event,
identity event, or auth event is semantically valid.

This is the intended receive path:

```text
core TCP row
  -> transit_in runs the transit projector
  -> canonical.in row with unwrap provenance
  -> event_admission claims canonical.in
  -> reject invalid provenance/event-scope combinations
  -> registry decodes the shareable canonical event
  -> common event pipeline stores/blocks/applies/rejects
  -> projectors receive only already-applied dependency context
```

Do not add an "event id was requested on this connection" requirement as an
auth invariant for inbound durable events. It is a useful send-side/work-queue
dedupe concept, not proof that a received event is valid. A peer can send a
shareable event unsolicited; if it is missing dependencies, unauthorized, or for
a workspace that cannot make it valid locally, the common worker blocks or
rejects it.

Solicitation is not the security boundary because sync does not always know
what it is asking for. `have_id` / `need_id` exchange opaque ids, and dependency
repair can request an id before the requester has decoded enough of the graph to
know its workspace, event type, or authority chain. A request proves only that a
local worker wanted to try resolving an id. It does not prove the remote endpoint
is allowed to supply that event, and it must not make the received bytes valid.
The durable ingress boundary is instead: the bytes came from a specific
connection endpoint, the event is scoped to a workspace that endpoint is allowed
to participate in, and the event then passes the ordinary codec, dependency,
signature, projector, and storage checks for that workspace.

Mutual-only workspace sync is enforced on outbound disclosure, not by trusting
inbound bytes. When a peer asks for a durable event id, the sync worker/command
path must check that the event's workspace is mutually shared by the local
endpoint and the remote endpoint for that connection before queueing bytes to
transit outbox. Inbound durable bytes still validate normally after receipt;
network sync messages can cause work to be attempted, but cannot make invalid
durable events valid.

Signing has two layers:

- the signed-envelope codec verifies that the signer possessed the Ed25519
  private key for the canonical payload bytes;
- the event projector verifies semantic authority from dependency context,
  labels, and projected rows.

The codec cannot decide that a signer is an admin, workspace member, user, or
authorized endpoint. That authority belongs in the pure projector for the signed
event type. Conversely, projectors should not redo primitive signature parsing;
they should consume signed payloads that have already passed codec verification.

Bootstrap invite connections do not need a separate validation pipeline. A
bootstrap request proves the remote side knows the invite/bootstrap secret
needed to establish the connection. Any invite-derived workspace scope should be
represented as connection/session state when that authorization is wired. The
inner durable events still enter the same common pipeline as ordinary connection
traffic, and they become useful only when their dependencies and signatures
project validly.

## CLI Locality

CLI commands should be as event-module-local as possible:

- `workspace/cli.rs`: `create-workspace`, workspace listing/status if local to
  workspace identity
- `user_invite/cli.rs`: create user invite and user-invite-specific inspection
- `device_invite/cli.rs`: create device link and device-link-specific
  inspection
- `invite_accepted/cli.rs`: only if accept flows are primarily acceptance-owned
- `endpoint_shared/cli.rs`: endpoint identity/status/listing commands
- `admin/cli.rs`: grant admin and admin listing
- identity root `cli.rs`: only commands that truly span multiple child modules
  and do not have a single primary event owner

`src/protocol/cli.rs` only aggregates command specs.

## Test Locality

Bring over p7 tests as behavior, not as p7 file structure. Prefer module-local
tests.

Leaf module tests should cover:

- codec roundtrip
- malformed/trailing decode rejection
- projector accepts valid dependency context
- projector rejects wrong signer/authority
- projector rejects malformed fields
- schema row encoding/decoding

For projector tests, prefer pure tests translated from p7's identity projectors.
Port row-output and decision assertions into the owning p8 `projector.rs`
`#[cfg(test)]` module. Do not port p7's top-level projector SQL harness,
tenant/`recorded_by` scoping, pending bootstrap trust side effects, key-history
assertions, or projector-emitted command behavior. In p8, projectors prove only
row-shaped output and local dependency/signer decisions; command scheduling and
worker effects belong elsewhere.

CLI tests should live beside the module command they prove:

```text
src/protocol/event_modules/identity/workspace/cli_tests.rs
src/protocol/event_modules/identity/user_invite/cli_tests.rs
src/protocol/event_modules/identity/device_invite/cli_tests.rs
src/protocol/event_modules/identity/admin/cli_tests.rs
src/protocol/event_modules/identity/endpoint_shared/cli_tests.rs
```

Each module should include its test with:

```rust
#[cfg(test)]
mod cli_tests;
```

Later CLI tests may import earlier local scenario helpers when they need to
build on prior flows. Keep helpers test-only and scoped:

```rust
// identity/workspace/cli_tests.rs
pub(crate) fn create_workspace_scenario(...) -> WorkspaceScenario;

// identity/user_invite/cli_tests.rs
use super::super::workspace::cli_tests::create_workspace_scenario;

// identity/device_invite/cli_tests.rs
use super::super::user_invite::cli_tests::create_joined_user_scenario;
```

If many modules need the same setup helpers, move only helpers to:

```text
src/protocol/event_modules/identity/test_support.rs
```

That helper file is not allowed by the static boundary today. Add it only with
an explicit boundary-test update in the same commit that introduces the first
real shared helper.

Keep assertions in the leaf `cli_tests.rs` file whose behavior is being proven.
Avoid a top-level scenario dumping ground. Keep `tests/cli_harness` generic and
process-only.

Command/flow test targets:

- create workspace creates workspace/user/endpoint/admin graph
- create user invite from authorized endpoint
- accept user invite creates user and endpoint_shared
- accepting same workspace twice on same endpoint errors
- create device invite and accept on a new endpoint
- wrong invite secret rejected
- wrong signer rejected
- non-admin invite/admin grant rejected

Reserve top-level black-box tests for true cross-domain flows that cannot be
owned by a leaf module.

## Validation

Run tests in this order:

1. focused leaf module tests
2. identity command and `cli_tests.rs` tests
3. p8 boundary tests, especially `cargo test --test rules_boundary_test`
4. full `cargo test`
5. `cargo clippy --all-targets -- -D warnings` if the branch is ready for
   review

For a doc-only update to this plan, no runtime test is required. State that in
the handoff.

## Expected Adaptation Points

No p8 structure blocker is expected.

The main adaptation work is:

- remove p7 tenant semantics cleanly
- map p7 `peer_shared` to p8 `endpoint_shared`
- keep endpoint private material local-only
- replace p7 projection-query-heavy auth checks with p8 dependency/context
  checks
- convert p7 projector side effects into command-owned or worker-owned work
- keep key-history/key-sharing fields out of the implementation
- keep CLI commands and tests at the closest event-module scope

## Required Handoff Step

Commit the completed work on the same worktree branch before handoff or review:

```text
git -C /home/holmes/poc-8-identity-auth-graph status
git -C /home/holmes/poc-8-identity-auth-graph add ...
git -C /home/holmes/poc-8-identity-auth-graph commit -m "<clear summary>"
```

# Core

`core/` is protocol-agnostic. It provides the generic substrate needed by any
protocol:

- canonical byte and table-row storage,
- queue tables and idempotent table-row writes,
- opaque network queue row types and generic target/source queue mechanics,
- generic TCP listener/connect/read-frame/write-frame mechanics,
- storage operations used by protocol-owned wait queues,
- generic transactions and storage queries,
- generic Crux app/effect driving, isolated from protocol code.

Core does not decide admission, blocking, dependency meaning, signature/auth
validity, which projector runs, connection, bootstrap, transit, sync ranges,
workspaces, content, endpoint identity, codec format, or CLI command semantics.
A different protocol should be able to reuse `core/` by providing its own
scoped workers, event registry, tables, wire helpers, and CLI command registry.

The current code split follows that boundary:

```
src/core/
  cli.rs
  store.rs
  crux_runner.rs
  network_queues.rs
  tcp.rs

src/protocol/
  cli.rs           // current protocol command registry
  event_modules/
    worker.rs       // common event-module admission/apply worker
    connection/
      worker.rs     // connection-scope queued work
    sync/
      worker.rs     // sync-scope queued work
  wire.rs
```

# Protocol

`protocol/` is the current Topo protocol built on the reusable core. It owns
all event families, domain workers, protocol byte meaning, and CLI commands. A
completely different protocol should be able to replace `protocol/` while
reusing `core/`.

`protocol/cli.rs` assembles the current Topo command registry. Command names,
help text, argv parsing, worker calls, follow-up queries, and output formatting
live in the closest relevant scoped `cli.rs`. The protocol-level CLI file only
collects those command specs and owns whole-protocol commands such as
status/count. There is no `protocol/app` layer. Core provides a generic command
runner; Crux remains available only as generic core runner machinery; protocol
code must not define Crux app/model/effect types.

**event_modules/** contains every protocol or domain behavior that can be
expressed as events, projectors, commands, module-owned tables, and module
workers. This includes content, identity, auth, connection, sync, and local-only
behavior. A built-out module owns its schema/read model next to its event type:
this is the poc-7 `message` / `reaction` pattern and the poc-6
`message.py` + `message.sql` pattern. Do not split "event type" and "tables"
into separate conceptual homes; tables live with the module that owns the
projection or queue. A domain may also own shared tables and
workers at the domain root when those tables coordinate several leaf event
modules.

`protocol/mod.rs` defines the current protocol composition object. That object
owns the event-module registry.
`protocol/event_modules/worker.rs` is the event-module-scope admission/apply
worker: it hashes canonical bytes, applies this protocol's dependency/scope
rules, calls this protocol's registry, and applies projector rows through core
storage. It also owns the default Topo blocking policy: immediate dependencies
declared by the codec/record are checked before projection, and missing
dependencies are written to the protocol's blocked-event queue.
`protocol/wire.rs` contains shared fixed-field binary helpers used by protocol
codecs; it is shared by modules, but it is still protocol infrastructure.
`protocol/event_modules/mod.rs` imports concrete protocol families and exposes
the narrow registry surface used by the protocol shell and tests. `core/` does
not call event parse/project traits and does not import concrete event
families. The protocol shell calls through the protocol composition object and
does not import `connection`, `sync`, `content`, or `identity` directly. Module
workers interpret inbound byte rows, canonical events, queues, and route state.

Suggested organization:

```
src/protocol/event_modules/
  content/
    message/
      types.rs
      codec.rs
      commands.rs
      projector.rs
      schema.rs
      queries.rs
      mod.rs
    reaction/
      ...
    file/
    cli.rs          // optional content-level command registry/help
  identity/
    workspace/
    user/
    peer/
    cli.rs
  auth/
    invite/
    key/
    removal/
    cli.rs
  connection/
    worker.rs
    schema.rs
    queries.rs
    types.rs
    cli.rs
    connection/
    connection_secret/
    observed_address/
  sync/
    worker.rs
    schema.rs
    queries.rs
    types.rs
    cli.rs
    compare/
    have_id/
    need_id/
    dep_cache/
  local/
    local_secret/
    clock_wake/
```

**Per-file pattern, always.** Every leaf event module is a directory with one
file per concern (`types.rs`, `codec.rs`, `projector.rs`, `commands.rs`,
`schema.rs`, `queries.rs`, `cli.rs`, `registry_meta.rs`, `mod.rs`, etc.) — but
only when the concern exists. Do not keep placeholder concern files that merely
say "no rows" or forward to another module. `schema.rs` is where the module
declares its own projection tables, indexes, queues, cursors, and storage
class. A domain root may also contain `schema.rs`, `queries.rs`,
`types.rs`, `commands.rs`, `worker.rs`, and `cli.rs` when it owns shared tables,
cross-child protocol decisions over explicit context, a worker, or a
domain-level CLI command registry coordinating several leaf event modules.
There is no generic `jobs/` or `cli_commands/` dumping ground and no fake event
module for an algorithm: `sync/worker.rs` may run negentropy over `sync/schema.rs`;
`negentropy/` is only a child module if it defines an actual event type. `worker`
is the component noun; `run` is the method verb.
The win is intentional friction without boilerplate. In a codebase where most
code is assistant-generated, uniform concern names make accumulating logic easy
to spot, while omitting no-op concern files keeps the tree honest. Files that
grow disproportionately, or directories that sprout extra concerns, are the
audit signal that something needs simplification or splitting. No collapsed
single-file event modules.

This rule is in conscious tension with "let complexity earn length" in the documentation quality bar (see appendix): that rule applies to *prose* in docs, this rule applies to *code structure* in event modules. Both stand.

**networking** All complex networking behavior including bootstrap,
connection, transit, and sync is implemented in event modules: commands propose
events, projectors write rows, module workers decide what to run next, and
connection/transit modules wrap and unwrap transit blobs. Core network queues
carry only `target/source + opaque bytes`, and core TCP only frames and moves
those bytes to concrete transport targets. Connections are
between two endpoints (daemons) and sync all data in all workspaces those two
endpoints share. Every workspace-scoped event carries its own `workspace_id`;
endpoint-scoped events (connection, intro, observed_address, self_address,
prekey events) carry endpoint identity instead. A daemon hosts at most one
instance of any given workspace, so for workspace-scoped events `workspace_id`
alone identifies the local processing scope and there is no separate
"recorded_by". See **Event Scopes** below for the full taxonomy.

**worker.rs** is the only active-component filename. A worker lives at the
scope whose queues/cursors it owns. `protocol/event_modules/worker.rs` covers
common canonical event admission/apply for all event modules. A domain worker
such as `sync/worker.rs` covers active sync queues and cursors. There is no
`protocol/worker.rs`: protocol root is too broad to own a worker.
Every `worker.rs` exposes one public free function, `run`, as the obvious
entrypoint. Public work/output types describe the worker boundary; helper
functions stay private.

Default dependency blocking is centralized in the common event pipeline after
record decoding and before projection. Projectors remain expressive by writing
module-owned wait/blocked rows for semantic blockers that are not just
immediate missing dependencies, but they do not each reimplement the common
dependency wait queue.

**control loop** means the protocol's worker scheduling policy. It claims
bounded batches of queue rows, dispatches to the owning worker, applies returned
state writes atomically through core storage, and admits returned events
through the common event pipeline. Workers queue network IO by writing
`OutboundNetworkRow`s with target metadata; core TCP drains those rows as
opaque frames. Core
provides queue and transaction mechanics; protocol owns which workers exist
and what their work means.

**state** is the explicit table-shaped substrate that projectors and workers observe. It is materialized from event-module table declarations and can be a database in production or an in-memory store in testing and simulation.

**core network queues** contain one outbound table and one inbound table. The
outbound queue is not split into per-target tables; `target` is metadata encoded
into the row key so core can claim a bounded batch for one target with a generic
key-prefix scan. `Store` only exposes generic table-row, prefix-scan, and
key-range-scan mechanics; `core/network_queues.rs` owns the typed row wrappers
and queue encoding.

**core TCP** drains and fills opaque network queue rows. It owns listener,
connect, length-prefixed frame read/write, socket shutdown, and transport
backpressure mechanics. It does not create or interpret transit blobs,
canonical event bytes, sync control events, invites, or connection ids.

**workers** are module-owned active components run from queue rows, timers, IO
readiness, or explicit CLI requests. A worker declares its input sources, read
set, and write set. Core uses those declarations to load bounded context
and commit output; the worker owns the semantic decision. Use `input` for
scheduling and `run` for execution.

**cli.rs** is the module-local CLI adapter. It owns help text, parameter names,
domain command invocation, follow-up queries, and output formatting for the
commands that belong to that module or domain. The generic CLI runner stays
boring: find the named command spec, reject duplicate command names, pass argv
tail and context to the command, and return text lines. The binary shell parses
global flags such as `--db`; the scoped command decides which workers to run
and which queries to run.

CLI files follow the tightest-scope rule. A command that creates or queries one
event type lives in that leaf event module's `cli.rs`. A domain-root `cli.rs`
exists only for commands that coordinate several child modules in the same
domain. `protocol/cli.rs` is only the command registry for the assembled Topo
protocol plus truly whole-protocol commands.

For a write command, the module CLI calls a pure module command to produce
`ProposedEvent`s with deterministic ids, asks the runner to process exactly
those proposed events, then runs whatever module query is needed for output:

```
let proposed = message::commands::create(params, context)?;
let applied = runner.run_proposed(proposed.events)?;
let row = message::queries::by_event_id(store, applied.primary_id)?;
CliOutput::text(message::cli::format_created(row))
```

`run_proposed` means "admit and apply this proposed chain enough that its own
projection rows are visible." It does not drain unrelated ready events. Query-only
commands simply run module queries and format output. Commands that need
external progress, such as `sync` or `assert-eventually`, say that explicitly by
waking the owning worker or polling a module query.

CLI scenario/check/expect definitions live in the closest event module or
domain root, not in the app shell. A generic scenario runner can still execute
the real `topo` binary and real TCP; the scenario's setup, command sequence,
and expected output stay local to the behavior being specified.

`cli_tests.rs` follows the same scope rule as `cli.rs`. A leaf event module test
owns scenarios for that event type; a domain-root test owns workflows spanning
its child event modules; protocol-level tests are only for cross-domain
end-to-end behavior. The shared CLI harness is deliberately uninteresting:
build/run the binary, allocate temp dbs and ports, capture output, and nothing
else. Command names, argv construction, invite editing, retries, polling, output
keys, and expected results belong to the scoped test file. If we add a generic
scenario type, it should be a small data contract like:

```
CliScenario {
  name,
  setup,
  steps: [argv + optional timeout + expect(stdout, stderr, status)]
}
```

The scenario type must not know Topo command semantics; it only standardizes how
scoped tests submit params and checks to the black-box runner.

The substrate pieces outside `event_modules` are deliberately narrow:

```
core/crux_runner.rs      // generic Crux app/effect driving
core/cli.rs              // generic command registry dispatch
core/store.rs            // typed table rows, memory/disk storage, transactions
core/network_queues.rs   // opaque inbound/outbound byte queue rows
core/tcp.rs              // generic length-prefixed TCP byte transport
protocol/cli.rs          // current Topo command registry
protocol/event_modules/worker.rs     // event-module admission/apply and blocking worker
protocol/wire.rs         // shared fixed-field protocol codec helpers
protocol/event_modules/  // protocol facts, projectors, tables, workers
```

If behavior is protocol semantics expressible as
events/projectors/commands/tables/workers, it belongs under `event_modules`. If
it owns Topo admission/apply semantics, it belongs in `protocol/event_modules/worker.rs`.
If it owns shared protocol encoding helpers, it belongs in `protocol/wire.rs`.
If it owns process execution, IO, storage mechanics, or queue mechanics, it
belongs outside event modules.

## Core State and Registry Interface

State is the set of declared tables the control loop can read and update atomically:

```
State_t =
  events
  + module-owned projection tables
  + boundary/work tables
  + declared caches
```

Processing has the shape:

```
Event + Context(State_t) -> StateUpdates
State_{t+1} = apply(State_t, StateUpdates)
```

`state` does not centrally know the domain schema. Each event module declares its schema and behavior:

```
module id
event types
tables it owns
indexes
storage class: durable | memory | temp
migrations / schema version
projectors
commands / workers
```

Those declarations form the runtime catalog:

```
event_modules/*/registry_meta.rs
  -> ModuleRegistry
  -> WorkerRegistry
  -> StateCatalog
  -> database / memory store schema
```

The event domain owns semantic meaning: what a row means, which projection
writes it, which indexes are required, which workers consume it, and whether it
may be rebuilt. A leaf event module owns one event type's codec, dependencies,
commands, projector, and leaf projection tables. A domain root owns shared
tables and workers that coordinate several leaves. `state` owns mechanics:
creating tables, applying migrations, opening transactions, inserting NewRows,
deleting Purges, querying declared indexes, resetting transient rows on
startup, and choosing durable vs memory storage.

Boundary tables should follow the same rule where possible. `outbox` is a
connection-domain queue declared by the connection domain root, `blocked_by_event`
by the ready-event loop, schedule rows by the owning module or `protocol/timers`,
and sync caches by the sync modules. The fewer central special tables, the
better.

## Protocol Admission And Codec Interface

**codec** is canonical event encoding and parsing. It is not necessarily network wire. A module's `codec.rs` defines `Event <-> CanonicalEventBytes`, the event type tag, field layout, dependency field declarations, signature and signer-family rules, and deterministic id rules. Canonical event layout is fixed-width per event type: once the type tag is known, the field layout and canonical byte length are known, though different event types may have different fixed lengths. `protocol/wire.rs` provides shared primitive reads/writes, fixed-size ids, truncation checks, and trailing-byte checks so codecs read as format descriptions.

**encode** encodes an Event to `CanonicalEventBytes`, returning a BLAKE3 event id, usually used by `create` or other domain-specific functions.

**parse** consumes `CanonicalEventBytes` and returns an Event, which includes all event values, its BLAKE3 hash id, its canonical bytes, and the `workspace_id` it belongs to, or throws an error if the bytes are invalid.

**canonical-event processing** is owned by `protocol/event_modules/worker.rs`. It hashes
the canonical bytes, checks protocol admission before loading context, parses
only newly admitted events, and then runs context/project/apply as one chained
step unless the event blocks.

Typed Rust event values are the in-process semantic representation. They should not carry canonical bytes as ordinary fields. Canonical bytes and ids are boundary artifacts:

```
Event type     = semantic fields
EncodedEvent   = event_id + event_type + CanonicalEventBytes
ParsedEvent<E> = E + EncodedEvent
```

For locally created events:

```
E
  -> encode(E)
  -> EncodedEvent
  -> insert/project
```

Local creation does not enqueue durable data for peers. Durable data transfer is driven by negentropy: compare events discover differences, have/need events identify missing ids, and only a `NeedId` response queues the requested durable event id to `outbox`.

For inbound events:

```
CanonicalEventBytes
  -> event_id = BLAKE3(CanonicalEventBytes)
  -> admit_event_id(event_id)
  -> parse(CanonicalEventBytes)
  -> ParsedEvent<E>
  -> project
```

Traits are the module API; canonical bytes are event identity. Projectors that need the id or original bytes receive them through `ParsedEvent<E>`, not because every event struct embeds them. This prevents typed values and encoded bytes from silently diverging.

**admit_event_id** consumes an event id and returns known or newly claimed. Known includes applied, blocked, rejected, and in-flight events. Duplicates record observations, call `suppress_received(id)` (see: Sync), and stop before context loading. Newly claimed ids become canonical event ids only after parse succeeds.

**get_context** consumes a newly admitted Event and returns an EventWithContext.
The protocol-owned default context for `project` is:

1. the parsed Event,
2. the other Events that the consumed Event names as immediate dependencies,
3. every `label` for that event,
4. generic origin metadata such as source socket address or received transport id.

This default should be sufficient for most projectors. If a projector needs more
state, first try to make that state an explicit dependency or a bounded label.
We can always add more dependency fields, and labels are the right substrate for
small derived facts such as authorization, trust-anchor, route, expiry,
supersession, or "this event blocks others." Do not introduce bespoke
per-event-type SQL queries against arbitrary state just because a dependency or
label is missing.

Connection handshakes are the important subjective case. A received
request/response is canonical event bytes plus local receive metadata in
`EventContext`, not in `EventRecord`. Request receive context must carry
bootstrap-invite authorization backed by an applied invite-secret dependency.
Response receive context must carry endpoint-transit authorization from the
decrypted sender endpoint. The connection projector consumes those together and
writes the established connection row plus the current transport-target row only
when the origin is a route worth dialing later. The route is not a separate
durable `transport_target` event because it has no independent meaning outside
this peer's observation of that connection event.

Custom typed context is allowed only for module-owned read models that are too
large or index-shaped to fit the default context. The module owns the context
request type, the context result type, and the semantics of the read model; the
protocol runner only routes the request/result and never inspects
module-specific fields.

`queries.rs` is reserved for read-only CLI/reporting surfaces. Active workers
keep their state reads in the worker that consumes them, and command-time reads
use narrow context traits owned by the command module. If a worker is checking a
relationship between two events, prefer declaring the relationship as an event
dependency and validating it through generic context.

The known required case is negentropy response projection: compare/have/need
responders need indexed range summaries, event ids, presence checks, and event
bytes from module-owned sync/negentropy tables. That is context for the sync
module, not sync vocabulary in the core.

Connection and bootstrap projectors should not need custom context in the first
cut. Model their checks as first-level dependencies and labels:

- a connection request depends on the invite, peer-shared signer, or other
  signer/prekey facts needed to verify it;
- a connection response depends on the request it accepts;
- invite acceptance creates or labels local trust anchors and route hints rather
  than reaching through custom context;
- observed/self address and route facts are labels or module rows consumed by
  sender/outbox workers, not projector-only hidden queries.

If a future connection or bootstrap behavior appears to need custom context,
the burden is to prove that extra dependencies or labels cannot express it
boundedly.

**labels** is a table whose rows are tuples of (event_id, label_type); adding a label can be a result of projection. Labels become part of context so there should be a bounded number of labels for a given event_id. "This event blocks others" can be a label. 

**blocking** is protocol-worker-owned policy over core-maintained queues. A blocked event remains an `events` row with `status = blocked`; each missing dependency is a `blocked_by_event(blocked_by_event_id, event_id)` row.

**project** consumes an EventWithContext and returns either RejectedEvent (if known invalid), BlockedEvent, or StateUpdates.

**apply** consumes StateUpdates, applies them to State, and returns an AppliedEvent. There must be no writes (or at least no *context-relevant* writes) between the `get_context` and `apply` steps.

**StateUpdates** is [Purges, NewRows] i.e. what to delete and what rows to write to State.

**Purges** is a list of event id's for `apply` to purge.

**NewRows** is a list of tuples (table, row) for adding new rows to sorted tables in State, e.g. in SQLite with INSERT OR IGNORE. All NewRows are indexed by (event_id, workspace_id) and adding a NewRow with the same index must be idempotent.

Semantic removal is expressed by durable facts or labels, not by the absence of old rows. Examples include `deleted:message_id`, `expired:event_id`, `removed:user_id`, `revoked:key_id`, and `superseded:invite_id`. A projector may remove visible projection rows immediately, but future correctness must come from the surviving fact, label, summary, or high-water mark.

`Purges` are physical compaction. In trace, simulation, and audit modes, time-based purge should be disabled so facts remain monotonic and replayable. In app/production mode, events and projection rows may be purged for deletion or TTL once no future projector needs their bytes or rows as the only evidence of what happened.

Invariant: purging may remove physical evidence, but it must not be the only representation of a semantic change. If future behavior depends on knowing that something was deleted, expired, revoked, removed, or superseded, some surviving row must say so after purge.

Queue-like work is represented as ordinary NewRows into module-owned tables. Boundary tables are used only at wait, dedupe, retry, schedule, and IO boundaries.

## Event Scopes

All events inserted into `events` have canonical bytes from a module `codec.rs`, even if they are never sent over the network. Canonical bytes provide the event id, dedupe key, replay form, dependency reference, and projector input.

```
durable event:
  workspace_id: yes
  codec: yes
  signed: yes
  may be sent to peers: yes

endpoint-scoped event:
  workspace_id: NO  (carries endpoint identity instead)
  codec: yes
  signed: yes
  may be sent to peers: yes
  examples: connection, connection_prekey, connection_prekey_shared, intro,
            observed_address, self_address

endpoint-local event:
  workspace_id: optional (e.g. negentropy/sync events name (connection_id, workspace_id))
  codec: yes
  signed: usually no
  may be sent to one endpoint/connection: yes

connection-scoped event:
  connection_id: yes
  workspace_id: optional, when the event concerns a workspace over the connection
  codec: yes
  signed: usually no
  core scope: Transient
  may be sent only on that connection
  id: BLAKE3(canonical bytes), with connection_id inside the bytes
  examples: sync_compare, sync_have_id, sync_need_id

local-only event:
  workspace_id: usually yes
  codec: yes, if stored/projected/deduped
  signed: usually no
  may be sent to peers: no

work item:
  codec: no, unless promoted into events
```

Examples of work items that do not need codecs are timer-fired, socket-writable, CLI-command-entered, and internal-wakeup notifications. Once something is inserted into `events`, referenced by id, deduped, blocked, replayed, or projected like an event, it needs canonical bytes.

## Protocol Worker Scheduler

The control loop is the protocol worker scheduler. It owns:

- the module registry,
- generic table-row storage,
- transaction boundaries,
- resource limits,
- queue commit ordering.

All domain behavior lives in event modules and their colocated workers. The
control loop should stay domain-agnostic within this protocol: it sees ready
events, opaque worker wakes, and worker output, not sync ranges,
connection handshakes, content semantics, or connection routes. Core maintains
the queues, transactions, opaque network queues, and TCP byte mechanics the
scheduler uses.

Queued work is typed:

```
WorkItem =
  ReadyEvent
  WorkerInput(worker_id, input_key)
```

Each queue item has exactly one owning worker. The control loop calls one
function:

```
worker.run(input, context) -> WorkerOutput
worker.run(input, context) -> WorkerOutput
```

Mathematically:

```
Worker_i : Input_i x Read_i(State) -> Delta_i(State) x Events x Complete
```

The module registry gives core an worker catalog:

```
WorkerSpec:
  worker_id
  input_sources
  read_set       // declared tables/indexes this worker can read
  write_set      // declared tables this worker can update
  run
```

The protocol scheduler owns the mechanical sequence:

```
select input
lookup WorkerSpec
load declared context from read_set
worker.run(input, context)
commit returned rows/events/completions against write_set
```

Core does not know this worker catalog exists. The protocol supplies worker
catalogs and input sources. At network boundaries, protocol workers write
`OutboundNetworkRow`s with target metadata; core TCP drains those rows without
learning protocol meaning.

`WorkerOutput` contains:

```
StateUpdates   // includes NewRows into ordinary tables and boundary tables
Events         // proposed canonical events to admit through the common event pipeline
Complete       // queue rows to complete/delete after the state commit
```

The common event pipeline is a pure chain over canonical event bytes:

```
CanonicalEventBytes
  -> event_id = BLAKE3(CanonicalEventBytes)
  -> admit_event_id(event_id)
  -> parse(CanonicalEventBytes)
  -> get_context(Event)
  -> project(EventWithContext)
  -> apply(ProjectorRows)
```

Admission happens before parse context. Known event ids stop at
`admit_event_id`. Parse failures reject the proposed event and let the
protocol caller record whatever IO-level failure row it owns. Blocked events
write `blocked_by_event` rows and stop.

Deterministic replay is a core recovery invariant. Given only durable canonical
event bytes plus local-only canonical bytes that were intentionally retained, a
node must be able to restore projected state by replaying those events through
the same common event pipeline. Replay must be out of order: backup restore,
sync, negentropy, and queue recovery may hand events to admission in any order,
so readiness is determined by declared dependencies and semantic blockers, not
by log/file order or arrival order. A replay that receives children before
parents must block, then unblock and project deterministically when the missing
dependencies arrive.

Projectors only write rows. They cannot emit follow-on events. If projection
discovers work, it writes a module-owned queue row; a worker reads bounded queue
rows, queries its declared context, calls module commands, and sends the
proposed canonical events back to the control loop for admission. If the work
reaches a network boundary, the worker writes `OutboundNetworkRow`s to the core
network queue.

Workers are the active boundary. Projectors can only change rows, especially
queue rows. Commands are pure construction/query helpers. Workers are the only
event-module surface that can advance queued work. They do not return ad hoc
effects; they write queue rows.

Protocol inbound processing receives `InboundNetworkRow`s from core TCP.
`transit_in` runs the transit projector over those opaque bytes and writes
surviving canonical bytes into `canonical.in`. Event admission rejects invalid
transit/provenance shapes and remote local-only durable events before sending
accepted bytes through the common event pipeline.

Boundary tables that need claim/retry ownership are ordinary module-owned tables with status metadata:

```
id primary key
status
not_before_ms
attempts
last_error
created_at_ms
updated_at_ms
```

Core tables:

```
events              // canonical event bytes plus status; ready rows are claimable
blocked_by_event    // dependency wait edges, not a job queue
```

`events` stores every canonical event byte string that can be projected, replayed, referenced by id, or sent:

```
events:
  event_id primary key
  canonical_event_bytes
  scope        // durable | local | endpoint_local
  status       // processing | ready | blocked | applied | rejected
  created_at_ms
  expires_at_ms
```

`blocked_by_event` stores dependency wait edges:

```
blocked_by_event:
  blocked_by_event_id  // missing dep
  event_id             // blocked event
  primary key(blocked_by_event_id, event_id)
  index(event_id, blocked_by_event_id)
```

When event `D` becomes applied, the same transaction deletes `blocked_by_event_id = D` rows and marks affected blocked events `ready` when `NOT EXISTS` any remaining blocker.

Unblocking never recursively processes dependents in the same call. `events.status = ready` is the unblocked-events queue; the control loop later claims a bounded batch of ready events.

The control loop commits `StateUpdates`, proposed events, and queue completions
in one transaction. Network IO happens later by draining committed core network
queues.

The first implementation has one process-wide control-loop writer. Failed
claim/retry work remains in its table with status, attempts, and last_error
until its owning module marks it pending, rejected, blocked, expired, or dead.
On startup, `events.processing -> ready`; protocol-owned processing rows return
to pending according to their module rules. Memory protocol queues start empty;
recurring protocol workers recreate recoverable work.

Modules may run pure helper transforms inline until they reach a queue, state,
or effect boundary. Modules do not recursively drain queues and do not perform
transport IO inline.

The control loop has no sync, bootstrap, auth, connection, or event-type policy
beyond calling protocol workers. It only knows dispatch, bounded batches,
transactions, time, limits, retries, and queue commits. Blocking policy belongs to
the common event pipeline. Leases are a
later extension for multiple workers or long-running claim ownership.

## Network Boundary

There is no `protocol/network.rs`. Network mechanics are split:

- `core/network_queues.rs` defines one outbound byte queue and one inbound byte
  queue. The outbound queue is not split into per-target tables. Target metadata
  is encoded into each row key so core can claim bounded batches for a concrete
  target with a generic key-prefix scan.
- `core/tcp.rs` owns listener, connect, `[u32 length][bytes]` framing, socket
  shutdown, and transport backpressure. It sends and receives only opaque bytes.
- protocol event modules own route facts, connection ids, transit wrapping,
  bootstrap, auth, sync event meaning, and canonical event admission.

The only transport target visible to core is a concrete network target such as
`(ip, port)` or a future socket id. If a protocol worker starts with a
`connection_id`, it must resolve that id to a concrete `NetworkTarget` before
writing `OutboundNetworkRow`s. Core must not see the connection id.

Protocol-owned boundary tables include:

```
outbox              // connection_id + event_id, dedupe by unique pair
wake_schedules      // timer IO enters the protocol
```

Normal inbound processing is a core/protocol worker chain:

```
InboundNetworkRow { source, bytes }
  -> connection.unwrap / raw frame parse
  -> CanonicalEventBytes
  -> common event pipeline
```

Normal outbound processing is:

```
protocol outbox row
  -> connection/transit worker resolves NetworkTarget and creates opaque bytes
  -> OutboundNetworkRow { target, bytes }
  -> core/tcp.rs writes length-prefixed TCP frames
```

`Store` supports this without network semantics by exposing generic table-row
operations, including bounded prefix and key-range scans. Network queue encoding
lives in `core/network_queues.rs`, not `core/store.rs`.

## Possible Further Work

The current target-indexed core network queue is the right boundary for a POC,
but the sender loop can become more mature without changing that model. A
future long-lived sender should keep each open `NetworkTarget` fed with bounded
low/high watermarks, claim queued bytes by target and byte budget, and run
protocol workers when that target has capacity for more wrapped bytes. That
demand signal should stay generic: core TCP reports target capacity and drains
opaque rows; protocol workers decide which connection-scoped outbox rows to
wrap. This does not imply per-connection core network queues. Per-connection
dedupe and fairness remain protocol concerns, while physical backpressure
remains target-scoped in core.

**connection** is an event module. A connection request is a local event that
depends on the invite secret and the initiator's local ephemeral secret event.
The request carries the invite id and an Ed25519 signature by the invite private
key over the request transcript; it is not signed by the new endpoint identity.
The response is the connection event: its event id is the `connection_id`, it
answers exactly one request, and it carries the derived `connection_secret` used
by normal connection transit. The response is encrypted back to the requester
with a native Noise-like handshake key mixed from the invite secret,
`DH(initiator_eph, responder_eph)`, and
`DH(initiator_eph, responder_static)`.

Connection-layer forward secrecy is deletion based. The ephemeral secret events,
connection events, connection-scoped sync event bytes, and queued transit frames
are local-only records and must be TTL-purged after they are no longer needed.
After purge, retained connection transit ciphertext cannot be decrypted from the
long-term endpoint secret alone. This does not make already-projected shared
events disappear, and it does not protect local files/backups that retained the
purged records. TODO: add the TTL purger for old connection ephemerals,
connection events, connection-scoped event bytes, and transit queues.

The connection module also owns the transit envelope as plain functions:

- `connection.wrap_bootstrap(remote_endpoint_id, inner_event) -> TransitBlob`:
  encrypts a connection request to the invite endpoint public key.
- `connection.wrap_connection_handshake_response(request_id, inner_connection)`:
  encrypts the connection event with the handshake response key.
- `connection.wrap(connection_id, inner_events) -> TransitBlob`: loads the
  connection event, derives a symmetric AEAD key from `connection_secret` and
  frame associated data, and encrypts a batch of shared or connection-scoped
  canonical bytes.
- `connection.unwrap(bytes) -> Vec<CanonicalEventBytes>`: authenticates the
  outer frame and emits inner canonical bytes plus transit provenance for the
  common admission pipeline.

Wrapped bytes are never canonical events. They have no event id, no dependencies, and no labels — they are an opaque transit form. Only inner canonical event bytes are ids in the event store.

*Invariants: a valid unwrap under one of our inbound secrets proves the bytes
came through the remote endpoint of that connection, not that every inner
durable fact is semantically valid; every wrap is bound to exactly one
connection; outbound workers enforce disclosure policy before queueing bytes;
inbound durable events still validate through codecs, dependency blocking,
signatures, projectors, and storage constraints.*

**Outbox.** No projector calls `transport.send` or emits a `SendEvent`.
Projectors write rows to module-owned queues. A sync worker that wants to send a
durable event, for example after reading a queued need from connection C for
event E, must first check that E can be disclosed to C's remote endpoint through
a mutual workspace. Only then may it write the id-only
`outbox(connection_id=C, event_id=E)` row. `transit_out` claims outbox
rows, resolves C to a current transport target, calls the transit wrap command,
and writes a core TCP send queue row. The TCP IO worker packs those bytes into
TCP frames and writes sockets. A slow route backs off its own target; other
transport targets continue.
*Invariant: ordinary durable bytes on the wire have passed send-side disclosure
policy before entering transit outbox. The receiving side does not trust that
fact; after unwrap it admits only shared-scope durable bytes to the common
pipeline, which performs dependency, signature, projector, and storage
validation.*

For the current POC, connection response projection owns connection rows and
route learning. Request projection only validates and caches request bytes; it
does not create a connection. Network admission attaches receive metadata as
projector context to accepted inbound handshake records before admitting them.
The response projector writes:

```
connection.connections[connection_id] = remote_endpoint
connection.transport_targets[connection_id] = route_addr             # when a reusable route is known
```

This keeps connection establishment and "where can I send back to that
connection?" in one atomic projection. A transport target is still a protocol
row consumed by transit out, but it is not its own child event module.
For TCP listeners, the client's ephemeral source port is receive metadata but
usually not a durable route. The invite address from the accepted link and the
requester's advertised daemon listen address are the routes we rely on for now;
peer discovery and observed-address promotion remain out of scope.

Normal sync starts on any routed connection when the connection-scoped summary
changes or when a new connection has no prior sync snapshot. Invite-scoped
connections do not poll every tick; the connection worker owns retry/connect
policy, while sync owns compare/have/need protocol decisions once a route
exists. Plain non-invite connections still use deterministic endpoint ordering
to avoid redundant initiators.

`outbox` stores only deterministic event ids to process for a connection:

```
outbox:
  connection_id
  event_id
  queued_at_ms
  primary key(connection_id, event_id)
```

`outbox` is a memory row table by default and has no per-row claim, lease, or
retry status. It is send work, not truth: if the process restarts, sync can
recreate the same deterministic connection-scoped events and outbox rows. Each
active connection has exactly one transit out worker owner for outbox drain
work:

```
transit_out::run:
  connection_id
  hot_queue: bounded deque<event_id>
  present: set<event_id>
```

`hot_queue` is bounded by estimated bytes, not only event count. When it drops
below a low-water mark, `transit_out::run` refills with a prefix scan over
pending `outbox` rows for that connection, skipping ids already in `present`.
After the socket
accepts a complete frame, the protocol runner deletes the corresponding
`outbox` rows and removes those ids from `present`. On send failure it removes
ids from `present`, leaves `outbox` rows pending, and backs off the target. No
database transaction is held while writing to the socket.

# Protocol source references

Use poc-6 for the event-based networking shape. Its `events/network/` tree is
the local reference for expressing connection establishment, bootstrap,
observed/self addresses, sync-window facts, and transit-related facts as
ordinary canonical events projected into tables. The translation target is not
to copy poc-6 directly; it is to keep connection, bootstrap, transit, and route
state in protocol event modules rather than in core runtime code.

Use poc-7 for sync behavior and user-facing scope. Its negentropy and
dep-aware sync code are the local references for range comparison, have/need
id exchange, dependency closure accounting, incremental dep caches, and the CLI
commands/perf surfaces worth preserving. The translation target is to move that
logic behind `protocol/event_modules/sync` workers and tables rather than keep a
parallel sync engine.

The protocol should preserve useful poc-7 CLI functionality as black-box
surfaces: account/workspace creation, invite/join, messaging, file transfer,
large message sync, and cascade/dependency stress commands. Those commands are
not core APIs; they are this protocol's public behavior and tests.

Every migration of a poc-6 or poc-7 surface must land directly on this design:
one core substrate, one protocol module family for each domain, projectors that
write rows only, commands that propose events only, and workers that own active
queue/cursor work. No compatibility adapters or duplicate engines.

# Daemon runtime plan

`topo start` is the product daemon path. It is built by the generic core app
shell from the selected protocol spec. Core owns the long-lived `Store` context
handoff, TCP listener, daemon lock, and scheduler loop. The protocol supplies
commands and daemon worker objects through `src/workers`. RPC is optional;
direct-DB CLI commands are acceptable as long as the daemon observes durable
committed state and keeps syncing.

The daemon runner belongs in `src/core/daemon.rs`, not under `src/protocol`.
The project root `src/main.rs` is only the app shell that chooses the protocol
spec. Protocol semantics stay in event modules and workers; the core daemon
only runs opaque named worker steps.

Daemon responsibilities:

- accept inbound TCP frames continuously through `core/tcp.rs`
- drain raw inbound network rows through event admission and the transit
  projector
- drain ready durable events through the common event pipeline
- periodically run `sync::worker::Work::Tick`
- drain transit outbox routes and write framed bytes through the same core TCP
  pump used by finite CLI tests
- enforce one daemon per DB with a clear duplicate-start error

TCP send liveness rule: the daemon must not wait indefinitely for a peer to
drain its socket. TCP already handles packet loss and retransmit while a
connection is healthy, but a blocked send buffer, stalled peer, or broken route
must return control to the worker loop within a bounded budget. On timeout or
route failure, protocol send rows stay queued or are recreated by set
reconciliation; they are consumed locally only after core has written the
framed bytes and completed its send bookkeeping. This is a synchronous
one-worker-step send, not a claim that the peer has processed the frame.

Daemon non-responsibilities:

- no auth shortcuts
- no projector calls outside the common worker
- no protocol-specific TCP/framing code in core
- no durable state hidden in memory rows

Sync cadence belongs in `sync::worker`, not in the daemon. The daemon's timer is
only a wakeup edge. The daemon-facing sync `Tick` catches up the sync index,
chooses whether to start a round, and drains projected sync input. Duplicate
compare/have/need events are correctness-safe, but a live daemon should avoid
wasteful overlapping rounds.

Manual finite sync listeners are deprecated. Daemon behavior needs black-box
coverage through real `topo start` processes.

# Appendix: Negentropy, dependencies, and dedupe

## Plain negentropy

Negentropy is a recursive equality query over a sorted set of event ids.

For a range-tree node `v`, define:

```
R_v = locally present root events whose sync key is inside range(v)
F_v = Hset("root", R_v)
```

A sync compare event from connection `C` carries `(workspace_id, node,
count, fingerprint)`. Starting sync is not a separate protocol concept; it is
just the top-level compare over the root node.

```
compare(v, remote_count, remote_fingerprint):
  if remote_fingerprint == F_v:
    return []
  else if v is splittable:
    return child compare events
  else:
    return have-id events for ids in R_v
```

There is no protocol session id required for correctness. Duplicate compares
are harmless because the compare answer is a pure function of projected state.
The top-level compare starts a round of work for a connection. The sync worker
should avoid creating a new root compare while that connection has recent
sync or bulk-transfer activity.

## Dep-aware negentropy

Dep-aware negentropy uses the same equality query, but the fingerprint for a root range also includes the present external dependencies required by those roots.

For every root event `r`, maintain a cached transitive dependency set:

```
D(r) = transitive event ids required by r
```

For each range-tree node `v`:

```
R_v = local root events inside range(v)
Q_v = union D(r) for r in R_v
X_v = Q_v \ R_v
P   = locally present event ids

F_v = Hset("root", R_v) + Hset("dep", X_v intersection P)
```

`X_v` is the invariant: it contains deps required by roots in `v` that are not already satisfied as roots inside `v`.

Projection maintains this incrementally. On inserting root `r` at leaf `L`:

```
add r to root membership on path L -> root

for each d in D(r):
  for v in path L -> root:
    if d is a root inside v:
      stop
    add requirement d to external deps for v
    if d is present locally:
      add d to present external dep hash for v
```

Use refcounts for `(node, dep_id)` and separate hash domains for roots and deps. A dep contributes to a node hash only when its refcount transitions `0 -> 1`, and is removed only when it transitions `1 -> 0`. This prevents duplicate dependency edges from double-counting or XOR-canceling.

When an event `d` becomes present, update the present-external-dep contribution for nodes that already require `d`. When `d` also becomes a root inside some node, it satisfies that dep for the node and all ancestors, so the external-dep contribution stops at the first satisfying node.

This is the same dep-aware comparison computed by poc-7's session code, but materialized as projected state instead of rebuilt as an on-demand session snapshot.

## Connection-scoped sync events and outbox

Sync protocol messages are connection-scoped events. They are not durable shared
events and do not need signatures. The connection already authenticates the
endpoint pair; the messages are only hints:

```
compare this node
I have these ids
I need these ids
```

They still use the normal event model: a module `codec.rs` defines canonical
bytes, and `event_id = BLAKE3(canonical_event_bytes)`. `connection_id` is part
of the canonical sync event, so ids for otherwise identical sync messages do not
overlap across connections.

The current POC event shape is the plain range-negentropy baseline:

```
SyncCompare(connection_id, start_timestamp, end_timestamp, count, fingerprint, response_requested)
SyncHaveId(connection_id, timestamp, event_id)
SyncNeedId(connection_id, event_id)
```

The durable dep-aware target keeps the same module shape but extends range
identity from raw timestamps to a workspace/sync-key range:

```
SyncCompare(connection_id, workspace_scope, node, count, fingerprint)
SyncHaveId(connection_id, workspace_scope, node, event_id)
SyncNeedId(connection_id, workspace_scope, event_id)
```

The current POC uses real connection-scoped sync events: `SyncCompare`,
`SyncHaveId`, and `SyncNeedId`. There is no sync packet/frame event. Outbound
and inbound are not encoded in those canonical bytes. They are connection-scope
projection context:

```
EventScope::Connection(Outgoing { connection_id })
  -> projector writes connection-scoped byte cache + id-only transit outbox row

EventScope::Connection(Incoming { connection_id })
  -> projector writes sync.inbound_events
```

Inbound transit bytes are unwrapped by `transit_in`, decoded as the same
canonical sync event bytes, admitted with incoming connection scope, projected
to `sync.inbound_events`, and then read by `sync/worker.rs`. Core owns only TCP
length framing; protocol event modules own event bytes and transit wrapping.

Connection transit may batch several canonical inner events into one encrypted
transit blob. That is still connection-domain work, not TCP framing: the
plaintext batch is a fixed-format list of canonical event bytes, and core sees
only one opaque `[u32 length][bytes]` frame for the resulting transit blob. The
batch exists to keep the sender fed and to let the receiver project a coherent
set of inbound sync events before the sync worker drains `sync.inbound_events`.

Sync request events are not shared durable data. They are connection-scoped
transient facts by default. A debug or trace mode may choose durable storage for
the sync work rows, but that is a storage/debug choice, not protocol truth.

Projectors do not write to sockets and do not emit events. They only maintain
sync/outbox queue rows. Commands are the only place new semantic events are
created. Workers may decide that a follow-up sync event is needed, but they
express that decision by calling a module command and admitting its
`ProposedEvent`s. Workers may also admit canonical bytes that already exist,
such as bytes received from a connection, but decoding existing bytes is not
event creation. A worker may write an id-only `transit.outbox` row for an
already-existing durable shared event requested by `NeedId`; that row is send
work, not a newly created event.

There is no distinct `SyncStartRequested` protocol event in the base design.
The current CLI runs `sync::worker::Work::Start`; that input is local worker
control, not wire protocol. Today the worker fans out across known routed
connections, calls `compare::commands::start`, and returns an outgoing root
`SyncCompare` for admission. Once the materialized sync index exists, the same
input first catches the index up and then calls the root-compare command for each
selected connection. The first protocol event on the wire remains
`SyncCompare(root)`.

```
topo sync
  -> sync::worker::run(Work::Start)
  -> compare command from current sync index/context
  -> proposed outgoing root SyncCompare events
  -> common event pipeline admits events

Outgoing-scoped SyncCompare / SyncHaveId / SyncNeedId projected
  -> local durable connection_scoped_events(event_id, bytes)
  -> temp outbox(connection_id, event_id)

Incoming transit bytes
  -> transit_in runs transit projector
  -> sync::inbound_record_from_connection_bytes(connection_id, bytes)
  -> common event pipeline admits incoming connection-scoped event

Incoming-scoped SyncCompare / SyncHaveId / SyncNeedId projected
  -> temp sync.inbound_events(connection_id, event_id, bytes)

sync::worker.run
  -> drains sync.inbound_events by connection
  -> command(ctx, params) -> proposed SyncCompare / SyncHaveId / SyncNeedId
  -> or id-only temp outbox row for requested durable event id
  -> common event pipeline admits proposed sync events

transit_out::run
  -> prefix-scans temp outbox(connection_id, event_id)
  -> transit_wrap command returns transit bytes
  -> writes core TCP send queue rows for those bytes
```

The current implementation keeps a timestamp-ordered shared-event feed in the
common event schema. The sync worker owns the process-local sync index over
that feed plus catch-up timing and queue consumption: it catches the index up before
response work, calls sync commands over explicit read context, and writes the
resulting event/outbox rows. In the current CLI each command is a fresh process,
so the index may rebuild once at command start. In the intended long-lived
control loop it stays warm and receives only new applied shared events.

`topo sync` starts at the root timestamp range. `topo sync today` is a narrow
POC selector: it starts the same compare protocol at the synthetic day bucket
containing the newest local timestamp. Test-event commands that create
"recent" roots place them in the next timestamp bucket so old dependencies are
outside the selected range. When a leaf advertises root ids, the worker also
advertises the present transitive dependency closure for those roots. The
worker suppresses duplicate `HaveId`s per connection, so many recent leaves
that share one old dependency closure do not resend the same closure ids over
and over. This proves the core dep-aware shape: recent roots can be synced and
projected even when old dependencies sit outside the selected timestamp range
and the receiver has none of them yet. It is not the final dep-aware invariant
because equal root hashes still do not include present external-dep hashes.

The next performance and correctness step is to add a durable shared-event feed
cursor and the full dep-aware summary state. If that state remains in memory,
the durable cursor can be just enough to know what must be replayed into the
warm index after restart; it does not need to make every range node durable.
Use an apply/feed sequence, not event timestamps, as cursor order. Catch-up
updates and cursor advancement are one atomic unit from the worker's point of
view. Prefer per-workspace indexes and aggregate the allowed workspace scopes
for a connection at response time rather than maintaining per-connection
negentropy indexes.

Duplicate worker output collapses because connection-scoped sync event bytes are
deterministic and `outbox` is unique on `(connection_id, event_id)`.

## Negentropy implementation plan

Keep the current file shape. Do not add a separate `negentropy/` module unless
it defines a real event type. The implementation plan is:

1. Preserve the current POC boundary. `sync/compare`,
   `sync/have_id`, and `sync/need_id` stay leaf event modules. Their projectors
   remain row-only: outgoing scope writes connection-scoped bytes plus temp
   outbox rows, incoming scope writes `sync.inbound_events`. `sync/commands.rs`
   chooses compare/have/need responses from explicit context;
   `src/workers/sync.rs` owns the process-local index shape, scans queues,
   catches up the index, writes transit out rows, and consumes work.
2. The current code already has real range negotiation: `SyncCompare` names an
   inclusive timestamp range and carries a count/fingerprint summary;
   mismatched ranges split; small leaves emit `SyncHaveId`; missing ids emit
   `SyncNeedId`; received needs queue id-only temp outbox rows. This replaced
   the old whole-set bucket shortcut and is covered by black-box TCP tests,
   including a 10k-history/one-new-event incremental guard.
3. Add a shared-event feed in `protocol/event_modules/schema.rs` or the closest
   common event-worker schema. The common event worker writes one feed row for
   each admitted shared event in the same transaction that records the event.
   Use a monotonically increasing feed/apply sequence in the row key, not event
   timestamps. Transient sync events and rejected bytes do not enter this feed.
4. The current POC already has process-local sync index state in
   `src/workers/sync.rs`. If we need restart-time replay to be bounded, add
   `sync.index_cursor` to `sync/schema.rs` and a monotonic shared-event feed in
   the common event schema. Keep range nodes in memory unless measurements show
   restart rebuild is the real bottleneck.
5. Keep `src/workers/sync.rs` responsible for index catch-up before response
   work. It should drain the shared-event feed after the cursor, update the
   process-local index, and advance any future durable cursor in the same
   transaction as cursor writes.
6. Keep every newly created sync protocol item on the command/admission path.
   The sync worker may call module commands and return proposed events to the
   common event pipeline; it must not hand bytes to transit or write core
   network rows. Connection transit may batch many outbox ids into one encrypted
   transit blob; core TCP still owns only the outer length frame.
7. Add the full dep-aware invariant without changing the worker boundary. The
   current POC sends present dependency closure ids with leaf root ids. The next
   step is to maintain known and present transitive-dependency closure caches,
   dep waiters, and range-node dep summaries. Compare range nodes using root
   hash plus present external-dep hash so "I have the root bytes but lack an old
   dependency" is still detected.
8. Replace the synthetic timestamp-day selector with the durable dep-aware
   selector. It should select a root range for the current day's sync key while
   dep-aware sends may include older dependencies outside that root range. If
   command-generated test events need wall-clock-shaped timestamps, add that
   control to the closest test-event CLI, not to the harness.

New black-box limits should be tiered so ordinary validation remains useful:

- keep the existing default 10k sync perf test and large-payload test;
- add a default or short `50k x 256B` content sync test if runtime stays low;
- add ignored heavy `100k` and `500k` content sync tests with events/s and
  MiB/s measured from `sync` command start to receiver count convergence;
- keep the default `sync today` shared-closure test: 10k old dependency-cascade
  events are outside the selected range and absent on the receiver, 10k recent
  roots across many leaves share that same old closure, and the receiver
  projects all roots after receiving the deduped closure through real TCP;
- add a sharper full-invariant test: the receiver already has the recent root
  bytes blocked but lacks an old dependency; equal root hashes should still
  trigger dep-aware repair through the external-dep hash;
- add ignored dep-perf tests for a transitive old chain feeding one recent
  root, with at least `1k` and `10k` chain variants, proving response-time
  request handling reads precomputed closure rows instead of recursively
  walking the graph.

Keep the storage split explicit:

```
event_modules.events(event_id, canonical_event_bytes, status, ...)
connection.connection_events(event_id, canonical_request_or_connection_bytes) # local durable, TTL-purged
connection.connection_scoped_events(event_id, canonical_event_bytes)   # local durable, TTL-purged
transit.outbox(connection_id, event_id)                             # temp
sync.inbound_events(connection_id, event_id, canonical_event_bytes)     # temp
sync.index_*                                                           # future durable sync-owned index tables
```

`connection/worker.rs` resolves an outbox `event_id` first from durable shared
event storage, then from local connection-scoped event storage. Sync modules
do not batch ids into transport frames and do not create transit blobs. They
either propose new connection-scoped sync events through commands or write
id-only temp outbox rows for already-existing durable event ids requested by the
peer.

Outgoing dedupe belongs at the temp `outbox` boundary and the per-connection hot
queue, not in every projector's context. Projectors should not need
`recently_sent` sets. If suppression beyond pending-buffer dedupe is needed
later, add an explicit recent-send table with TTL instead of turning outbox into
durable truth.

## Incoming buffer dedupe

Core TCP and core network queues remain byte-only. On receive, a durable inbound
buffer can hash bytes before parsing:

For the minimal reactive POC this buffer can be memory-only or skipped: the socket reader wakes the inbound-byte loop immediately, and recurring sync can recreate transient control traffic after a crash. When durable ingress is enabled, use the shape below.

```
wire_id = BLAKE3(bytes)

inbound_bytes:
  wire_id primary key
  bytes
  status

inbound_observations:
  wire_id
  connection_id
  remote_endpoint_id
  ip
  port
  first_seen_at
  last_seen_at
  seen_count
```

The incoming buffer is idempotent by `wire_id`. Source observations are tracked separately so address changes are diagnostics and dialing hints, not event semantics. Inner canonical event bytes unwrapped by the transit projector re-enter the same inbound processing path and dedupe again by their own canonical bytes.

Canonical-event processing only calls sync suppression after parse succeeds and the canonical event id is known. Invalid bytes may be deduped as bytes, but they are not event ids.

## Transit wrapping

Dedupe deterministic send intent before transit wrapping.

```
NeedId
  -> SendEvent(connection_id, inner_event_id)
  -> outbox(connection_id, send_event_id)
  -> transit_out::run
  -> connection.wrap(connection_id, inner_event)
  -> core tcp_send_queue(target: ip/port or socket_id, bytes: transit_blob)
  -> protocol TCP frame/write
  -> delete sent outbox rows
```

Bootstrap and repair traffic uses `connection.wrap_bootstrap(remote_endpoint_id, inner_events)`. Ordinary sync/control/event traffic uses `connection.wrap(connection_id, inner_events)`.

If send fails, leave the temp `outbox` rows for retry and back off the
connection sender. If the process crashes before retry, later sync recreates the
work. Dedupe remains `(connection_id, event_id)` based, not ciphertext based.

The receiver still validates inner events normally after decrypting. Network sync messages can cause work to be attempted, but they cannot make invalid durable events valid.

# Appendix: Documentation quality bar

Write this plan, implementation docs, and significant inline comments in the style of high-quality systems documentation: concrete, narrow, and audit-friendly. The model to emulate is Stellar Core's documentation:

- Overview and component map: https://github.com/stellar/stellar-core/blob/master/docs/readme.md
- Process and network architecture: https://github.com/stellar/stellar-core/blob/master/docs/architecture.md
- History system design and failure behavior: https://github.com/stellar/stellar-core/blob/master/docs/history.md
- BucketList mental model, formal model, examples, and cost analysis: https://github.com/stellar/stellar-core/blob/master/src/bucket/BucketListBase.h
- LedgerManager thread/data-flow diagram and invariant `LCL <= A <= Q <= H`: https://github.com/stellar/stellar-core/blob/master/src/ledger/LedgerManager.h
- OverlayManager responsibility and message taxonomy: https://github.com/stellar/stellar-core/blob/master/src/overlay/OverlayManager.h
- SCP/Herder separation between abstract protocol and application-specific driver: https://github.com/stellar/stellar-core/blob/master/src/scp/readme.md and https://github.com/stellar/stellar-core/blob/master/src/herder/readme.md

For every important component, document the same surface:

```
Purpose
Ownership / non-ownership
Interfaces
State
Invariants
Flow
Failure / restart behavior
Performance notes
Testing hooks
```

Style rules:

- Start with the component's responsibility, not implementation trivia.
- Say what the component does not own.
- Define vocabulary before relying on it.
- Prefer data flow and lifecycle descriptions over architecture slogans.
- State invariants explicitly, as small facts, formulas, or ordering rules.
- Explain a mechanism first with the simplest mental model, then with the precise rule.
- Use examples when a mechanism is subtle enough that the rule alone is easy to misread.
- Include operational consequences: crash, restart, retry, slow peer, invalid input, and overload behavior.
- Treat performance constraints as part of the design.
- Link prose to concrete files, functions, tables, events, or interfaces.
- Use inline comments only for non-obvious ownership, ordering, threading, safety, or performance rules.
- Keep small components brief; let complexity earn length.

Code-structure lessons from Stellar Core:

- Source directories should mark semantic subsystem boundaries, as in Stellar's `scp`, `herder`, `overlay`, `ledger`, `bucket`, `history`, `work`, and `transactions` directories. Avoid generic dumping grounds.
- Large runtime components should have a small public interface and a concrete implementation, following Stellar's `OverlayManager` / `OverlayManagerImpl`, `HistoryManager` / `HistoryManagerImpl`, and `Application` / `ApplicationImpl` pattern.
- Abstract protocol machinery should be separated from application meaning. Stellar's `scp` is protocol-generic; `herder` maps slots and values onto ledgers and transaction sets. Here, negentropy is the generic comparison mechanism; sync event modules map it onto workspace roots, deps, have/need/send events, and outbox writes.
- Managers own lifecycle, scheduling, and resource wiring. Helpers own algorithms. Do not let managers accumulate domain policy.
- Long-running work should be represented explicitly, as Stellar does with `work/`, `catchup/*Work`, and `historywork/*Work`. Hidden background behavior should become an worker, table row, or effect owner.
- Data structures should encode workload assumptions. Stellar's BucketList is shaped around temporal churn, incremental hashing, and catchup. Here, dep-aware negentropy should be a projected incremental tree/cache, not a session-time rebuild.
- Canonical encoding is a hard boundary. Stellar uses XDR for hashed, historical, and peer-message forms. Here, `codec.rs` produces canonical event bytes for ids, storage, projection, replay, and dedupe; connection wrapping is a separate transit layer. The codec should name the fixed-per-event-type format; shared utilities should do the repetitive binary lifting.
- Prefer immutable snapshots and stable ids at concurrency boundaries.
- Keep the first concurrency model legible: one control-loop writer, one sender owner per connection, bounded work at explicit boundaries.
- Failure behavior should be local: a failed send backs off one connection; a duplicate event is admitted once; a memory outbox can be regenerated; invalid bytes stop before event semantics.

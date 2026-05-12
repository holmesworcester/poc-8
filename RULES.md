# Rules

## Enforcement Checklist

Legend: **typed** means Rust types make the invalid shape hard or impossible to
express; **static** means a boundary test scans or inspects source; **partial**
means the guard exists but does not prove the whole rule; **uncovered** means
the rule is still prose/review only.

## TODO

- Add an explicit rule that commands may only provide ergonomic preflight
  validation. Any invariant required for accepting shared/received protocol
  state must be enforced by codecs, pure projectors over event context, or
  storage/admission constraints that received events cannot bypass.
- Search the poc-6 and poc-7 RULES/AGENTS-equivalent files and pull in any
  significant applicable security and safety rules. Ask before importing any
  rule whose fit with poc-8's event-module boundaries is unclear.
- Add boundary tests proving receive-only metadata for connection bootstrap
  records cannot be admitted outside the network admission path. Invite-secret
  authorization may live in active connection handling only if raw admission
  cannot forge the receive context needed to project routes.
- Add boundary tests for sync exfiltration scope: inbound `need_id` handling may
  queue bytes only through a worker/command path that checks the requested event
  is shared with the remote endpoint through a mutual workspace.
- Add boundary tests that enumerate production shared event tags and prove every
  durable shared-state mutation is either signed by an authorized dependency,
  self-authenticating as a workspace root, or explicitly excluded as local /
  connection-scoped bootstrap work.

| Rule | Status | Enforcement |
| --- | --- | --- |
| The protocol is a fact graph: commands create canonical fact nodes, dependencies/receive/provenance describe edges or local edge context, projectors derive rows from accepted facts, and workers move/admit/wrap facts through explicit queues. | partial | [src/workers/README.md](src/workers/README.md), [EventRecord](src/protocol/event_modules/types.rs), [CommandOutput](src/workers/common_event_pipeline.rs), [ProjectionOutput](src/workers/common_event_pipeline.rs), queue-schema checks in [rules_boundary_test.rs](tests/rules_boundary_test.rs). |
| Commands create new semantic events or transport bytes from explicit params/context and do not drive workers, CLI, TCP, queues, rows, effects, or storage writes. | typed + static | [CommandOutput](src/workers/common_event_pipeline.rs), `command_output_contains_events_not_state_changes`, `event_module_commands_do_not_mutate_storage_directly`, `event_module_commands_do_not_drive_workers_cli_or_transport_queues` in [rules_boundary_test.rs](tests/rules_boundary_test.rs). |
| Proposed event ids are deterministic from canonical bytes. | typed + static | [ProposedEvent](src/workers/common_event_pipeline.rs), `proposed_event_carries_deterministic_id_and_record`. |
| Canonical event projectors return row-shaped output only and do not emit events/effects, query storage, or perform transit/crypto work. The transit projector is the explicit network-admission exception and may authenticate/decrypt a queued frame into `canonical.in` rows. | typed + static | [ProjectionOutput](src/workers/common_event_pipeline.rs), `projection_output_contains_rows_and_labels_not_events`, `event_module_projectors_are_row_only_boundaries`, `event_module_projectors_do_not_query_storage_directly`, `event_module_projectors_do_not_do_transit_or_crypto_work`. |
| Every projector has pure functional behavior tests. | static + partial | `projector_files_have_pure_functional_tests` requires each `projector.rs` to carry test code; review verifies the tests cover row/label output, explicit context handling, and rejection paths without storage or worker side effects. |
| Projector context only contains events already accepted by their own projector. | typed + tested | The generic worker blocks on `EventStatus::Applied` before loading dependency context; Ready/Blocked/Rejected/failed events are invisible to dependent projection. Covered by `worker_never_surfaces_failed_projection_as_dependency_context` in [worker_contract_test.rs](tests/worker_contract_test.rs). |
| Core is protocol-agnostic queue/storage support. | static | `core_does_not_import_protocol`, `core_does_not_own_protocol_worker_or_wire_codec`, `core_has_no_protocol_io_vocabulary`, `core_has_no_domain_vocabulary`, `common_event_pipeline_has_no_domain_branching_vocabulary`, `core_files_do_not_contain_sync_protocol_logic`. |
| Core stays small and named. | static | `core_file_set_stays_small_and_named`. |
| Core store is a schema runner and row substrate, not a protocol fact store. | typed + static | [Schema](src/core/store.rs), [SchemaDefinition](src/core/store.rs), [TableName](src/core/store.rs), [TableRow](src/core/store.rs), `core_store_is_row_only_not_protocol_fact_storage`, `core_store_applies_only_declared_schemas`, `store_table_rows_use_typed_table_names`. |
| Protocol event modules own common fact/status/dependency tables. | typed + static | [event_modules/schema.rs](src/protocol/event_modules/schema.rs), `protocol_event_schema_owns_common_fact_indexes`. |
| Generic Crux, CLI command driving, and daemon runtime mechanics are core, not protocol. | typed + static | [EffectHandler](src/core/crux_runner.rs), [crux_runner.rs](src/core/crux_runner.rs), [CliCommand](src/core/cli.rs), [core/daemon.rs](src/core/daemon.rs), `crux_core_is_isolated_to_core`, `daemon_runner_is_core_and_protocol_supplies_workers`, core vocabulary checks. |
| Worker implementations live in the central worker catalog and follow the universal worker contract. | static + partial | [src/workers](src/workers), `worker_implementations_live_in_workers_folder`, `workers_folder_has_standard_catalog_shape`, and the plan in [src/workers/README.md](src/workers/README.md). |
| `mod.rs` files are plumbing only, not command/work orchestration facades. | static | `leaf_mod_rs_files_are_declarations_only` and `event_module_mod_rs_files_do_not_orchestrate_commands_or_work` in [rules_boundary_test.rs](tests/rules_boundary_test.rs). |
| Event modules use canonical directory/file shape. | static | `event_modules_are_directories`, `domain_roots_contain_only_children_and_shared_domain_files`, `domain_root_cli_requires_cross_child_scope`, `event_module_files_use_only_standard_concern_names`, `child_event_module_directories_have_canonical_shape`, `event_modules_do_not_use_dumping_ground_directories`. |
| `event.rs` is forbidden; semantic types live in `types.rs`; codecs do encode/decode only. | static | `event_modules_do_not_use_event_rs`, `codec_files_do_not_define_public_types`, `codec_modules_have_type_files`. |
| Workers expose one obvious entrypoint and do not own CLI parsing or user formatting. | static + partial | `worker_files_export_only_run_as_public_entrypoint`, `worker_files_do_not_own_cli_parsing_or_user_formatting`; compatibility facades must delegate to explicit queue workers instead of hiding new behavior. |
| Connection and sync operational queue logic lives in workers, not app/network/core. Protocol decisions live in commands/projectors. | partial | [transit_in](src/workers/transit_in.rs), [event_admission](src/workers/event_admission.rs), [transit_out](src/workers/transit_out.rs), [sync](src/workers/sync.rs), [sync commands](src/protocol/event_modules/sync/commands.rs), `sync_worker_drains_projected_rows_not_direct_ingest_work`; static checks prevent core/network leaks, while protocol-action ownership is enforced by named worker entrypoints, command boundaries, and focused tests. |
| `protocol/app` is forbidden; CLI behavior is scoped to parsing, calling commands/queries/named worker work, and formatting results; the app shell chooses a protocol spec and core runs the generic daemon. | typed + static | [CliCommand](src/core/cli.rs), [protocol/cli.rs](src/protocol/cli.rs), [core/app.rs](src/core/app.rs), [core/daemon.rs](src/core/daemon.rs), `protocol_app_layer_does_not_exist`, `daemon_runner_is_core_and_protocol_supplies_workers`, `cli_files_live_with_event_modules_or_the_protocol_shell`, `scoped_cli_files_do_not_own_transport_or_cross_cli_operations`, `sync_cli_is_deprecated`. |
| CLI scenario/check/expect definitions live beside relevant event modules. | static + partial | `cli_harness_is_process_only` keeps the shared harness generic; scoped `cli_tests.rs` migration and typed scenario declarations are still prose/planned. |
| Network boundary is opaque core queues plus core TCP. | typed + static | [NetworkTarget](src/core/network_queues.rs), [OutboundNetworkRow](src/core/network_queues.rs), [InboundNetworkRow](src/core/network_queues.rs), `network_queue_uses_single_target_indexed_outbound_table`, `store_exposes_generic_prefix_scan_not_network_methods`, `tcp_uses_network_queue_helpers_not_table_names`, `protocol_network_module_does_not_exist`, `protocol_cli_does_not_use_socket_primitives`, `core_network_queues_are_opaque_byte_rows`, `core_tcp_is_opaque_frame_transport`. |
| Connection route learning is part of connection projection, not a transport-target event module. | typed + static | [ReceiveMetadata](src/protocol/event_modules/types.rs), [connection/schema.rs](src/protocol/event_modules/connection/schema.rs), `connection_routes_are_projected_from_receive_metadata`. |
| Transit out is memory-local id-only send work; transit batches canonical inner events. | typed + static + partial | Transit out row helpers stay crate-internal so centralized workers can own queue movement; `transit_out_is_id_only_and_transit_batches_inner_events` checks the table shape, and connection module tests cover memory restart/stale-row cleanup. Exact batch sizing remains implementation/test coverage. |
| Network admission rejects remote local-only events and rejects shared workspace events unless the transit sender endpoint is mutually in that workspace with the local endpoint before delegating to the main pipeline. | partial + tested | [transit_in](src/workers/transit_in.rs) drains raw network rows through the transit projector; [event_admission](src/workers/event_admission.rs) then classifies recovered canonical bytes by provenance: bootstrap transit only carries connection requests, connection transit only carries connection-scoped or shared events, and shared events require mutual endpoint workspace membership. Covered by transit in and event admission tests. |
| Sync direction is connection-scope context, not canonical bytes. | static | `sync_canonical_bytes_do_not_encode_inbound_or_outbound_direction`. |
| Table names and schemas are typed and declared in owning module scopes. | typed + static | [Schema](src/core/store.rs), [TableName](src/core/store.rs), `table_names_are_declared_in_schema_files`, `table_declaration_files_declare_schemas`, `row_table_declarations_use_store_schema_helper`, `store_table_rows_use_typed_table_names`. |
| Query modules are read-only CLI/reporting surfaces; worker reads live in workers and command read-context traits live in commands. | static | `event_module_queries_are_read_only`, `worker_and_command_logic_do_not_call_query_modules`. |
| `EventRecord` literals are constructed only by codecs. | static | `event_records_are_constructed_only_by_codecs`. |
| Codecs use shared binary helpers and reject trailing bytes. | static + partial | `codec_files_use_shared_binary_helpers_and_finish_reads`; this catches common drift but is not a formal fixed-width proof. |
| `types.rs` does not store encoded/canonical artifacts as semantic fields. | static | `event_module_types_do_not_store_encoded_event_artifacts`. |
| Production shared events require authority. | partial | Durable shared-state events must be signed by an authorized dependency unless they are self-authenticating root events such as `workspace`. Local-only secrets, connection-scoped protocol work, and test-only event modules are explicit carveouts. Raw `device_invite` and raw content are rejected by registry dispatch; signed identity/content projectors validate signer authority from event context. |
| Crypto behavior must be real where claimed and primitive implementations live in core crypto. | static + partial | `source_does_not_contain_fake_crypto_claims`; transit uses `core::crypto` X25519/XChaCha helpers while keeping associated-data and purpose policy in connection code. Cryptographic correctness still needs implementation review and tests. |
| Functional proof comes from black-box CLI/network tests, except pure projector/command tests. | static + partial | Existing tests spawn the real `topo` binary for sync/generate/cascade/content paths. `functional_cli_and_network_tests_use_black_box_setup` rejects protocol/store imports and known seeding shortcuts in functional CLI/network tests so initial setup cannot install domain rows or identity graphs directly. |
| Workers with bounded calls, fairness limits, and explicit inputs are the control loop. | partial | Described in [src/workers/README.md](src/workers/README.md); event admission/projection/dependency unblock, transit out, and sync expose explicit worker entrypoints and queues. The caller chooses the next worker step. |
| Rust idiom and common correctness lints pass. | static | Run `cargo clippy --all-targets -- -D warnings` in addition to `cargo test`; Clippy complements but does not replace [rules_boundary_test.rs](tests/rules_boundary_test.rs). |

## Rules Intended To Be Covered By Types And Static Checks

Prefer enforcement in this order:

1. Rust types, traits, visibility, and crate/module boundaries.
2. Static boundary tests over file paths, imports, exported names, and forbidden
   vocabulary.
3. Short prose rules for intent, review judgment, and behavior that cannot be
   proven mechanically.

The following rules should stay mechanically enforced where practical:

- Every boundary review asks these questions and turns any "yes" into cleanup
  pressure:
  - Is a `cli.rs` file doing anything beyond parsing CLI params, calling the
    closest commands/queries or named worker work items, and formatting results?
    If it owns transport, queue drains, send bookkeeping, scheduling, semantic
    selection, or helper APIs for sibling CLIs, move that behavior out.
  - Is a `mod.rs` file doing anything beyond declarations, schema aggregation,
    codec/projector dispatch, or registry trait glue? If it is a convenience
    facade for commands, queries, workers, or storage mutation, move that out.
  - Is a file under `src/workers` doing anything beyond managing queued/operational
    work, calling commands, admitting events, draining owned queues, and
    touching boundary effects it owns? If it parses CLI args or formats
    user-facing output, move that to `cli.rs`.
  - Is a `commands.rs` file doing anything beyond constructing canonical events
    or transport bytes from explicit params and narrow context? If it drives
    workers, starts queue drains, formats CLI output, opens TCP, or performs
    storage/row mutation, move that behavior out.
- Commands return `CommandOutput<T>` with `Vec<ProposedEvent>`, not rows,
  effects, or storage writes. `ProposedEvent` is constructed from an
  `EventRecord` and carries both the deterministic `event_id` and that
  canonical record.
- Projectors return `ProjectionOutput` with rows, exact row deletes, and labels,
  not events.
- `commands.rs` is reserved for event modules. CLI adapters live in
  module-local or domain-local `cli.rs`; `src/protocol/cli.rs` only aggregates
  scoped command specs, and `src/core/cli.rs` only dispatches generic command
  specs.
- `event.rs` is forbidden. Semantic event types live in `types.rs`; canonical
  wire parsing and formatting live in `codec.rs`.
- Codec files do not define public semantic types, and every codec module has a
  sibling `types.rs`.
- Domain roots contain only child event modules plus shared domain files:
  `mod.rs`, `schema.rs`, `queries.rs`, `types.rs`, `commands.rs`, and
  `cli.rs`. Domain commands are for cross-child protocol decisions over
  explicit context. Worker
  implementations live under `src/workers`; domain roots may re-export worker
  modules for compatibility while the codebase migrates.
- Child directories under `event_modules/<domain>/` are canonical event modules
  and must carry `mod.rs`, `types.rs`, and `codec.rs` at minimum. Add
  `schema.rs`, `projector.rs`, `queries.rs`, `commands.rs`, or `cli.rs` only
  when that concern exists. Shared domain schema, queues, and helper types live
  at the domain root instead of masquerading as event modules.
- Event-module files use standard concern names only. New concern files require
  an explicit boundary decision and a static-test update.
- `mod.rs` files have one job: declare child modules and provide shallow
  registry/catalog dispatch such as schema aggregation, tag-to-codec decoding,
  and tag-to-projector routing. They must not own commands, queries, workers,
  TCP exchange, queue draining, storage mutation, scheduling loops, or send
  bookkeeping.
- Files live at the tightest scope that owns the behavior. A domain-root
  `cli.rs` is only for commands spanning multiple child modules; a command for
  one leaf event type belongs in that leaf's `cli.rs`.
- Dumping-ground directories such as `jobs`, `cli_commands`, `runtime`,
  `state`, and algorithm-only `negentropy` are forbidden under
  `event_modules`.
- Workers live under `src/workers`, not inside leaf event modules. Leaf modules
  write queues; the worker catalog coordinates shared queues and cursors through
  named workers.
- Core never imports protocol modules and does not contain protocol vocabulary
  such as connection, transit, sync, outbox, bootstrap schema, admission
  workers, blocking policy, or wire codec helpers. Core may own generic TCP
  mechanics and opaque network queue mechanics.
- `core/store.rs` is only a schema runner and generic row substrate. It may
  define `Schema`, `SchemaDefinition`, `StorageClass`, `TableName`, `TableRow`,
  transactions, row insert/replace/delete, exact row reads, prefix scans, and
  the generic key/value row-table schema helper. It must not define event ids,
  event records, event statuses, labels, missing-dep edges, protocol indexes,
  network queue semantics, or any protocol table schema. Protocol tables are
  declared by `schema.rs` files and passed to store at open time.
- `protocol/event_modules/schema.rs` owns the protocol-wide fact/status,
  missing-dep, ready-event, partition-index, and label rows used by the
  common event pipeline. Scoped event modules own their own `schema.rs`
  declarations for domain rows and queues.
- Core has a small allowlisted file set and must not contain domain vocabulary
  such as workspace, content, endpoint, identity, invite, or message.
- Generic Crux command driving and generic CLI command dispatch belong in core.
  Protocol code must not define Crux app/model/effect layers or import
  `crux_core`; core CLI code must not know Topo command names or module
  semantics.
- Protocol worker owns admission/apply plumbing; concrete domain branching
  belongs behind the protocol module registry.
- Generic projector context is a validity boundary. A dependency can appear in
  `EventWithContext` only after its own projector accepted it and the worker
  committed its `Applied` status. Events that are merely stored, Ready, Blocked,
  Rejected, or failed during projection must not be visible to dependent
  projectors.
- `src/protocol/event_modules/mod.rs` is registry plumbing only. It may declare
  modules, own the protocol module list, aggregate schemas, dispatch
  parse/project calls by event tag, expose registry state accessors, and
  implement registry traits. It must not become a convenience facade for user
  commands or protocol work: no `create_*`, `generate_*`, `start_*`,
  `drain_*`, `mark_*`, timestamp selection, dependency selection, invite/local
  endpoint orchestration, route/outbox policy, command-output merging, or
  worker input decisions. Put that behavior in the closest owning `commands.rs`
  or `src/workers` implementation; keep user parsing and output in the closest
  `cli.rs`.
- Sync modules do not own TCP/frame IO, and core/network code does not contain
  sync protocol logic.
- The long-lived daemon runner is core runtime machinery. It lives at
  `src/core/daemon.rs`, is registered by the generic app shell, and must not be
  a `src/protocol` module or a protocol command aggregator concern. Protocols
  supply worker objects through the `src/workers` catalog.
- Event-module commands do not mutate storage directly. Event-module
  projectors do not query storage directly.
- Event modules do not import runtime/control-loop/transport effect machinery.
  The top-level protocol registry is the only event-module file that implements
  the protocol worker registry trait.
- Projectors are row-only boundaries: no `CommandOutput`, `ProposedEvent`,
  `EventRecord`, IO effects, transport work, or transit creation.
- Table names and schemas are declared in the owning `schema.rs` scope as typed
  `TableName` and `Schema` values; projectors and queries use those
  declarations. Ordinary row tables should use `Schema::durable_row_table` or
  `Schema::memory_row_table` so the module owns the table name while store owns
  the uniform row shape and storage class.
- `EventRecord` literals are constructed by codecs. Other code asks codecs to
  produce records or proposed events.
- `codec.rs` uses shared binary helpers and finishes reads so trailing bytes are
  rejected.
- `types.rs` does not store encoded/canonical event artifacts as semantic
  fields.
- `protocol/network.rs` is forbidden. Raw TCP mechanics live in `core/tcp.rs`.
  Opaque inbound/outbound byte queues live in `core/network_queues.rs`.
  Protocol workers may read/write those core queue row types, but only event
  modules interpret bytes. There is one outbound network queue table with
  target metadata encoded into each row key for bounded target claims; do not
  create dynamic per-target queue tables.
- `core/tcp.rs` uses `core/network_queues.rs` helpers for queue rows. It must
  not name queue tables or encode/decode queue row keys directly.
- `tests/cli_harness` stays process-only. It may know how to build and run the
  `topo` binary, allocate temp db paths, reserve ports, and expose stdout/stderr
  helpers. It must not know command names, global flag policy, invite syntax,
  retry policy, output keys, or expected results.
- Source tests reject fake-crypto terminology that would let placeholder crypto
  be named as real protection.

When a prose rule becomes mechanically enforceable, add the type boundary or
static check and shorten the prose. Keep prose for realness, black-box proof,
crypto quality, performance expectations, and design rationale.

`tests/rules_boundary_test.rs` is the current architectural linter. Keep it
fast, deterministic, and runnable as `cargo test --test rules_boundary_test`.
If it grows beyond test-shaped source checks, move the same checks into an
`xtask`/lint command instead of weakening them.

Run Clippy as a separate linter: `cargo clippy --all-targets -- -D warnings`.
Clippy catches Rust mistakes and suspicious idioms; the architectural linter
catches folder shape, import direction, and protocol vocabulary.

## Commands Live In Event Modules

Commands belong under `event_modules`, alongside the event types, codecs,
projectors, queries, and module-owned tables they operate on.

CLI, RPC, workers, and other adapters should dispatch into module commands
instead of constructing canonical event bytes directly. Adapters own
input/output shape; event modules own protocol and domain semantics. An adapter
may choose which command to invoke from explicit user input or queued work, but
it must not invent semantic defaults by querying broad state. If a command needs
the next timestamp, a local endpoint, a route, a dependency set, or a sync
range, that read belongs in a narrow command context or in the owning worker.

Commands receive explicit input values plus narrow read context values. They do
not mutate SQLite, open transactions, drain queues, or call broad apply loops.
They return `CommandOutput` with proposed canonical events only. Commands must
not return rows or effects. The API that runs a command is responsible for
admitting those proposed events through the worker; admission returns the
event ids for chaining.

Projectors return `ProjectionOutput` with table rows, exact row deletes, and
generic event labels only. They cannot emit events. If projection discovers
follow-on work, it writes a module-owned queue row; a module worker reads that
queue, queries context, runs a command, and sends the command's proposed events
back through the worker. Generic event labels are protocol event-module state
declared under `protocol/event_modules/schema.rs`; they are not a core store
concept.

Workers are the active boundary. A worker implementation under `src/workers`
exports exactly one public free function, `run`; work/output types may be
public, and all helper functions stay private. Projectors do not perform IO or
emit effects. Event-module commands do not perform IO either; they construct
canonical events or transport bytes from explicit input and context. Workers own
claiming input, fairness, bounded work, retries, calling commands, admitting
proposed events, and writing output queues at the next boundary.
Workers do not return ad hoc effects.

The intended shape is:

```text
event_modules/<domain>/<module>/commands.rs
  command(ctx, input) -> CommandOutput { value, events: Vec<ProposedEvent> }

event_modules/<domain>/<module>/codec.rs
  Event <-> CanonicalEventBytes

event_modules/<domain>/<module>/types.rs
  Event type and semantic constants

event_modules/<domain>/<module>/projector.rs
  EventWithContext -> ProjectionOutput { rows, labels }

event_modules/<domain>/<module>/schema.rs
  module-owned projection schema, indexes, queues, cursors, and storage class

event_modules/<domain>/<module>/cli.rs
  optional module-local CLI help, parameters, queries, and output formatting

src/workers/<name>.rs
  worker over explicit queues/status indexes/cursors; event modules may re-export
  the worker while imports migrate

event_modules/<domain>/cli.rs
  optional domain-level CLI registry/help for commands spanning child modules
```

Leaf event modules own event types. Domain roots may own shared `schema.rs`,
`queries.rs`, `types.rs`, and `cli.rs`. Worker implementations live in
`src/workers`. Do not create an
event-module directory for an algorithm unless it defines an actual canonical
event type.

Do not create `event.rs` files in event modules. The typed event struct belongs
in `types.rs`. `codec.rs` is only for canonical format tags, field order,
encode/decode, and event-specific parse validation. Commands belong in
`commands.rs`.

CLI commands belong in the closest relevant event module or domain root
`cli.rs`. CLI output structs and formatting live there too. Each scoped CLI file
exports `CliCommand` specs with command name, usage, help, parsing, worker
work item calls, follow-up queries, and formatting for that scope. It must not
assemble worker internals such as ready-drain loops; ask a named worker work
item to do that. `src/protocol/cli.rs` only aggregates the current protocol's
command surface and owns truly
whole-protocol commands such as `count`/`status`. `src/core/cli.rs` dispatches
generic command specs and prints returned output. It must not own domain command
semantics, help text, post-write queries, worker selection, or formatting.
Use the tightest scope possible: a command for one event type belongs in
`event_modules/<domain>/<event>/cli.rs`; a domain-root CLI file is for commands
that coordinate multiple child modules in that domain.

CLI scenario definitions should live beside the closest relevant event module
or domain root. A generic integration runner may execute those scenarios through
the real CLI and check expected output.

The intended `cli_tests.rs` contract is scoped:

- `event_modules/<domain>/<event>/cli_tests.rs` covers the black-box CLI behavior
  for one leaf event module: command params, created event ids, projection
  visibility, validation failures, and output formatting for that module.
- `event_modules/<domain>/cli_tests.rs` covers workflows spanning child modules in
  the same domain, such as invite/bootstrap/connection setup or sync request /
  response behavior.
- Protocol-level CLI tests cover cross-domain scenarios only, such as multiple
  endpoints talking over real TCP.

At every scope, the test file owns its parameters and expectations. It may define
small local typed helpers for that scope, but the shared harness remains a
minimal process runner. If a generic scenario type is introduced later, it
should be data-only: full argv, setup resources, an optional timeout, and a
checker function over stdout/stderr/status. It must not encode Topo command
semantics in the harness.

Crux stays isolated in `core/crux_runner.rs`. If a future UI/runtime wants Crux,
it can use the core runner without introducing `protocol/app`, protocol
`ProtocolMsg`, or protocol effect enums.

A module CLI command may run module queries and format text or JSON output. If
it creates events, it first calls a pure module command, then asks a named
worker work item to admit those proposed events and perform any explicitly
owned follow-up drain, then runs any query that depends on their projection
rows. CLI must not directly call broad drain work; commands that wait, poll,
or drain name that behavior in worker-owned work values.

CLI files are for user interaction, not domain logic. They may parse argv,
print help, call the closest command or worker entrypoint, submit returned
proposed events to the generic worker, and format the resulting value/query
output. They must not compute semantic values such as "next content timestamp",
"which dependencies should this event use", "ensure/create the local endpoint
then create an invite/request", "which routes should be drained", or "which
sync range means today". Those choices belong to `commands.rs` when they create
events, or to `src/workers` when they drain queues, run protocol work, or touch
module-owned operational state. CLI files must not own TCP exchange, core
network queue row bookkeeping, daemon scheduling, or operational helper APIs for
other CLI files. If another command needs that behavior, expose it through the
owning worker instead of calling a sibling `cli.rs`.

`src/protocol/event_modules/mod.rs` is even stricter than CLI. It is the module
registry and cross-module dispatch point, not a public service layer. Keep it
to declarations, schema cataloging, codec selection, projector selection, and
registry trait glue. Do not add new public helpers there just because several
callers need them. Move behavior to the closest event/domain module and have
callers import that scoped API directly.

Custom contexts for commands, projectors, and workers must be narrow DTOs, not
database-shaped snapshots. If a context can answer arbitrary storage questions,
the boundary has failed; replace it with explicit query results or a
module-owned worker query.

## Core Is Protocol-Agnostic

Core code under `src/core` must not import `src/protocol` or concrete event
families. `protocol/event_modules/mod.rs` is the protocol composition point
that knows the concrete module list.

Allowed in core:

```text
use crate::core::store::Store;
```

Not allowed in core:

```text
use crate::protocol::event_modules::Modules;
use crate::protocol::event_modules::{connection, sync};
crate::protocol::event_modules::connection::...
```

The protocol shell talks to the current protocol composition object,
`Protocol`. `Protocol` owns the event-module registry (`Modules`). The shell may
pass `Protocol` into protocol workers, but raw network mechanics go through core
`NetworkTarget`, `InboundNetworkRow`, `OutboundNetworkRow`, and TCP helpers.
Core must not import concrete protocol namespaces to get work done.

`src/workers/common_event_pipeline.rs` holds shared event pipeline types and the
compatibility runner. The explicit event workers are `transit_in`,
`event_admission`, `event_projection`, and `dependency_unblock`: together they
unwrap inbound transit into `canonical.in`, admit canonical bytes, apply
protocol blocking policy, parse new events, call projectors, apply rows, and
unblock dependents. They must not branch on connection, sync, response, or
transport-target details; that branching belongs in the module registry and
domain workers. Framed byte handling lives in `core/tcp.rs` as opaque bytes.

`protocol/wire.rs` is the shared fixed-field codec helper used by protocol
codecs. It is not core, because canonical event format is protocol surface.

`event_admission` plus `dependency_unblock` are the default Topo blocking policy.
Admission checks immediate dependencies declared by codecs before projection and
writes blocked queue rows when dependencies are missing; dependency unblock consumes
`recently_valid_events` and writes newly unblocked events back to `ready_events`.
Projectors may still write module-owned wait/blocked queue rows for semantic
blockers that are not simple dependency absence.

`store.rs` is generic storage mechanics. It applies `Schema` declarations from
core IO modules and protocol module scopes, then exposes typed table names,
opaque key/value rows, transactions, exact row reads, bounded prefix scans, and
bounded key-range scans.
It may generate the uniform `(row_key, row_value)` table shape for
module-declared row tables. It must not expose event ids, event status, labels,
missing-dep edges, sync ranges, connection/bootstrap schema, content payload
semantics, or network queue semantics as storage concepts.
`core/network_queues.rs` owns typed network queue rows and encodes them through
generic `TableRow`s. Protocol and module `schema.rs` files declare the tables
the selected protocol needs; core executes those declarations without learning
their protocol meaning.

## Proposed Events Have Deterministic IDs

Event ids come from canonical event bytes, not from projected state. The codec
or shared codec utility that constructs canonical bytes should also expose the
event id, usually as `BLAKE3(canonical_event_bytes)`, so commands can chain
proposed events without writing, re-querying, or inferring ids from projection
tables.

The write path still returns event ids as a receipt for the exact bytes it
admitted. That receipt is for status and verification: callers can confirm the
stored id matches the proposed id, learn whether the event was applied,
blocked, or duplicate, and surface pending ids when needed.

Prefer this command shape:

```text
create(input, ctx) -> CommandOutput {
  value,
  events: Vec<ProposedEvent { event_id, record }>
}
```

Use two levels of write API:

```text
append_event(proposed_event) -> Admission {
  event_id,
  status: Ready | Blocked { blocked_by } | Duplicate { status },
}

append_apply(proposed_event) -> WriteResult {
  event_id,
  status: Applied | AlreadyApplied | Blocked { blocked_by },
  admitted: Vec<EventId>,
}
```

Commands that only need a prior proposed event's id can use the proposed id
directly:

```text
let workspace = workspace::create(...)?;
let account = account::create(workspace.event_id, username)?;

CommandOutput {
  value: account.value,
  events: vec![workspace.event, account.event],
}
```

If a later event requires the prior event to be semantically applied, the worker
or API running the command admits and applies the proposed chain in order and
checks the write result. Event-module commands do not call the writer directly.

Commands that intentionally create pending work, such as accepting an invite
before the invite event has synced, may return proposed events whose admission
can block; the caller surfaces the proposed id as pending.

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
- out rows
- returned event ids

Module commands own semantic construction:

- what command input means
- which state queries are required
- which canonical events to create
- how to interpret `Applied`, `AlreadyApplied`, or `Blocked`

All state mutation still goes through canonical events and projectors.

## Event Modules Use The Clean Contract

Event modules must target the new core/protocol contract directly. Do not introduce
compatibility adapters for old `state`, `runtime`, queue, or transport APIs.
If an existing module depends on old core machinery, refactor the module until
the dependency is gone.

When migrating a boundary, retire the old path in the same commit that proves
the new path. Do not leave parallel old/new engines for the same behavior unless
one is explicitly disabled and scheduled for deletion before handoff.

The module shape is:

```text
event module =
  codec
  deps
  projector
  tables
  commands/queries where needed
```

```text
event family =
  child event modules
  shared domain tables/queries/types where needed
  domain worker where active queued/cursor work spans child modules
```

The universal contract is:

```text
CanonicalBytes -> Event
Event -> Vec<EventId>
(Event, Context) -> Projection

Projection =
  rows
```

Rows may target module-owned projection schema, indexes, labels, queues,
outbox, or purge/compaction tables. They are still rows. Projectors do not
return events or effects.

Event modules must not:

- import `crate::runtime`
- import old `crate::state` internals
- know queue table names or worker phase names
- start workers or drive the control loop
- perform transactions
- call global drain/apply functions
- write SQLite directly, except for data-only table declarations if that
  remains the chosen schema representation
- know transport implementation details

Event modules may:

- decode and encode canonical event bytes
- declare dependencies
- declare owned schema, indexes, and storage class (`durable`, `memory`, or
  `temp`)
- query through a narrow read context
- return canonical events from commands
- return declarative projector output: rows, labels, queue rows, out rows,
  and purges
- implement workers under `src/workers` that claim module-owned queue rows, call
  commands, and write explicit output queues at network boundaries

`codec.rs` describes the module's canonical/wire format: tags, field order,
and event-specific validation. Shared binary mechanics such as integer
encoding, length prefixes, fixed-size ids, truncation checks, and trailing-byte
checks belong in a format-agnostic utility, not reimplemented in every codec.

Canonical event fields should be fixed-width per event type: once the event
type tag is known, the field layout and canonical byte length are known.
Different event types may have different fixed lengths. Use fixed-size ids,
fixed-size hashes, fixed-size integers, fixed-size enum tags, and fixed-size
domain fields. Do not introduce varints, maps, self-describing encodings,
nullable ad hoc fields, or variable-width strings into canonical event codecs.
If variable application data must cross a boundary, express it as fixed-size
chunk event types or padded size-bucket event types. Counted transport batches
may carry repeated fixed-format items or opaque canonical event bytes, but that
batch framing is not itself an open-ended canonical event schema.

Strict checks should stay true:

```text
rg "crate::runtime" src/protocol/event_modules
rg "crate::state" src/protocol/event_modules
rg "rusqlite|Transaction" src/protocol/event_modules
```

These should return no matches unless a match is explicitly documented as a
data-only schema declaration.

## Sync And Connection Are Event Modules

Sync and connection protocol logic must not be custom code hidden in the CLI,
network transport, runtime loop, or core. It must be expressed as properly
decoupled event modules along the same lines as the structured modules in
`poc-8/src/protocol/event_modules`.

This includes:

- connection setup and supporting connection events
- connection metadata and observed/self addresses
- key, invite, and bootstrap protocol events
- sync compare/have/need events
- deterministic connection-scoped send-intent events
- dep-aware negentropy events and tree/cache maintenance
- request/response behavior that can be represented as event emission

Core may:

- store declared table rows as opaque key/value bytes
- execute schemas declared by core IO and protocol module scopes
- run transactions over generic rows
- expose exact row reads, prefix scans, and key-range scans for queues/indexes
- maintain one opaque outbound network queue with target metadata and one opaque
  inbound network queue with source metadata
- run generic TCP listener/connect/read-frame/write-frame mechanics over those
  opaque network queue rows
- provide transactions and idempotent row insertion

Protocol event modules may:

- compute event ids from canonical event bytes
- store canonical bytes through protocol-owned event tables
- maintain protocol event status, ready, blocked, dependency, label, and
  partition-index rows
- expose protocol queries over stored event bytes, statuses, and labels

Network queues are ordinary memory-local core table rows with typed wrappers.
There is one outbound queue table, not one table per target. `target` is
metadata encoded into the row key so core can claim a bounded batch for a
target with a generic key-prefix scan. `Store` may expose
`table_rows_with_key_prefix` and generic key-range scans; it must not grow
network-specific methods.

Core must not:

- contain a bespoke sync coordinator
- contain connection protocol state machines
- create transit blobs, choose transit encryption/padding/key rules, or decide
  which events are authorized on a connection
- inspect sync ranges or negentropy trees except through module-declared tables
- contain negentropy, compare/have/need, or sync-range vocabulary in
  `src/core`
- own protocol admission, blocking policy, projector dispatch, or wire codec
  helpers
- contain connection-target, semantic outbox, transit, or connection-id
  vocabulary in `src/core`
- special-case have/need/compare behavior outside event modules
- bypass event admission for protocol messages
- use side-channel protocol messages when an event can express the fact

`core/tcp.rs` owns only transport mechanics: TCP framing, sending, receiving,
buffering, and backpressure to concrete targets such as `(ip, port)` or socket
ids. It does not own sync, connection, transit wrapping, or authorization
semantics.

`core/network_queues.rs` owns typed opaque byte queues:
`NetworkTarget`, `NetworkSource`, `OutboundNetworkRow`, and
`InboundNetworkRow`. Protocol event modules own protocol out rows and
transit bytes. Core does not name sync, connection, semantic outbox, or transit
concepts.

Events declare scope explicitly:

- `Shared`: durable data that participates in sync summaries and dependency
  checks.
- `Local`: durable private facts such as endpoint keys and invites.
- `Transient`: non-durable canonical protocol events. The current Topo
  protocol uses connection-scoped transient events for established connections.

Connection transit receive handling must not admit local-only events from a
remote endpoint. Durable shared events received over a connection go through the
main event-module admission pipeline, where codecs, dependency blocking,
signature checks, projectors, and storage constraints decide validity.
Network admission must not grow event-type-specific content authorization. If
receive-side workspace filtering is added later, it should be generic
connection/session policy over event `workspace_id`, not per-content special
casing and not a substitute for projector validation.

Connection-scoped protocol events are real canonical events. Their connection id
must be inside their canonical bytes, and their id is the normal
`BLAKE3(canonical_event_bytes)`. Inbound/outbound handling is not encoded in the
event body. It is `EventScope::Connection(...)` projection context supplied by
the command path or receive path. They are facts/state/semantics, so they enter
the normal event admission and projection path. They are not durable shared
event-set truth: their cached bytes and transit out rows are memory-local
operational state. After send, the transit out row can be deleted; after
restart, sync can recreate any needed send work by emitting the same
deterministic connection-scoped events again.

Inbound connection-scoped protocol bytes also become canonical transient
events, but the long-lived daemon must not hide them behind direct worker calls.
Event admission consumes raw `core.network.inbound` frames, runs the transit
projector to authenticate/unwrap them, writes recovered inner bytes to
`canonical.in`, and then admits those canonical bytes through the same pipeline
as command-created events. For sync today this means outgoing-scoped
compare/have/need events project to `transit.out`, while incoming-scoped
compare/have/need events project to `sync.in`.
Those sync request rows may be memory-local; if a debug mode wants durable protocol
trace facts, it should make the storage class explicit instead of treating them
as shared durable data.

Connection request/response receive metadata is projection context. When core TCP
queues an inbound frame, event admission may attach `ReceiveMetadata` into
`EventContext` for a decoded connection event after transit provenance has been
checked. It is not
canonical event data and must not be stored in `EventRecord`. Request projection
requires bootstrap-invite receive authorization whose invite-secret event is an
applied dependency. Response projection requires endpoint receive
authorization from the decrypted sender endpoint. Only then may the projector
write the connection row and, when the route is worth dialing later, the current
transport-target row in one projection. Do not model that route observation as a
separate `transport_target` event module: the address is subjective to this
peer's receive boundary, and it is meaningful only with the connection event
being projected. Listener-side client source ports are receive metadata, but not
durable routes. Durable receive metadata is allowed only when the event can be
projected immediately; if dependency blocking would require storing that
metadata for later, admission must fail unless storage is extended to persist it.

`queries.rs` is not a worker junk drawer. Keep it for read-only CLI/reporting
queries such as counts or staged test reads. Reads that are part of active work
belong next to that work in `src/workers`; reads that are part of command
construction should be expressed as narrow command context traits. Prefer the
generic projector context for event-to-event relationships before adding any
custom read path.

Durable data events are not pushed to peers on creation. Durable data transfer
is queued only when protocol work asks for a durable event id, usually by the
sync worker after projectors write compare/need/range queue rows. The connection
out queue dedupes by `(connection_id, event_id)` while the work is pending; it
is a temp queue, not a durable resend log. The transit out worker drains
transit out and may batch several canonical inner events into one encrypted
transit blob; core network queues only carry target metadata plus opaque bytes,
and core TCP only frames and writes those bytes.

Only commands create new semantic events. Workers can decide that a follow-up
event is needed, but they express that by calling an event-module command and
admitting the returned `ProposedEvent`s. Workers may admit canonical bytes that
already exist, such as bytes received from a connection, but they should not
construct new event meanings inline.

Core TCP send queue targets are transport routes, not semantic connection ids.
Use an address or socket target such as `(ip, port)` or `socket_id`. If a
module starts from `connection_id`, it must resolve that connection to a
transport target before writing an `OutboundNetworkRow`.

## Core Crypto

Cryptographic primitives and reusable hash helpers belong in `src/core/crypto.rs`.
Protocol event modules may call those helpers with domain-specific context, but
they should not own primitive implementations or duplicate hash/cryptor code.
Event modules still own semantic decisions: what is signed, what dependency is
authorized, which associated data is passed, and how projection treats a
verification failure.

Keep the core crypto API small and honest, following the useful `poc-6` shape:
`hash`, `sign`/`verify`, X25519 key derivation, nonce generation, and
`encrypt`/`decrypt`-style helpers over real primitives. Do not leak low-level
library calls through event modules, and do not name a helper after a property
it does not actually enforce.

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
- Initial setup for functional tests must also be black-box. If a test needs
  workspaces, users, endpoints, invites, routes, or initial content, create them
  through the public CLI/process/network path being claimed rather than seeding
  core tables, copying rows, or installing domain graphs directly.
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
  assert output. They must not create core tables or apply domain semantics.
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
core and new core/protocol split can both satisfy the same user-visible tests while internal
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
- whether storage is backed by the old state modules or the new core store

The CLI test harness may spawn processes, allocate temp directories, choose
ports, and assert command output. It must not create core schema, insert rows,
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
old core and the replacement core/protocol implementation.

## Fresh Minimal Rewrite Guardrails

The fresh rewrite starts from `plan.md` and `RULES.md` only. Add code back only
when it serves the minimal black-box path:

```text
topo --db PATH invite --public-addr ADDR
topo --db PATH connect INVITE_LINK
topo --db PATH generate NUM_EVENTS EVENT_SIZE_BYTES
topo --db PATH sync
```

A read-only `count`/`status` command is allowed solely so black-box tests can
assert eventual convergence and measure sync-start to all-counted time.

Keep core boring:

- `core/tcp.rs` owns TCP, frame boundaries, connection attempts, and byte IO only.
- `core/network_queues.rs` owns one target-indexed outbound byte queue and one
  source-indexed inbound byte queue; it does not define per-target tables.
- `core/store.rs` owns durable bytes, generic module-owned rows, and generic event-set
  reads/writes only. It may expose generic prefix and key-range scans over table row keys,
  but it must not know network queue meaning.
- `protocol/event_modules/content` owns content event construction, codec, and projection.
- `protocol/event_modules/sync` owns all negentropy, compare/have/need/range decisions,
  connection-scoped sync events, and sync workers.
- `protocol/event_modules/connection` owns endpoint identity, bootstrap/connection
  events, established-connection rows, and the route facts needed to reach an
  endpoint.

Core should be a pleasure to read: small files, direct control flow,
plain names, and no hidden protocol cleverness. A reader should understand the
core as queue/storage/TCP mechanics without learning the content or sync
protocols. All real domain and protocol logic belongs in protocol event
modules.

Core files must not own connection, peer, or bootstrap schema. If a
protocol needs a durable or transient table, the owning event module declares
the table and writes it through generic storage/projector output.

Do not put sync protocol vocabulary or decisions in core files. In particular,
`core/store.rs` may not decide what a negentropy range means, when to split a
range, which ids are needed, or which events satisfy a sync request. Protocol
shell code may only call protocol workers/event-module functions and move
returned bytes.

Do not put transit wrapping in `core/tcp.rs`, `core/network_queues.rs`,
`core/store.rs`, CLI glue, or sync modules. Connection/transit modules create
transit blobs; core TCP creates only generic TCP frames around module-produced
opaque bytes.

Event modules stay directory-shaped:

```text
protocol/event_modules/<name>/commands.rs
protocol/event_modules/<name>/codec.rs
protocol/event_modules/<name>/types.rs
protocol/event_modules/<name>/projector.rs
protocol/event_modules/<name>/schema.rs
protocol/event_modules/<name>/queries.rs   # only when needed
protocol/event_modules/<name>/mod.rs
```

Domain roots may additionally contain shared schema/query/type surfaces:

```text
protocol/event_modules/<domain>/schema.rs
protocol/event_modules/<domain>/queries.rs
protocol/event_modules/<domain>/types.rs
```

Never create `event.rs`.

Functional proof for this rewrite means black-box CLI tests that spawn the real
`topo` binary, use real TCP sockets, start `sync`, wait through the CLI-observed
event count, and report both events/s and MiB/s for perf cases.

## In-Line Documentation Describes Current Code, Not History

Every doc comment, module-level comment, and inline comment must describe the
code as it currently stands. It must not reference:

- Development plans, phases, or slices (e.g. "slice 2 will introduce…",
  "the slice-1 fallback", "phase 2 spec").
- Commit hashes, PR numbers, or task ids (e.g. "fixed in commit abc123",
  "see task #21", "after the master merge").
- Removed or pre-merge code (e.g. "the old `is_expired_at_receive` branch",
  "before the connection refactor").
- Future work conditioned on a development plan (e.g.
  `TODO(disappearing-messages): whole-minute retirement will land in slice 7`).
  Future-work TODOs are allowed only when they name a concrete, code-level
  concern (e.g. `TODO: cap walk depth at trie_root_bit_depth - 1`).

The text "slice N", "task #N", and commit-hash references in `src/` source
text are forbidden by lint.

Rewrite stale references in terms of what the code currently does and what
modules it interacts with. For example:

```text
// Bad
//! The setting carries the slice-1 fallback `disappearing_ttl_minutes`.
// Good
//! When no `disappearing_messages_setting` event has been admitted, the
//! workspace's `disappearing_ttl_minutes` field is the effective TTL.
```

```text
// Bad
// Past-TTL re-deliveries are caught earlier by the receive-side admission
// gate, so by the time projection runs the only remaining tombstone trigger
// is the author-driven deletion label.
// Good
// The only tombstone path that reaches this projector branch is the
// author-driven deletion label. The receive-side admission gate
// (`projector::admit_check_received`) drops past-TTL re-deliveries before
// they reach projection.
```

The standard for "current code" is: a reader who has never seen the plan
documents, the commit history, or any prior architecture should be able to
read a doc comment and understand what the code does and why, by name only.

Plan documents (`plan.md`, `disappearing_messages_plan.md`, etc.) are the
right home for slice numbers, sequencing, and historical decisions. They
must not leak into `src/`.

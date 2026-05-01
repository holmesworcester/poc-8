# Variant 4: Existing-Expressive

This demo keeps the existing event-module/projector shape, but lets modules
declare more of the state surface they own:

- table schemas with primary keys and indexes,
- derived views used as named access paths,
- queue boundaries for inbound bytes, ready events, and outbox refill,
- projectors that return table rows instead of mutating transport or queues
  directly.

The implementation is intentionally small and executable. It uses an in-memory
store, but the catalog declarations in `variant04/event_modules/*/registry_meta.py`
are shaped like metadata a persistent `state` layer could materialize as DDL.

## Component Map

`variant04/catalog.py`
: Module, table, index, derived-view, and queue-boundary declarations.

`variant04/state.py`
: Generic table store. It validates rows against declarations and exposes named
index reads.

`variant04/control_loop.py`
: Single writer. It claims bounded inbound rows and ready events, admits event
ids before semantic projection, blocks on missing dependencies, and unblocks
dependents in the same transaction that applies the dependency.

`variant04/sender.py`
: One sender owner for one connection. It refills a byte-bounded hot queue from
`outbox` rows and deletes outbox rows only after a successful send.

`variant04/event_modules/content_user`
: Durable user events and the `users` table.

`variant04/event_modules/content_message`
: Durable message events, dependency declaration through `deps`, and the
`messages` table.

`variant04/event_modules/sync_need`
: Endpoint-local need events. The projector validates connection/workspace
membership and writes `outbox(connection_id, event_id)`.

`variant04/event_modules/pipeline_boundary`
: Pipeline-owned `inbound_bytes`, `events`, `blocked_by_event`, and their queue
boundaries.

`variant04/event_modules/sender_boundary`
: Sender-owned `outbox` boundary and refill candidate view.

## Flow Demonstrated

1. An inbound message arrives before its author event. The control loop hashes
   the canonical bytes, admits the event id, parses the event, finds the missing
   dependency, marks the event `blocked`, and writes
   `blocked_by_event(blocked_by_event_id, event_id)`.
2. The author event arrives later. Its projector writes a `users` row and marks
   the event `applied`. In the same transaction, the pipeline deletes matching
   blocker rows and marks the message event `ready`.
3. The message is not projected recursively. A later bounded ready-event pass
   claims it and writes the `messages` row.
4. A `sync.need_event` queues an applied event in `outbox`.
5. `ConnectionSender.refill()` joins `outbox`, `events`, and `connections`,
   wraps canonical event bytes into a connection frame, and fills a byte-bounded
   hot queue without holding a transport write transaction.

## Invariants

- Every event row is keyed by deterministic canonical bytes.
- Missing dependencies are represented only as `blocked_by_event` edges.
- Applying dependency `D` and unblocking dependents of `D` happen in one
  transaction.
- Unblocking changes status to `ready`; it does not recursively project
  dependents.
- Queue-like work is an owned table row at an explicit boundary.
- `outbox` stores `(connection_id, event_id)`, not transport bytes.
- The sender deletes `outbox` rows only after successful send acceptance.

## Run

```bash
python3 experiments/dataflow_queue_blocking/variant_04_existing_expressive/run_demo.py
```

## Tests

```bash
python3 -m unittest discover -s experiments/dataflow_queue_blocking/variant_04_existing_expressive/tests -v
```

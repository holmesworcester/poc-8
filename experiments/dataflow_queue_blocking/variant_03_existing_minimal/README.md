# Variant 03: Existing-minimal

This demo stays close to the current poc-8 plan: SQL tables, module-owned
state, one control-loop writer, and no Differential dependency. Differential
is only vocabulary here:

- queue = a materialized boundary table, or an indexed subset such as
  `events.status = 'ready'`
- blocked = durable state in `events` plus rows in `blocked_by_event`
- ready = an index-backed queue the control loop claims in bounded batches

## Purpose

Show the minimal existing-code-shaped kernel for inbound bytes becoming
parsed events, blocked events, ready events, projections, and `outbox` rows.
The runnable demo is [demo.py](./demo.py), backed by the exact SQLite tables
in [schema.sql](./schema.sql).

## Ownership

The table owners are explicit in `module_catalog`.

| Table | Owner | Role |
| --- | --- | --- |
| `inbound_bytes` | `transport.ingress` | Deduped transport ingress boundary, claimed by bounded batch. |
| `events` | `event_pipeline` | Canonical event bytes plus status. `status = 'ready'` is the event queue. |
| `event_dependencies` | `event_pipeline` | Parsed dependency metadata for audit and tests. |
| `blocked_by_event` | `event_pipeline` | Wait edges from missing dependency id to blocked event id. |
| `content_messages` | `event_modules.content.message` | Example module-owned projection table. |
| `workspace_connections` | `event_modules.connection` | Projection-time routing context for outbox writes. |
| `outbox` | `sender.connection` | Deduped `(connection_id, event_id)` boundary for one sender owner. |

## Exact Tables

The authoritative DDL is `schema.sql`. The important indexes are:

```sql
CREATE INDEX inbound_bytes_claim_idx
  ON inbound_bytes(status, not_before_ms, received_at_ms, wire_id);

CREATE INDEX events_ready_idx
  ON events(status, created_at_ms, event_id);

CREATE INDEX blocked_by_event_event_idx
  ON blocked_by_event(event_id, blocked_by_event_id);

CREATE INDEX outbox_connection_idx
  ON outbox(connection_id, queued_at_ms, event_id);
```

Those indexes are the queues. There is no separate scheduler object for ready
events and no recursive dependent processing inside apply.

## Bounded Flow

Inbound claim is a bounded materialized boundary read:

```sql
BEGIN IMMEDIATE;
SELECT wire_id, canonical_event_bytes
  FROM inbound_bytes
 WHERE status = 'pending'
   AND not_before_ms <= :now_ms
 ORDER BY received_at_ms, wire_id
 LIMIT :inbound_batch_size;
UPDATE inbound_bytes
   SET status = 'processing',
       attempts = attempts + 1,
       updated_at_ms = :now_ms
 WHERE wire_id = :wire_id
   AND status = 'pending';
COMMIT;
```

For each claimed row, the control loop computes `event_id`, admits that id
before loading context, parses canonical bytes, and then chooses exactly one
state:

- duplicate known id: mark the inbound row `processed` and stop before
  projection
- parse failure: mark inbound `invalid` and release the event claim
- missing dependency: write `events.status = 'blocked'` plus
  `blocked_by_event(missing_dep, event_id)`
- all dependencies applied: write `events.status = 'ready'`

Ready claim is another bounded indexed read:

```sql
BEGIN IMMEDIATE;
SELECT event_id
  FROM events
 WHERE status = 'ready'
 ORDER BY created_at_ms, event_id
 LIMIT :ready_batch_size;
UPDATE events
   SET status = 'processing',
       updated_at_ms = :now_ms
 WHERE event_id = :event_id
   AND status = 'ready';
COMMIT;
```

## Apply Transaction

`demo.py::apply_event` projects one already-claimed event and unblocks
dependents in one `BEGIN IMMEDIATE ... COMMIT` transaction:

```sql
BEGIN IMMEDIATE;

-- Projection owned by event_modules.content.message.
INSERT OR IGNORE INTO content_messages(
  event_id, workspace_id, message_name, body, applied_at_ms
)
VALUES (:event_id, :workspace_id, :message_name, :body, :now_ms);

-- Outbox is written by projection, but stores only event ids.
INSERT OR IGNORE INTO outbox(connection_id, event_id, queued_at_ms)
SELECT connection_id, :event_id, :now_ms
  FROM workspace_connections
 WHERE workspace_id = :workspace_id;

UPDATE events
   SET status = 'applied',
       updated_at_ms = :now_ms
 WHERE event_id = :event_id;

-- Same transaction unblocking. The temp table is a control-loop scratch set.
DELETE FROM apply_unblock_candidates;
INSERT OR IGNORE INTO apply_unblock_candidates(event_id)
SELECT event_id
  FROM blocked_by_event
 WHERE blocked_by_event_id = :event_id;

DELETE FROM blocked_by_event
 WHERE blocked_by_event_id = :event_id;

UPDATE events
   SET status = 'ready',
       updated_at_ms = :now_ms
 WHERE status = 'blocked'
   AND event_id IN (SELECT event_id FROM apply_unblock_candidates)
   AND NOT EXISTS (
     SELECT 1
       FROM blocked_by_event
      WHERE blocked_by_event.event_id = events.event_id
   );

DELETE FROM apply_unblock_candidates;
COMMIT;
```

The transaction does not apply dependents recursively. It only moves them to
`ready`; a later bounded ready batch claims them.

## Worked Dependency Trace

The scenario creates three message events:

| Label | Dependency | Inbound order |
| --- | --- | --- |
| `A` | none | third |
| `B` | `A` | second |
| `C` | `B` | first |

With `inbound_batch_size = 2` and `ready_batch_size = 1`:

| Step | Action | Event state | Wait edges | Outbox |
| --- | --- | --- | --- | --- |
| 0 | Seed inbound bytes for `C`, `B`, `A` | no events | none | none |
| 1 | Process inbound batch: `C`, `B` | `C=blocked`, `B=blocked` | `B -> C`, `A -> B` | none |
| 2 | Ready batch | no ready rows | `B -> C`, `A -> B` | none |
| 3 | Process inbound batch: `A` | `A=ready`, `B=blocked`, `C=blocked` | `B -> C`, `A -> B` | none |
| 4 | Apply ready batch: `A` | `A=applied`, `B=ready`, `C=blocked` | `B -> C` | `A` |
| 5 | Apply ready batch: `B` | `A=applied`, `B=applied`, `C=ready` | none | `A`, `B` |
| 6 | Apply ready batch: `C` | all applied | none | `A`, `B`, `C` |

That table is checkable by running the unit test:

```sh
python3 test_variant_03_existing_minimal.py
```

## Sender Boundary

`outbox` has no per-row lease. One sender owner per connection refills a
bounded hot queue:

```sql
SELECT o.event_id, e.canonical_event_bytes
  FROM outbox AS o
  JOIN events AS e ON e.event_id = o.event_id
 WHERE o.connection_id = :connection_id
   AND e.status = 'applied'
 ORDER BY o.queued_at_ms, o.event_id;
```

The owner stops before `byte_budget` is exceeded, skips event ids already in
its in-memory `present` set, wraps bytes outside the database transaction, and
deletes sent outbox rows only after a complete frame is accepted by the socket.

## Lessons Learned

- The minimal kernel is mostly status transitions plus two boundary tables:
  `inbound_bytes` and `outbox`.
- Blocking does not require a job queue. `blocked_by_event` is state, and
  unblocking is a same-transaction consequence of applying a dependency.
- `ready` is an index over `events`, so crash recovery can reset
  `processing -> ready` without reconstructing an external queue.
- Keeping outbox rows as `(connection_id, event_id)` preserves replay and
  wrapping boundaries. The sender owns bytes and socket backpressure.
- The single-writer model makes the first version easy to audit; multi-worker
  leases can be added later without changing module-owned table semantics.

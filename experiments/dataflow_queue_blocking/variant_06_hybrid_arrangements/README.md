# Variant 6: Hybrid Arrangements

## Purpose

This demo keeps the existing SQL/control-loop shape but adds explicit in-memory
arrangements for hot relations:

- `events_by_id`
- `blocked_by_dep`
- `outbox_by_connection`
- `negentropy_leaves`

The design point is the middle of the axis. SQL is still the authority for
facts, blocking rows, outbox rows, and negentropy leaves. The arrangements are
disposable read indexes updated from committed deltas and rebuilt from SQL after
restart.

## Ownership / Non-Ownership

`HybridKernel` owns the single-writer transaction boundary. It admits events,
commits durable rows, and applies deltas to arrangements only after commit.

`ArrangementCaches` owns in-memory indexes. It does not decide event validity,
dependency policy, or sender progress.

`SenderOwner` owns one bounded in-memory queue for one connection. It does not
own the durable outbox. A slow or unwritable connection leaves rows in SQL and in
`outbox_by_connection`.

## Interfaces

- `Event.create(...)` builds deterministic canonical bytes and an event id.
- `HybridKernel.ingest(event)` commits an event, blocks it if its dependency is
  absent, or projects it into outbox and negentropy leaves if ready.
- `HybridKernel.restart()` closes and reopens the database, rebuilding all
  arrangements from committed SQL rows.
- `SenderOwner.refill_from_arrangement()` fills a bounded sender queue from
  `outbox_by_connection`.
- `SenderOwner.ack_written(event_id)` commits outbox progress and applies the
  resulting delete delta to the arrangement.

## State

Durable SQL tables:

- `events`: canonical event facts keyed by event id.
- `blocked_by_dep`: wait rows keyed by dependency id and blocked event id.
- `outbox`: durable send work keyed by connection id and event id.
- `negentropy_leaves`: projected leaves keyed by workspace, bucket, and event id.

Hot arrangements mirror those tables into query shapes that the control loop and
sender need on the hot path.

## Invariants

- SQL rows are authoritative. An arrangement can be dropped at any point and
  rebuilt from SQL.
- Arrangement mutation happens after `COMMIT`, never from staged rows.
- A blocked event is present in `events_by_id` and `blocked_by_dep`, but absent
  from `outbox_by_connection` and `negentropy_leaves`.
- Unblocking removes the `blocked_by_dep` row and projects the formerly blocked
  event in the same control-loop transaction that committed the missing
  dependency.
- Sender memory is bounded by `capacity`; overflow remains durable in `outbox`
  and visible in `outbox_by_connection`.

## Flow

For an event with a missing dependency:

1. Insert the canonical event row in SQL.
2. Query `events_by_id`; if the dependency is absent, insert
   `blocked_by_dep(dep_id, event_id)`.
3. Commit.
4. Apply the committed `events` and `blocked_by_dep` deltas to arrangements.

For an event that satisfies blocked work:

1. Insert the dependency event row.
2. Project the dependency into `outbox` and `negentropy_leaves`.
3. Query `blocked_by_dep[dependency_id]`.
4. Delete matching block rows and project each unblocked event.
5. Commit.
6. Apply all committed insert/delete deltas to arrangements.

For sender backpressure:

1. `SenderOwner` scans `outbox_by_connection[connection_id]`.
2. It loads only up to its remaining memory capacity.
3. Writing to the socket does not remove durable work.
4. `ack_written` commits the outbox delete and updates the arrangement from that
   delete delta.

## Failure / Restart Behavior

A rollback leaves arrangements unchanged because staged deltas are discarded.
`test_rolled_back_sql_deltas_do_not_update_arrangements` covers this directly.

After restart, `ArrangementCaches.rebuild(conn)` scans SQL tables in stable order
and reconstructs all four arrangements. Sender memory is intentionally not
rebuilt; the sender refills from durable outbox rows.

## Worked Trace

Run:

```sh
python3 experiments/dataflow_queue_blocking/variant_06_hybrid_arrangements/hybrid_arrangements_demo.py
```

Trace:

```text
worked trace: child arrives before parent
parent id = 0ed32e020d21e1d4
child id = 1c30f24c7c4b5aef
commit-stage events[1c30f24c7c4b5aef] inserted into SQL log
block 1c30f24c7c4b5aef: dep 0ed32e020d21e1d4 missing from events_by_id arrangement
arrangements updated after commit: 2 committed relation deltas applied
commit-stage events[0ed32e020d21e1d4] inserted into SQL log
project 0ed32e020d21e1d4: dependency present in read arrangement; projector reads hot outbox and negentropy arrangements for dedupe
  outbox_by_connection[conn-east] += 0ed32e020d21e1d4
  negentropy_leaves[workspace-alpha:0e] += 0ed32e020d21e1d4
unblock scan: blocked_by_dep[0ed32e020d21e1d4] -> ['1c30f24c7c4b5aef']
  blocked_by_dep[0ed32e020d21e1d4] -= 1c30f24c7c4b5aef
project 1c30f24c7c4b5aef: dep 0ed32e020d21e1d4 committed in this batch; projector reads hot outbox and negentropy arrangements for dedupe
  outbox_by_connection[conn-east] += 1c30f24c7c4b5aef
  negentropy_leaves[workspace-alpha:1c] += 1c30f24c7c4b5aef
arrangements updated after commit: 6 committed relation deltas applied
sender refill: loaded ['0ed32e020d21e1d4']; remaining durable outbox = ['0ed32e020d21e1d4', '1c30f24c7c4b5aef']
sender writable: wrote 0ed32e020d21e1d4; outbox row stays durable
ack conn-east/0ed32e020d21e1d4: committed outbox delete; outbox_by_connection updated from delta
sender refill after ack: loaded ['1c30f24c7c4b5aef']
restart rebuild: arrangements match committed SQL = True
```

## Checks

Run:

```sh
python3 -m unittest discover -s experiments/dataflow_queue_blocking/variant_06_hybrid_arrangements -p 'test_*.py'
```

The tests cover:

- child-before-parent blocking and same-transaction unblock projection
- restart rebuild of all arrangements from SQL
- sender backpressure with a capacity-one queue
- rollback behavior proving arrangements follow only committed deltas

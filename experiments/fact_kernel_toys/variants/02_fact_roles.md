# Variant 2: Fact Roles Owned by Modules

Semantic modules own fact roles instead of treating every fact as the same
event-log item. The kernel stores facts and dependencies; modules define what a
fact means, how it materializes, and how deletion/tombstones sweep their own
outputs.

## Toy Types

- `MessageCreated`: event fact for visible message content.
- `MessageDeleted`: tombstone fact that invalidates one message.
- `UnblockObligation`: obligation fact emitted when a missing dependency may now
  be retried.
- `SweepDeletedMessage`: obligation fact emitted by tombstones to remove stale
  projections.
- `Need` / `Have`: setting/trace facts used by the kernel to explain dependency
  state.

## Module / File Organization

```text
fact_kernel/
  kernel.py                 # append facts, index needs/haves, dispatch modules
  schema.py                 # Fact, FactId, Need, Have
  modules/
    messages/
      events.py             # MessageCreated
      tombstones.py         # MessageDeleted
      projectors.py         # message_view, dependency_view
    obligations/
      unblock.py            # UnblockObligation
      sweep_deleted.py      # SweepDeletedMessage
    trace/
      needs.py              # Need/Have trace facts and diagnostics
```

## Tables

`facts`

| fact_id | type | subject | payload | created_at |
| --- | --- | --- | --- | --- |
| `f_b` | `MessageCreated` | `msg:B` | `{text, needs:["msg:A"]}` | `t1` |
| `need_b_a` | `Need` | `msg:B` | `{needs:"msg:A"}` | `t1` |

`have_index`

| subject | fact_id | module |
| --- | --- | --- |
| `msg:A` | `f_a` | `messages.events` |

`need_index`

| waiter | needs | status |
| --- | --- | --- |
| `msg:B` | `msg:A` | `missing` |

`obligations`

| obligation_id | type | target | reason | status |
| --- | --- | --- | --- | --- |
| `obl_unblock_b` | `UnblockObligation` | `msg:B` | `msg:A arrived` | `pending` |
| `obl_sweep_b` | `SweepDeletedMessage` | `msg:B` | `MessageDeleted(msg:B)` | `pending` |

## Projector / Materializer Outputs

`message_view`

| message_id | text | visible | blocked_by | source_fact |
| --- | --- | --- | --- | --- |
| `B` | `reply to A` | `false` | `["msg:A"]` | `f_b` |

`dependency_view`

| message_id | dependency | state |
| --- | --- | --- |
| `B` | `A` | `missing` |

`trace_view`

| subject | role | detail |
| --- | --- | --- |
| `msg:B` | `Need` | `needs msg:A` |
| `msg:A` | `Have` | `provided by f_a` |

## Flow

1. `B` arrives first as `MessageCreated(msg:B, needs=["msg:A"])`.
2. `messages.events` records `B` as blocked and emits `Need(msg:B -> msg:A)`.
3. `trace.needs` writes `need_index[msg:B,msg:A] = missing`; `message_view.B`
   is materialized with `visible=false`.
4. `A` arrives as `MessageCreated(msg:A)` and emits `Have(msg:A)`.
5. The kernel matches `Have(msg:A)` against `need_index` and appends
   `UnblockObligation(target=msg:B, reason=msg:A arrived)`.
6. `obligations.unblock` rechecks `B`; all needs are now satisfied, so
   `message_view.B.visible=true` and `dependency_view.B.A=present`.
7. `MessageDeleted(msg:B)` arrives as a tombstone owned by
   `messages.tombstones`.
8. The tombstone appends `SweepDeletedMessage(target=msg:B)`.
9. `obligations.sweep_deleted` removes or marks stale rows owned by the message
   module: `message_view.B` is hidden/deleted, `dependency_view.B.*` is cleared,
   and trace rows remain only as audit history.

## Strengths

- Roles make ownership explicit: event modules project, tombstone modules
  invalidate, obligation modules retry/sweep, trace modules explain.
- Deletion is concrete and local; tombstones do not need global knowledge of all
  materializers.
- `Need`/`Have` facts make unblock behavior inspectable instead of hidden in
  scheduler state.

## Friction

- More fact types means more module boundaries and dispatch rules to document.
- Cross-module sweeps need a registry of owned projections, or stale rows can be
  missed.
- Obligations are durable work items, so idempotency and retry semantics must be
  designed early.

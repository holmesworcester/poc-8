# Variant 01: Differential-Minimal Queue Blocking

Purpose: sketch inbound queue processing as Differential Dataflow-style
collections and joins, while keeping the kernel surface small enough to audit.

Position on the design axes:

- Close to Differential/Timely: all queue state is derived from collections,
  signed deltas, arrangements, semijoins, and antijoins.
- Minimal: there are no workers, timestamps, frontier APIs, compaction rules, or
  custom operators in the demo.
- Farther from the existing kernel: `blocked`, `ready`, and `outbox` are treated
  as derived collections, not as imperative queues owned by runtime code.
- Less expressive: this version does not model retries, deadlines, priorities,
  external IO ownership, or multi-output projectors.

## Vocabulary

Collection: a set of rows with integer weights. The demo only uses `+1` and
`-1` deltas over set-like rows.

Arrangement: an indexed collection used by joins. The demo arranges facts by
`fact_id` and missing dependencies by `event_id`.

Semijoin: keep a row from the left collection if a matching key exists in the
right arrangement.

Antijoin: keep a row from the left collection if no matching key exists in the
right arrangement.

## Collections

Input collections:

```text
inbound(event_id, deps, connection_id)
facts(fact_id)
```

Derived collections:

```text
parsed(event_id, deps, connection_id)
dep_edges(event_id, required_fact_id)
missing_deps(event_id, required_fact_id)
blocked(event_id, deps, connection_id)
ready(event_id, deps, connection_id)
outbox(connection_id, event_id)
```

`parsed` is the minimal stand-in for canonical event parsing. Invalid bytes are
outside this variant; a parsed row means admission and decoding already
succeeded.

## Dataflow Rule

The queue/blocking rule is:

```text
parsed       = inbound
dep_edges    = parsed.flat_map(event deps)
missing_deps = dep_edges.antijoin(facts arranged by fact_id)
blocked      = parsed.semijoin(missing_deps arranged by event_id)
ready        = parsed.antijoin(missing_deps arranged by event_id)
outbox       = ready.map((connection_id, event_id))
```

This is the whole kernel model for this variant. A new fact does not call an
unblock routine. It changes `facts`, which changes `missing_deps`, which changes
`blocked`, `ready`, and `outbox` through the joins.

## Invariants

- Every inbound row is exactly one of `blocked` or `ready`.
- `blocked(event)` exists if and only if at least one dependency edge for that
  event is missing from `facts`.
- `ready(event)` exists if and only if no dependency edge for that event is
  missing from `facts`.
- `outbox(connection_id, event_id)` is derived only from `ready`.
- Re-applying an unrelated fact may change `facts`, but it must not produce an
  `outbox` delta.

## Worked Trace

Initial fact:

```text
facts = { workspace:W }
```

Inbound delta contains three events from `peer-1`:

```text
A depends on workspace:W
B depends on event:A
C depends on event:B
```

Trace:

```text
t1 +inbound(A,B,C)
  missing_deps = { B->event:A, C->event:B }
  blocked delta = +B, +C
  ready delta   = +A
  outbox delta  = +(peer-1, A)

t2 +fact(event:A)
  missing_deps delta = -B->event:A
  blocked delta = -B
  ready delta   = +B
  outbox delta  = +(peer-1, B)

t3 +fact(event:B)
  missing_deps delta = -C->event:B
  blocked delta = -C
  ready delta   = +C
  outbox delta  = +(peer-1, C)
```

If projecting `A` inserts `event:A` in the same transaction as admitting `A`,
then `t1` and `t2` can collapse into one dataflow tick. They are separated here
only to make the unblocking delta visible.

## Testing Hooks

Run the executable trace:

```sh
python3 experiments/dataflow_queue_blocking/variant_01_differential_minimal/demo.py
```

Run the checks:

```sh
python3 -m unittest discover \
  -s experiments/dataflow_queue_blocking/variant_01_differential_minimal \
  -p 'test_*.py'
```

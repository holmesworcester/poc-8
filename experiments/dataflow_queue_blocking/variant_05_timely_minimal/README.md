# Variant 05: Timely-Minimal

## Purpose

This demo models the event/fact kernel as a small Timely-style dataflow without
pulling in Timely or Differential as dependencies. The point is the shape:
operators, bounded handoffs, frontiers, and capabilities as the rule for when an
operator may create downstream work.

The demo intentionally keeps the kernel small. It uses in-memory tables and a
readable canonical byte format:

```text
id=child;deps=root;send=conn-a;body=needs root first
```

`id` stands in for the canonical event hash so traces stay legible.

## Operators

| Operator | Responsibility | Input boundary | Output boundary |
| --- | --- | --- | --- |
| `inbound` | Accept transport bytes and unwrap them into canonical event bytes. | `inbound_rx` | `parse_handoff` |
| `parse` | Parse canonical bytes, suppress duplicate event ids, and insert `events` rows. | `parse_handoff` | `context_handoff` |
| `context` | Check dependency readiness and either block the event or hand it to apply. | `context_handoff` | `apply_handoff` or `blocked_by_event` |
| `apply` | Mark an event applied and materialize send/unblock work. | `apply_handoff` | `outbox`, `unblock_handoff` |
| `unblock` | Delete wait edges for an applied dependency and requeue now-ready events. | `unblock_handoff` and `blocked_by_event` | `context_handoff` |
| `send` | Keep a bounded per-connection hot queue filled from `outbox` and write frames. | `outbox` | `sender_hot`, `sent_frames` |

This is a Timely mental model, not a Timely implementation. A `Capability`
contains `(from_operator, to_operator, time)`. The demo records capabilities in
the trace whenever an operator emits downstream work. A frontier is the smallest
timestamp still present at, or blocked before, a stage. If no such timestamp
exists, the frontier is the source upper timestamp.

## Where Queues Materialize

The queues are intentionally visible in the kernel state:

| Boundary | Materialization | Why it exists |
| --- | --- | --- |
| Transport ingress | `inbound_rx` bounded queue | Bytes can arrive faster than parse work. |
| Inbound to parse | `parse_handoff` bounded queue | Unwrap and parse can be independently paced. |
| Parse/context and unblock/context | `context_handoff` bounded queue | New and newly unblocked events share the same context rule. |
| Context/apply | `apply_handoff` bounded queue | Ready events are claimed in bounded batches. |
| Apply/unblock | `unblock_handoff` bounded queue | The applied-event capability tells unblock which wait edges are complete. |
| Dependency waits | `blocked_by_event(blocked_by_event_id, event_id)` table | Blocking is a durable wait edge, not recursive stack work. |
| Outgoing send | `outbox(connection_id, event_id)` table | Projectors dedupe send intent before any transport wrapping. |
| Per-connection send | `sender_hot[connection_id]` bounded queue | Slow sockets back up one connection without changing semantic outbox rows. |

The only table with event semantics is `events`. The queues are boundary state:
wait, claim, dedupe, and IO handoff.

## Concrete Trace

Scenario: `child` arrives before its dependency `root`.

```text
source accepted inbound frame @t0
inbound emitted canonical bytes with capability inbound->parse @t0
parse admitted event child with capability parse->context @t0; upstream was capability inbound->parse @t0
context blocked event child @t0 on missing deps [root]
```

At this point:

```text
events[child].status = blocked
blocked_by_event(root, child)
frontier.context = 0
frontier.apply = 0
```

Then `root` arrives:

```text
source accepted inbound frame @t1
inbound emitted canonical bytes with capability inbound->parse @t1
parse admitted event root with capability parse->context @t1; upstream was capability inbound->parse @t1
context emitted event root with capability context->apply @t1; upstream was capability parse->context @t1
apply committed event root and emitted capability apply->unblock @t1; upstream was capability context->apply @t1
unblock consumed capability apply->unblock @t1; released [child]
send wrote event root on conn-a and deleted its outbox row
context emitted event child with capability context->apply @t0; upstream was capability unblock->context @t0
apply committed event child and emitted capability apply->unblock @t0; upstream was capability context->apply @t0
unblock consumed capability apply->unblock @t0; released []
send wrote event child on conn-a and deleted its outbox row
```

Once `child` applies, the blocked timestamp no longer holds progress and the
context/apply frontiers advance to the source upper.

## Lessons

- Timely-style progress gives blocked rows an explicit cost: a missing dependency
  holds the context/apply frontier at the blocked event time until the wait edge
  is removed.
- Capabilities make handoff ownership concrete. `apply` is the only stage that
  can mint `apply->unblock` work for an applied event, and `unblock` is the only
  stage that turns wait edges back into context work.
- The send path stays outside projection. `apply` writes `outbox` rows, while
  `send` owns transport pacing and deletes outbox rows only after a frame write.
- Bounded handoffs expose where backpressure belongs. A full parse handoff stops
  inbound without changing event state; a full or unwritable sender hot queue
  leaves semantic outbox rows intact.
- Differential-style arrangements are not necessary for this small kernel
  shape. The useful borrowed idea here is Timely's small set of progress rules.

## Checks

Run from the repository root:

```sh
cargo test --manifest-path experiments/dataflow_queue_blocking/variant_05_timely_minimal/Cargo.toml
```

The tests cover:

- a missing dependency materializing `blocked_by_event` and holding the apply
  frontier,
- dependency arrival unblocking the child and sending both events,
- the bounded inbound-to-parse handoff,
- the bounded per-connection send hot queue with persistent outbox rows while a
  socket is blocked.

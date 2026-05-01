# Decision: Semantic fact modules with optional stage traces

## Recommendation

Use Variant 2 as the primary kernel structure:

```
semantic module owns fact roles
  -> event facts
  -> tombstone facts
  -> obligation facts
  -> materialized tables
  -> bounded sweeps
```

Use Variant 3 selectively for kernel stages that need observability or deterministic
simulation traces. Do not make every pipeline stage the primary source layout.

Variant 1 is closest to the current plan, but it keeps too much special logic
inside "event pipeline" vocabulary and makes deletion, unblocking, and sweeps
feel like add-ons rather than the natural model.

## Comparison

| Variant | Best property | Main cost | Verdict |
| --- | --- | --- | --- |
| 1. Event pipeline modules | Familiar and compact | Blocking, deletion, and sweeps remain special cases | Good baseline, weaker model |
| 2. Fact roles owned by modules | Clear monotone semantics and ownership | More vocabulary up front | Best primary design |
| 3. Stage projectors | Excellent trace/simulation story | Too many intermediate facts for normal source layout | Use as instrumentation mode |

## Kernel Shape

The kernel should be a fact expansion kernel, not just an event pipeline:

```
FactKernel:
  append immutable facts
  dispatch semantic modules
  materialize bounded projections
  schedule obligation facts
  run endpoint-scoped deterministic turns
```

An event is one kind of fact:

```
event fact       = something happened
tombstone fact   = something now invalidates prior/current projections
obligation fact  = bounded work remains
trace fact       = this stage or materialization step happened
setting fact     = this endpoint/simulation uses this parameter
```

The central rule:

```
Facts are append-only.
Current state is a projection of facts.
Negative semantics are positive tombstone facts.
Large consequences become obligation facts.
```

## Module Structure

Organize by semantic ownership, not by fact kind:

```
src/modules/
  content/
    message/
      facts.rs        // MessageCreated, MessageDeleted, SweepDeletedMessage
      codec.rs
      project.rs
      tables.rs
      sweeps.rs
      registry.rs
  sync/
    compare/
    have/
    need/
    negentropy_tree/
  connection/
    connection/
    secret/
  kernel/
    admission/
    unblock/
    trace/
```

Each module declares:

```
fact types
fact roles: event | tombstone | obligation | trace | setting
tables and indexes
projectors/materializers
sweep obligations
storage class
```

This keeps `MessageDeleted` and `SweepDeletedMessage` with `message`, where
ownership is obvious. A generic `tombstones/` or `obligations/` folder would
hide the domain owner of cleanup.

## Monotonicity Rules

Positive facts do not need optimistic guards when they never go away.

Do not make final decisions from absence:

```
if dependency exists:
  use it
if dependency is absent:
  block or enqueue work
```

Negative operations are positive facts:

```
MessageDeleted(B)
  -> tombstone deleted(B)
  -> obligation SweepDeletedMessage(B)
```

Future projectors can consult `deleted(B)` immediately. Existing projections are
cleaned up by bounded sweep materializers.

## Large Writes

A projector should not return a million rows directly. It should return a small
fact delta plus an obligation:

```
MessageDeleted(B):
  + deleted(B)
  + SweepDeletedMessage(B)

SweepDeletedMessage(B):
  load next N affected rows in stable order
  purge/update those rows
  requeue SweepDeletedMessage(B) if N rows were found
```

This keeps writer transactions short, makes progress deterministic, and lets
batch sizes and priorities be tuned without changing semantics.

Queue consumption follows one safety rule:

```
A transaction may delete the current work item only if it also commits:
  all required effects, or
  a durable continuation, or
  enough durable state to reconstruct the continuation, or
  no durable state because sync will reliably rediscover the work after crash
  and the loss is rare enough not to affect propagation.
```

The last case is for resyncable network work, not local-only facts. Local-only
facts that matter after crash must be durable because no peer can restore them.

## Simulation

Simulation should run the same fact kernel with different retention and timing
settings:

```
initial facts
  + endpoint settings
  + scheduler policy
  + virtual time
  + step count
  => deterministic trace
```

In trace mode:

```
disable time-based purge
retain endpoint-local facts
retain local trace facts
use stable ORDER BY for every bounded query
use virtual time and seeded randomness only
```

Variant 3's stage-projector idea is best here: stages such as `admit`, `parse`,
`context`, `project`, `apply`, `unblock`, `sweep`, and `send` can emit trace
facts and timing facts without changing the primary semantic module layout.

## Resulting Design Bias

Prefer this sentence as the design north star:

```
Projectors assert monotone facts and bounded obligations;
materializers maintain projections from those facts.
```

That gives the kernel a smaller correctness surface than a mutable event queue
design, while preserving the event-module locality we want.

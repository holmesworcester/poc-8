# Variant 3: Pipeline Stages as Projectors

Treat each pipeline stage as a small projector: it consumes facts from its input
set, emits derived facts into its output set, and may also emit trace facts that
explain what happened. The kernel stays append-oriented except for explicit
tombstones and sweep facts.

## Toy Fact Types

| Fact | Meaning |
| --- | --- |
| `MessageCreated(id, text)` | A message exists and can enter the pipeline. |
| `MessageDeleted(id)` | A message is deleted; downstream projections must be removed. |
| `Need(message_id, key)` | A message is blocked on a missing dependency. |
| `Have(key, source_id)` | A dependency or projection is available. |
| `Unblock(message_id, key)` | A previous need has been satisfied. |
| `Sweep(message_id, target)` | Remove projections for a deleted or invalidated message. |

Trace facts use the same shape everywhere:

`Trace(stage, input_fact, output_fact, note)`

## Module Organization

```text
experiments/fact_kernel_toys/
  kernel/
    facts.md              # fact identity, tombstones, append/read API
    trace.md              # trace fact schema and rendering helpers
    simulation.md         # deterministic step runner
  stages/
    admission.md          # external events -> canonical facts
    parse.md              # message text -> needs/haves
    context.md            # needs + haves -> context candidates
    project.md            # messages/context -> visible projections
    apply.md              # committed projections -> Have facts
    unblock.md            # Need + Have -> Unblock
    sweep.md              # MessageDeleted -> Sweep
    send.md               # ready projections -> outbound sends
  variants/
    03_stage_projectors.md
```

## Stage Table

| Stage | Inputs | Outputs | Trace examples |
| --- | --- | --- | --- |
| `admission` | external create/delete events | `MessageCreated`, `MessageDeleted` | accepted, normalized, rejected |
| `parse` | `MessageCreated` | `Need`, local `Have` | parsed dependency, parsed provided key |
| `context` | `Need`, `Have` | context candidate facts | dependency still missing, match found |
| `project` | `MessageCreated`, context candidates | projection facts | projected blocked row, projected ready row |
| `apply` | projection facts | `Have` | projection committed as available |
| `unblock` | `Need`, `Have` | `Unblock` | need satisfied by source |
| `sweep` | `MessageDeleted` | `Sweep` | removed projection target |
| `send` | ready projection facts, `Unblock` | send facts or side effects | sent, deferred, skipped deleted message |

## Projector Outputs

The stages do not mutate shared state directly. Each stage writes an output fact
set that later stages can read.

```text
admission.out:
  MessageCreated("B", "B depends on A")

parse.out:
  Need("B", "A")

context.out:
  Trace("context", Need("B","A"), null, "missing A")

project.out:
  Projection("B", state="blocked", reason="Need(A)")

apply.out:
  Have("projection:B:block", "project")

unblock.out:
  Unblock("B", "A")

sweep.out:
  Sweep("B", "projection:B:*")
```

`Projection(...)` and send facts are implementation facts, not toy input facts.
The toy surface stays small while the trace log still shows what each stage did.

## Step-by-Step Flow

### 1. B Depends on Missing A

```text
external:
  create B: "B depends on A"

admission:
  + MessageCreated("B", "B depends on A")
  + Trace("admission", create("B"), MessageCreated("B", ...), "accepted")

parse:
  + Need("B", "A")
  + Trace("parse", MessageCreated("B", ...), Need("B","A"), "dependency")

context:
  + Trace("context", Need("B","A"), null, "no Have(A)")

project:
  + Projection("B", state="blocked", reason="missing A")
  + Trace("project", Need("B","A"), Projection("B", blocked), "blocked")

send:
  + Trace("send", Projection("B", blocked), null, "deferred")
```

### 2. A Arrives

```text
external:
  create A: "A is available"

admission:
  + MessageCreated("A", "A is available")

parse:
  + Have("A", "A")
  + Trace("parse", MessageCreated("A", ...), Have("A","A"), "provided key")

context:
  + ContextMatch("B", need="A", have_source="A")
  + Trace("context", Need("B","A"), ContextMatch("B","A","A"), "match")
```

### 3. B Unblocks

```text
unblock:
  + Unblock("B", "A")
  + Trace("unblock", [Need("B","A"), Have("A","A")], Unblock("B","A"), "satisfied")

project:
  + Projection("B", state="ready", context="A")
  + Trace("project", Unblock("B","A"), Projection("B", ready), "ready")

apply:
  + Have("projection:B:ready", "project")
  + Trace("apply", Projection("B", ready), Have("projection:B:ready", ...), "committed")

send:
  + Sent("B")
  + Trace("send", Projection("B", ready), Sent("B"), "sent")
```

### 4. Delete B Sweeps Existing Projections

```text
external:
  delete B

admission:
  + MessageDeleted("B")
  + Trace("admission", delete("B"), MessageDeleted("B"), "accepted")

sweep:
  + Sweep("B", "Projection(B, *)")
  + Sweep("B", "Have(projection:B:*)")
  + Trace("sweep", MessageDeleted("B"), Sweep("B", "Projection(B, *)"), "projection")
  + Trace("sweep", MessageDeleted("B"), Sweep("B", "Have(projection:B:*)"), "applied have")

project:
  + Trace("project", MessageDeleted("B"), null, "skip deleted")

send:
  + Trace("send", MessageDeleted("B"), null, "suppress sends")
```

Readers treat matching swept projections as absent:

```text
visible_projection(B) =
  latest Projection(B, *) where no later Sweep("B", "Projection(B, *)") exists
```

## Strengths

- Traceability is native: every stage can explain input, output, and skipped work.
- Simulation is simple: run stage projectors in order over an immutable fact log.
- Stage boundaries are readable and testable because each has a tiny input/output
  table.
- Replaying with extra trace enabled does not change the toy fact model.

## Friction

- The number of intermediate facts grows quickly, especially trace and projection
  facts.
- Ordering rules matter: `sweep` must dominate stale projections and pending
  sends.
- Stages can accidentally duplicate coordination logic, such as deleted-message
  checks in both `project` and `send`.
- The projector model is clear for simulation, but a production implementation
  needs compaction or indexed reads to avoid scanning the whole fact log.

# Rewrite Rules

## Commands Live In Event Modules

Commands belong under `event_modules`, alongside the event types, codecs,
projectors, queries, and module-owned tables they operate on.

CLI, RPC, jobs, and other adapters should dispatch into module commands instead
of constructing canonical event bytes directly. Adapters own input/output shape;
event modules own protocol and domain semantics.

The intended shape is:

```text
event_modules/<domain>/<module>/commands.rs
  command(ctx, input, writer) -> CommandOutput

event_modules/<domain>/<module>/codec.rs
  Event <-> CanonicalEventBytes

event_modules/<domain>/<module>/projector.rs
  EventWithContext -> Projection
```

## Event Writes Return Event IDs

The substrate should expose an event writer API that returns the event id from
the write path, including after projection, so commands can chain writes without
re-querying or inferring ids from projected state.

Use two levels of write API:

```text
append_event(bytes) -> Admission {
  event_id,
  status: Ready | Blocked { blocked_by } | Duplicate { status },
}

append_apply(bytes) -> WriteResult {
  event_id,
  status: Applied | AlreadyApplied | Blocked { blocked_by },
  emitted: Vec<EventId>,
}
```

Commands that need a prior event to be semantically present before constructing
the next event should use `append_apply` and require an applied result:

```text
let workspace = writer.append_apply(workspace::create(...))?.require_applied()?;

let account = writer.append_apply(account::create(
  workspace.workspace_id,
  workspace.event_id,
  username,
))?.require_applied()?;
```

Commands that intentionally create pending work, such as accepting an invite
before the invite event has synced, may use `append_event` or accept a blocked
`append_apply` result and surface that event id as pending.

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
- outbox rows
- emitted event ingestion
- returned event ids

Module commands own semantic construction:

- what command input means
- which state queries are required
- which canonical events to create
- how to interpret `Applied`, `AlreadyApplied`, or `Blocked`

All state mutation still goes through canonical events and projectors.

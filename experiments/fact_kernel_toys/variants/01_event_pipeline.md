# Variant 1: Event Pipeline Modules

Conventional design: append typed events, run module-specific projectors, and let each projector own its tables.

## Toy Types

```ts
type MessageCreated = { id: MessageId; body: string; refs: MessageId[] }
type MessageDeleted = { id: MessageId }

type Need = { messageId: MessageId; missingId: MessageId }
type Have = { messageId: MessageId }
type Unblock = { messageId: MessageId; satisfiedBy: MessageId[] }
```

## Module Layout

```text
fact_kernel_toys/
  events/
    log.ts              # append/read MessageCreated, MessageDeleted
    schema.ts           # shared event envelopes
  modules/
    messages/
      projector.ts      # MessageCreated/Deleted -> messages table
      tables.ts
    dependencies/
      projector.ts      # MessageCreated/Deleted -> Need/Have/Unblock
      tables.ts
    projections/
      projector.ts      # visible read model, swept by deletes
      tables.ts
```

## Tables

`event_log`

| seq | type | payload |
| --- | --- | --- |
| 1 | MessageCreated | `{ id: "B", refs: ["A"] }` |
| 2 | MessageCreated | `{ id: "A", refs: [] }` |
| 3 | MessageDeleted | `{ id: "B" }` |

`messages`

| id | body | deleted |
| --- | --- | --- |
| A | `...` | false |
| B | `...` | true |

`dependency_state`

| message_id | needs | status |
| --- | --- | --- |
| A | `[]` | have |
| B | `["A"]` | deleted |

`projection_index`

| projection | source_message_id | present |
| --- | --- | --- |
| visible_messages | A | true |
| visible_messages | B | false |

## Projector Outputs

The dependency projector emits internal facts for downstream projectors:

| input | output |
| --- | --- |
| `MessageCreated(B, refs: [A])` and A absent | `Need(B, A)` |
| `MessageCreated(A, refs: [])` | `Have(A)` |
| `Have(A)` with pending `Need(B, A)` | `Unblock(B, [A])` |
| `MessageDeleted(B)` | remove B needs, mark B deleted |

The projection projector writes visible rows only when a message is present, not deleted, and unblocked.

## Flow

1. `MessageCreated(B, refs: ["A"])` is appended.
2. `messages.projector` inserts B as not deleted.
3. `dependencies.projector` sees A is missing, records `Need(B, A)`, and marks B blocked.
4. `projections.projector` skips B because it is blocked.
5. `MessageCreated(A, refs: [])` is appended.
6. `messages.projector` inserts A.
7. `dependencies.projector` records `Have(A)`, finds pending `Need(B, A)`, clears it, and emits `Unblock(B, [A])`.
8. `projections.projector` writes A and B to `visible_messages`.
9. `MessageDeleted(B)` is appended.
10. `messages.projector` marks B deleted.
11. `dependencies.projector` removes B dependency rows and suppresses future unblock work for B.
12. `projections.projector` sweeps every row indexed to B, so `visible_messages/B` disappears even though the event log remains.

## Friction

- Each module needs delete handling, otherwise stale projections survive.
- `Need`, `Have`, and `Unblock` are easy to explain, but their ordering rules leak into projector code.
- Sweeps need a projection index, adding bookkeeping that is unrelated to the domain model.
- Rebuilds are straightforward: replay events in order, but every projector must be idempotent.

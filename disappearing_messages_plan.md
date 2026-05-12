# Disappearing Messages Plan

This document extends `encryption_plan.md` with a first-class design for
disappearing messages: messages that expire automatically after a configurable
TTL, without anyone running `delete-message`. It is meant to be read alongside
`plan.md`, the current `encryption_plan.md`, and the older
`event-centered-encryption-auth-plan/encryption_plan.md` from which the
phase-two history-tree shape is borrowed.

The minimum viable shape is:

```text
admin-signed workspace TTL setting
  -> message authoring snaps an expiry minute into the message event
  -> per-minute history tree node covers all messages in that minute
  -> daemon worker punctures fully expired minute nodes on tick
  -> deterministic deletion summary commits to the expired minute set
```

This doc reuses the existing deletion + purge story rather than inventing a
parallel one. Disappearing messages are deletion facts whose source is "the
clock advanced past a minute boundary", not "an author chose to delete one
message". The same retained-cover/purge-cover machinery covers both.

## How This Doc Relates To The Plans It Extends

The current `encryption_plan.md` describes phase one (ordinary recipient-key
wraps for an entire `removal_frontier_id`) and a narrow phase-two slice that
adds local history range-node secrets:

> Real HKDF-SHA256 derivation in `core::crypto` for local range-node secrets.
> ... `local_history_node_secret` local events name canonical range nodes and
> can tombstone an older local path node by exact row delete.
> (`encryption_plan.md`, lines 277-285)

The original `event-centered-encryption-auth-plan/encryption_plan.md` Phase
Two section (lines 271-359) is more specific about *what* a leaf names and
*how* the cover summary is computed. The relevant lines are:

> ```
> history_coord = (unix_minute, event_id)
> leaf_secret   = KDF(epoch_root, "leaf", unix_minute, event_id)
> node_secret   = KDF(parent_secret, "left" | "right", node_prefix)
> ```
>
> Use BLAKE3-256 for event ids, tree commitments, and set hashes, with
> domain-separated inputs for each use.
> (original plan, lines 277-287)

> ```
> deleted_set'       = deleted_set union incoming_delete_cover
> retained_cover'    = canonical_minimal_cover(all_history - deleted_set')
> purge_cover'       = canonical_minimal_cover(deleted_set')
> history_summary_id = Hset("history-delete-summary", deleted_set', retained_cover')
> ```
> (original plan, lines 314-320)

Disappearing messages depend on both of those primitives: leaf coords keyed
by `(unix_minute, event_id)`, and a deletion summary that commutes under set
union. **The current implementation diverges from that spec**: see the
"Acknowledged divergence from the plan" section below. This design assumes
the corrected primitives and surfaces the gap explicitly.

## Acknowledged Divergence From The Plan

The phase-two slice landed in
`src/protocol/event_modules/encryption/local_history_node_secret/` does not
match the original spec. Specifically:

1. **KDF.** The plan calls for BLAKE3-256-keyed-hash with domain separation.
   The implementation uses HKDF-SHA256 (see
   `local_history_node_secret/commands.rs:48` calling `crypto::hkdf_sha256_key`
   with purpose `b"topo local history node secret v1"`).
2. **Leaf granularity.** The plan's leaf coordinate is
   `(unix_minute, event_id)`. The current code uses a power-of-two `range_start
   / range_width` keyed off `u64` slots interpreted as `created_at_ms` (see
   `commands.rs` and `codec::validate_range`); leaves are message-grained, not
   minute-grained.
3. **No `event_id` in leaf coord.** Two messages with the same `created_at_ms`
   would derive the same leaf secret. The current `next_timestamp` helper in
   `core/logical_clock.rs` keeps locally authored timestamps strictly
   increasing, but it cannot prevent cross-peer collision: peer A and peer B
   may independently author messages at the same ms while offline.

Disappearing messages cannot be built honestly on top of (1) and (2) without
adding cross-peer collision risk and a node-per-event tree. Therefore this doc
assumes the corrected leaf shape:

```text
history_coord = (unix_minute, event_id)
leaf_secret   = KDF(removal_frontier_secret, "leaf", unix_minute, event_id)
minute_secret = KDF(removal_frontier_secret, "minute", unix_minute)
node_secret   = KDF(parent_secret, "left" | "right", node_prefix)
```

The KDF must be a real reviewed primitive. `core/crypto.rs` already exposes
`hash` (BLAKE3) and `hkdf_sha256_key`. Adding a `blake3_keyed_hash` helper with
domain-separation tags `"topo disappearing minute v1"`,
`"topo disappearing leaf v1"`, etc., is needed; it is not invented crypto, just
a domain-separated wrapper around BLAKE3's keyed mode. Until that helper
exists, disappearing-messages code should not claim to implement the spec.

A separate slice — outside the scope of this plan — must rewrite
`local_history_node_secret` to take `unix_minute` as a leaf coordinate and use
BLAKE3-keyed-hash. That slice unblocks (a) cross-peer collision safety and (b)
the per-minute coarse-grained puncture that disappearing messages depend on.
This document specifies disappearing messages on top of the corrected shape;
the two slices land separately.

## 1. Vocabulary And Event Types

### Scope choice: workspace-wide TTL with no per-message override

poc-7 (Quiet) historically modeled disappearing messages at workspace
granularity. The simplest workable choice for poc-8 is:

- **Workspace-wide TTL.** A single admin-signed shared event sets the TTL for
  every shared content event in the workspace.
- **No per-message override** in the first slice. Per-message TTL means every
  message must commit to its own expiry, which then has to round-trip through
  the encryption/key-wrap obligations as if every TTL were a private epoch.
  That cost is real and is rejected in the first slice.
- **Per-thread TTL** is rejected. poc-8 has no first-class thread event; adding
  one is a separate problem and is explicitly out of scope.
- **Per-author TTL** is rejected. Authors do not own the workspace's
  forward-secrecy boundary; admins do.
- **Per-recipient TTL** is rejected. poc-8 is p2p; recipients are equal peers,
  not server-managed accounts.

### New event types

```text
src/protocol/event_modules/encryption/disappearing_messages_setting/
  types.rs        // DisappearingMessagesSettingEvent
  codec.rs        // signed envelope; admin-authority dependency
  commands.rs     // set_workspace_ttl(ttl_minutes, signer_admin_id, ...)
  projector.rs    // writes (workspace_id, setting_event_id, ttl_minutes,
                  //   effective_at_ms) row; supersedes prior setting row
  schema.rs       // DISAPPEARING_MESSAGES_SETTINGS table
  cli.rs          // optional: admin command to set/inspect TTL
  mod.rs

src/protocol/event_modules/encryption/expired_minute/
  types.rs        // local-only ExpiredMinuteEvent
  codec.rs
  commands.rs     // expire_minute(workspace_id, removal_frontier_id, minute)
  projector.rs    // writes EXPIRED_MINUTES row + tombstone summary
  schema.rs
  mod.rs
```

`disappearing_messages_setting` is a **shared admin-signed event**. Its
canonical bytes carry:

```text
TYPE_DISAPPEARING_MESSAGES_SETTING (u8)
workspace_id           : EventId
created_at_ms          : u64
ttl_minutes            : u32   // 0 = disabled
effective_at_minute    : u64   // floor(created_at_ms / 60_000); included for
                               //   deterministic comparison without
                               //   re-deriving from created_at_ms
signer_admin_event_id  : EventId  // admin authority dependency
```

Wrapped in the existing `signed::codec` envelope used by `admin`, `user`, and
`endpoint_shared`. Dependencies: `workspace_id`, `signer_admin_event_id`,
`signer_endpoint_shared_id`. The signer's endpoint must be authorized by the
named admin user (same model used by `admin` projection today).

`expired_minute` is a **local-only** event. Its canonical bytes carry:

```text
TYPE_EXPIRED_MINUTE (u8)
workspace_id           : EventId
removal_frontier_id    : EventId
unix_minute            : u64
expired_at_ms          : u64    // logical time when expiry was projected;
                                //   diagnostic only, not in the summary
source_setting_id      : EventId  // disappearing_messages_setting that
                                  //   authorized expiry; dependency
```

Dependencies: `removal_frontier_id`, `source_setting_id`. The event id is
deterministic from canonical bytes per the existing rule that proposed event
ids come from canonical bytes (RULES.md, "Proposed Events Have Deterministic
IDs"). Two peers receiving the same setting and reaching the same
`unix_minute` independently produce the same `expired_minute` event id.

### What is shared vs local

| Event                              | Scope  | Sync? | Notes |
|------------------------------------|--------|-------|-------|
| `disappearing_messages_setting`    | Shared | Yes   | Admin authority. |
| `expired_minute`                   | Local  | No    | Each peer derives its own; convergence comes from determinism. |
| Existing `message`                 | Shared | Yes   | Plus a derived `expires_at_minute` projection row (see §3). |
| Existing `local_history_node_secret` | Local | No  | Already local. |

`expired_minute` deliberately does not become a shared event. The shared
ingredient is the setting; the time advance is local clock work. Two peers
that both reach minute `M` and both have the same setting derive the same
expired-minute fact independently. Making it shared would force every peer to
acknowledge every other peer's clock advance, which is the wrong shape.

This mirrors the encryption plan's local-secret-events principle:

> The most important correction from the older plan is that local secrets are
> events. They should participate in the common event pipeline like any other
> dependency. (`encryption_plan.md`, lines 17-19)

## 2. Setting And Changing Disappearing-Message Settings

### Authority

Any workspace admin can issue a `disappearing_messages_setting` event. This
matches the existing admin model in
`src/protocol/event_modules/identity/admin/`: admins sign workspace-scoped
authority events, and the projector validates the signer's endpoint against
its admin's `signing_public_key`. No quorum, no founder-only restriction. The
cost of being wrong is bounded — a later setting can always change the TTL,
and existing messages already carry their authored-time expiry (see below) —
so a single-admin authority threshold matches the rest of the workspace
admin model.

This matches poc-7 (Quiet) precedent: an admin/owner-equivalent role sets
disappearing-message policy.

### Propagation

A setting change is a shared event. Sync delivers it like any other shared
fact. Convergence rules:

- **Order-independent projection.** Two settings `S1, S2` with
  `S1.created_at_ms < S2.created_at_ms` produce the same active setting row
  regardless of arrival order, because the projector keys the
  active-setting row by `workspace_id` and replaces it iff the incoming
  setting has a later `(created_at_ms, event_id)` than the current row.
- **Late arrivals do not retroactively change message expiry.** A setting
  applies only to messages authored after its `effective_at_minute`; messages
  authored before that minute were already stamped with their authored-time
  expiry and remain expired or live according to the setting that was active
  at authoring time.

### Authored-time expiry stamping

Every shared content event must carry the expiry it was given when authored,
not look up the current setting at projection time. Looking up at projection
time would mean a setting change retroactively rewrites every message's
expiry, which is exactly what "late-arriving setting events should not change
already-authored messages" forbids.

The authoring path is therefore:

```text
message::commands::send(input, ctx)
  context.active_setting -> (ttl_minutes, setting_event_id)
  expires_at_minute = floor(input.created_at_ms / 60_000) + ttl_minutes
  // expires_at_minute = u64::MAX when ttl_minutes == 0 (TTL disabled)
  ...stamps expires_at_minute into the canonical bytes
```

The active setting is read through a narrow command-context query (per
RULES.md "commands receive explicit input values plus narrow read context
values"). It is not a worker drain.

### Conflicting concurrent setting changes

Two admins concurrently emitting `S1` and `S2` is the same problem as two
admins concurrently emitting other workspace settings. Resolution is the
existing pattern: order by `(created_at_ms, event_id)` deterministically. Both
peers converge on the same active setting once both events have synced. There
is no "winner takes all" race because the projector keys the active row by
workspace and replaces strictly under `(created_at_ms, event_id)` ordering.

If a message was authored under `S1` while `S2` was concurrently in flight,
the message is still stamped with `S1`'s TTL. This is correct: at the time of
authoring, `S1` was the message's view of policy. Subsequent peers will agree
on the per-message expiry because the message canonical bytes carry it.

## 3. Per-Message Expiry Vs Workspace Setting

### Recommendation: stamp `expires_at_minute` into `MessageEvent` canonical bytes

The two options are:

1. **In-event `expires_at_minute`.** Add a fixed-width `u64` to
   `MessageEvent` canonical bytes after the existing per-message FS field
   set. Disappearing messages then have a self-describing expiry that is
   deterministic from the canonical bytes — no projector lookup, no race
   between message and setting arrival.
2. **External projection table.** Keep `MessageEvent` unchanged and write
   `(message_id -> expires_at_minute)` rows derived from the active setting
   at projection time. This sounds cheaper but is wrong: it makes message
   expiry depend on which setting events have arrived, which violates "same
   shared event set converges to the same projected state regardless of
   order".

Option 1 wins. The trade-off is that every message event grows by 8 bytes,
but message canonical bytes are already fixed-width per RULES.md, so adding a
fixed field is exactly what the codec allows.

The new `MessageEvent` shape (and the parallel `ReactionEvent`,
`FileEvent`, `FileSliceEvent` shapes) becomes:

```text
TYPE_MESSAGE (u8)
workspace_id           : EventId
created_at_ms          : u64
author_user_id         : EventId
removal_frontier_id    : EventId
local_key_secret_id    : EventId
expires_at_minute      : u64    // NEW; u64::MAX = no expiry
nonce                  : XChaCha20Poly1305Nonce
ciphertext             : MessageCiphertext
```

The projector validates `expires_at_minute >= floor(created_at_ms / 60_000)`
and rejects messages whose stamped expiry is in the past at authoring time.
This is a sanity guard against forged events; it is not a forward-secrecy
boundary, since the projector cannot prove what the active setting *was* at
the message's `created_at_ms`. The forward-secrecy boundary lives in §4 (the
history tree puncture).

### File and reaction expiry

Files and reactions inherit the parent message's TTL. Their canonical bytes
also carry `expires_at_minute`, set to the parent message's value at
authoring time, not recomputed from the active setting. This keeps the
"authored-time expiry stamping" rule uniform across content event types and
avoids a parent-lookup race.

## 4. Integration With The Per-Message FS History Tree

### Leaf coord and minute granularity

Per the original plan (lines 277-281), the leaf coord is
`(unix_minute, event_id)`:

```text
unix_minute  = floor(created_at_ms / 60_000)
leaf_secret  = KDF(epoch_root, "leaf", unix_minute, event_id)
```

Minute granularity is **load-bearing** for disappearing messages. The
per-minute epoch node is the smallest unit at which expiry can advance. Sub-
minute granularity (per-second or per-millisecond) would create one node per
event in practice and force every expiry to puncture every leaf
individually, which defeats the cover-summary scheme. Coarser-than-minute
granularity (per-hour, per-day) makes expiry chunkier than users want.

Therefore the minute is the unit of:

- KDF derivation (one node per `unix_minute`),
- expiry advancement (one `expired_minute` event per minute),
- cover-summary commitment (the deletion summary commits to the set of
  expired minutes).

### Per-minute node key derivation

```text
minute_node_secret(workspace_id, removal_frontier_id, unix_minute)
  = blake3_keyed_hash(
      key   = removal_frontier_secret(workspace_id, removal_frontier_id),
      data  = "topo disappearing minute v1" || workspace_id || removal_frontier_id || unix_minute,
    )
```

`blake3_keyed_hash` lives in `core::crypto` and is a thin domain-separated
wrapper around BLAKE3's keyed-hash mode. The `removal_frontier_secret` is
already the source secret for `local_history_node_secret`; the new helper
just adds a minute-granularity derivation alongside the existing
range-node derivation.

### The "minute fully expired" condition

A minute is *fully expired* when, for every message authored in that minute
under the corresponding `removal_frontier_id`, the message's
`expires_at_minute < current_minute`. Because messages stamp their expiry at
authoring time, a minute's expiry is determined by the largest stamped
`expires_at_minute` among messages with `unix_minute(created_at_ms) == M`.

Equivalently, with workspace-wide TTL and no per-message override, every
message in minute `M` shares the same TTL `T`, so the minute fully expires
at `M + T + 1`. The general formulation supports a future per-message
override slice without changing the cover algorithm.

### Per-minute puncture and the "purge cover"

When a minute is fully expired, the receiver punctures the entire
`unix_minute` epoch node (not its leaves). After puncture:

- The minute node's secret is irretrievably gone (its row is deleted via
  exact-row-delete).
- Every per-message leaf under that minute loses its derivation source.
- All ciphertext bound to those leaf secrets is unrecoverable.

The deterministic-cover gain over phase one is that one tombstone retires
many leaves. Without this gain, every disappearing message would need its own
tombstone event, which scales badly.

The "purge cover" at minute granularity is a set of cover entries:

```text
purge_cover_entry = (removal_frontier_id, unix_minute)
```

distinct from the user-delete "leaf retain set" used by individual
`message_deletion` events:

```text
leaf_retain_entry = (removal_frontier_id, unix_minute, event_id)
```

Both feed into the same deletion summary in §6.

## 5. Ongoing Purge Of Cover, Keys, Events

The current `content_purge` worker drains *on demand*: deletion projection
writes a `content.purge_pending` row, the post-admission hook runs the worker
once, and the daemon's tick still belt-and-suspenders runs a full scan
periodically. See `src/workers/content_purge.rs` and
`src/protocol/event_modules/content/message_deletion/schema.rs`.

Disappearing messages need a **time-driven** drain. There is no admission
event to react to: the only signal is that the logical clock has advanced
past a minute boundary.

### New worker: `disappearing_minute_expiry`

```text
src/workers/disappearing_minute_expiry.rs

inputs:
  - logical_clock::logical_time(store)
  - active disappearing_messages_setting per workspace
  - existing per-minute message index (to enumerate non-expired minutes)
  - already-projected expired_minute rows (idempotent skip)

step:
  for each (workspace_id, removal_frontier_id) in active workspaces:
    let now_minute = floor(logical_time / 60_000)
    let setting    = active_disappearing_messages_setting(workspace_id)
    if setting.ttl_minutes == 0: continue
    for unix_minute in candidate_expired_minutes(workspace_id, now_minute):
      if expired_minute_exists(workspace_id, removal_frontier_id, unix_minute): continue
      // Build a deterministic expired_minute event and admit through the
      // common pipeline. The event's projector then:
      //   1. Walks every message + reaction + file + slice authored in
      //      this (workspace, frontier, unix_minute), writes tombstone
      //      summary rows preserving "this minute existed and held N
      //      events, now expired", and exact-row-deletes the read-model
      //      rows.
      //   2. Calls retention::purge_event_storage_in_tx for each event,
      //      removing canonical bytes (the same primitive used by
      //      content_purge today).
      //   3. Tombstones the minute's epoch node by exact-row-deleting the
      //      LOCAL_HISTORY_NODE_SECRETS row keyed by
      //      (workspace, frontier, range_start=unix_minute, range_width=1)
      //      after writing a LOCAL_HISTORY_NODE_TOMBSTONES row.
```

The worker calls `expired_minute::commands::expire_minute(...)` and admits
the proposed event through the common worker. It does not mutate storage
directly — that follows the encryption plan's rule:

> Derivation workers may create events, but only by calling commands and
> sending proposed events back through common admission.
> (`encryption_plan.md`, lines 36-38)

### Tick budget

The daemon already has `--tick-ms`; `disappearing_minute_expiry` registers as
a `daemon_step` worker on the same tick (see `content_purge::daemon_worker`
for the pattern). One scan per tick, bounded by the standard `work_limit`,
catches up the expired-minute set deterministically. Tick budget is
unchanged because the per-tick work is `O(minutes since last tick)`, which
is `O(1)` under any reasonable tick cadence.

### Logical clock interaction

The expiry worker reads from `crate::core::logical_clock::logical_time`,
which is the same source used by every CLI test today. Tests that need to
"advance time past TTL" call `clock advance` and then drain the daemon. This
keeps disappearing-messages tests deterministic: no real wall clock, no
flaky sleeps. Production binaries can either expose a `clock now` command
that snapshots system time into the logical clock, or set the logical clock
from system time on every tick — that policy choice belongs to the daemon
loop, not to the worker, and is the same choice already made for any other
time-sensitive worker.

### Writing tombstones, then purging

Order of operations within the transaction:

1. Write durable tombstone summary rows (one per expired event, plus one
   per expired minute).
2. Exact-row-delete the read-model rows (messages, reactions, file
   descriptors, file slices).
3. `retention::purge_event_storage_in_tx` to remove canonical bytes.
4. Exact-row-delete the corresponding `LOCAL_HISTORY_NODE_SECRETS` row,
   after writing a `LOCAL_HISTORY_NODE_TOMBSTONES` row pointing the
   retired minute node at the expiry event id.

Step 4 is what keeps a future replay from re-deriving the minute secret.
The tombstone row is the surviving public commitment that the minute
existed and is now gone, per RULES.md "purging may remove physical
evidence, but it must not be the only representation of a semantic
change".

## 6. Cover Summary And Monotonicity

The deletion summary commits to both individual deletes and expired
minutes:

```text
history_summary_id = Hset(
    "history-delete-summary",
    deleted_set,           // sorted by (unix_minute, event_id)
    retained_cover,        // sorted by canonical node prefix
    expired_minute_set,    // sorted by unix_minute
)
```

`Hset` is a domain-separated BLAKE3 hash over the concatenation of:

```text
"history-delete-summary v1"
|| u32_be(deleted_set.len())
|| (for each entry sorted by (unix_minute, event_id):
      u64_be(unix_minute) || event_id)
|| u32_be(retained_cover.len())
|| (for each entry sorted by node_prefix:
      u8(width_bits) || u64_be(node_prefix))
|| u32_be(expired_minute_set.len())
|| (for each entry sorted by unix_minute:
      u64_be(unix_minute))
```

Sorts are bytewise lexicographic. All multi-byte integers are big-endian.
Set sizes are `u32_be` to fail loudly past 2^32 entries; production-scale
expiry should never approach that bound.

### Monotonicity claims

1. **Set-equality ⇒ id-equality.** Two peers with the same
   `(deleted_set, expired_minute_set)` derive the same `retained_cover` and
   therefore the same `history_summary_id`, regardless of the order in
   which deletes and minute expiries arrived.
2. **Idempotent expiry application.** Applying the same `expired_minute`
   event twice is a no-op: the second admission is a duplicate by event id,
   the second projection is a no-op because the read-model rows are already
   gone, and the canonical-bytes purge is a no-op because the bytes are
   already missing. The summary is unchanged.
3. **Re-running the worker against the same logical-clock value is
   idempotent.** The set of candidate minutes the worker enumerates is
   determined by `now_minute` and the active setting; `expired_minute`
   events are admitted only when the corresponding row does not yet
   exist. Running the worker N times at the same logical time yields the
   same summary as running it once.
4. **Delete-then-expire and expire-then-delete commute.** A
   `message_deletion` for an individual message followed by minute-level
   expiry of that minute, vs. minute-level expiry followed by an arriving
   `message_deletion`, both reach the same final
   `(deleted_set, expired_minute_set)`. The deletion-set entry for that
   single message is redundant once the whole minute is in the expired-set,
   but it does not change the summary id (the deleted-set is still hashed
   in).

## 7. Edge Cases The Design Must Handle

### Cross-peer same-`created_at_ms` collision

Two peers offline-author messages with `created_at_ms = 1_700_000_000_000`.
Under the current `next_timestamp` scheme each peer's local clock is
strictly increasing, but cross-peer there is no coordination. With the
plan's `(unix_minute, event_id)` leaf coord:

- Both leaves land in the same `unix_minute` node.
- Each leaf is keyed additionally by its `event_id`, which is BLAKE3 over
  canonical bytes. Even if `created_at_ms` collides, the two messages have
  different ciphertext / nonce / signer and therefore different event ids.
- The two leaves are distinct under the leaf KDF; no key collision.

If the leaf coord were just `unix_minute` without `event_id`, both peers
would derive the same leaf secret and collide. Including `event_id` is what
makes the cross-peer collision case safe.

### Authored-but-not-synced expiry

Peer A authors a message with `expires_at_minute = M`. Peer A goes offline
for longer than the TTL. Peer B's clock is now past `M`. When peer A
reconnects, the message tries to sync to peer B.

Two policies are possible:

1. **Admit-and-immediately-purge.** Peer B admits the message through the
   common pipeline. Projection succeeds (the message is well-formed),
   writes the read-model row, then the disappearing-minute-expiry worker
   on the next tick observes that this minute has been expired-set since
   long before and purges. The read-model row blinks into existence and
   then disappears.
2. **Refuse at admission.** Peer B's `event_admission` checks the
   message's `expires_at_minute < current_minute` and rejects without
   projection.

Choice (2). Reasoning:

- The message's canonical bytes survive on disk as `Rejected`; that wastes
  no key material, since the rejection is deterministic from the message
  and the local clock.
- Choice (1) requires plaintext to materialize on disk briefly, which
  contradicts the "ciphertext-only durable shared event" rule.
- A future receiver coming online after their own clock has advanced past
  the expiry will reach the same rejection deterministically, so no peer
  needs to keep the bytes around as projection bait.

This matches RULES.md's general rejection model: the receiver decides
under the same projector rules every other peer would.

### Conflicting TTL settings

Two admins concurrently emit `S1` and `S2` with different TTLs. The
projector keys the active setting row by `workspace_id` and replaces it
strictly under `(created_at_ms, event_id)` ordering — last-event-wins by
deterministic compare. Both peers converge on the same active setting once
both events have synced. Messages authored under `S1` keep `S1`'s TTL;
messages authored under `S2` keep `S2`'s; messages authored after both have
synced use whichever event is "active" by the deterministic compare.

### Manual delete plus disappearing TTL

A user runs `delete-message` on a message whose disappearing TTL has not
yet fired. The existing `message_deletion` event projects, the
content_purge worker runs, the message's leaf is retired ahead of schedule.
Later, the disappearing-minute-expiry worker reaches that minute and tries
to puncture the minute node. The retired leaf is no longer present; the
minute-node retire still proceeds. The semantics are:

- Manual delete is monotonic with TTL expiry. Both end up with the
  message's canonical bytes purged.
- The expired-minute tombstone is the durable summary; the manual-delete
  tombstone is a sub-summary. Both survive; both contribute to the
  deletion summary id.
- Re-running expiry against an already-deleted minute is a no-op.

### Manually-deleted leaf inside a not-yet-expired minute

Mirror image: a single message in minute `M` is manually deleted via
`message_deletion`. Its leaf secret row is retired immediately by the
existing per-message FS retire path (`local_history_node_secret`
projection). Later, when minute `M` expires globally, the
disappearing-minute-expiry worker enumerates messages in `M` and finds the
already-deleted message with no read-model row. The worker:

- Skips the per-event tombstone for this message (already written).
- Continues with siblings.
- Retires the minute node when reached.

The no-op is clean: every step that "would have" purged the message
canonical bytes finds them already missing and proceeds without error.

## 8. Out Of Scope

Explicitly not in this design:

- **Per-thread TTL.** poc-8 has no thread event.
- **TTL on file events independent of the parent message.** Files inherit
  the parent message's TTL via the same authored-time stamp.
- **Admin-override TTLs that bypass the workspace setting.** No "admin can
  exempt this message" path. If admins need different policy for different
  messages, they change the setting and re-author.
- **Per-recipient TTL.** Every workspace member sees the same TTL. There
  is no "Bob's view expires faster than Alice's" mode.
- **Read receipts or per-reader expiry.** poc-8 does not model read state.
- **Server-side enforcement.** poc-8 is p2p; there is no server.
- **Fractional or sub-minute TTL.** TTL is a `u32` count of minutes.
- **Time-zoned or wall-clock-aligned TTL.** Expiry is in unix minutes; UI
  may render in local time, but the protocol counts minutes from epoch.
- **Resurrection of expired messages.** Once a minute is in the expired
  set, no event can un-expire it. A future "extend TTL" feature would need
  to be a different design with very different forward-secrecy
  consequences.
- **Sub-minute jitter / random expiry windows.** Expiry is deterministic
  from `(created_at_ms, ttl_minutes)`.
- **Disappearing CLI sessions, notifications, or sync state.** Only
  durable shared content events expire.

## 9. Implementation Order

Each slice must include realistic tests and must be committed on this
worktree branch before handoff (the encryption plan's worktree rule
applies).

### Slice 1: minimum viable disappearing messages

Smallest viable proof. No CLI for changing the TTL setting; the TTL is
baked into workspace creation as a fixed argument.

1. Add `core::crypto::blake3_keyed_hash` with domain-separated tags. (Or
   document the helper as the explicit prerequisite for slice 2 if slice
   1 can use HKDF-SHA256 honestly; pick one and surface it in code.)
2. Rewrite `local_history_node_secret` to take `(unix_minute, event_id)`
   leaf coords using BLAKE3-keyed-hash. This is the cross-peer collision
   fix and the per-minute node prerequisite.
3. Add `expires_at_minute: u64` to `MessageEvent` canonical bytes; codec
   length and tests update; projector validates non-negative future-or-
   past authored-time semantics.
4. Add a `workspace.disappearing_ttl_minutes` initialization argument to
   `workspace::commands::create`. Slice 1 hardcodes this at creation; no
   changeability yet.
5. Add `expired_minute` event module: types/codec/commands/projector/
   schema/mod. Local-only, depends on a synthetic
   "workspace_initial_setting" until slice 2 introduces the shared event.
6. Add the `disappearing_minute_expiry` worker. Register it on the
   daemon tick alongside `content_purge`.
7. Black-box CLI test: two endpoints, authored TTL = 1 minute, send a
   message, advance the logical clock past the minute, run sync + drain,
   assert the message is gone from both peers' read models and the
   canonical bytes are purged.

### Slice 2: setting events

8. Add `disappearing_messages_setting` shared event module. Admin-signed.
   Replace slice 1's hardcoded creation argument with the shared event.
9. Add admin CLI for setting the TTL.
10. Project setting changes; validate that messages authored under the
    pre-change TTL keep their stamped expiry.

### Slice 3: deletion summary monotonicity

11. Implement `Hset` deletion summary covering deleted_set,
    retained_cover, expired_minute_set.
12. Property tests for set-equality ⇒ id-equality, expiry idempotence,
    delete-then-expire / expire-then-delete commutativity.
13. Cross-peer summary-equality CLI test: peers reach the same summary
    after independent expiry advancement and a single manual delete.

### Slice 4: reactions and files

14. Stamp `expires_at_minute` into reaction, file, and file_slice
    canonical bytes. Inherit parent message's expiry at authoring time.
15. Extend the expiry worker to enumerate non-message content; verify
    purge of file-slice ciphertext when the parent message minute
    expires.

### Slice 5: rotation interplay

16. Test interaction with `recipient_key_tombstone` and
    `removal_frontier`: a frontier change mid-TTL leaves old-frontier
    minutes punctured under the old frontier's history tree; expiry
    worker enumerates per-frontier.
17. Test invite-time history grant: a newly invited endpoint receives
    only retained-cover nodes for not-yet-expired minutes, never an
    expired minute's secret.

After slice 5, disappearing messages compose with the rest of the
encryption plan: rotation, deletion, history-tree puncture, and ciphertext
purge all share the same deletion-summary commitment, and the daemon's
tick-driven worker keeps the on-disk state aligned with the current
logical time.

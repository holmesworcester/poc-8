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

## Implementation Note (Supersedes Sections 1–5)

The slices that shipped on the `task-disappearing-messages` branch do **not**
introduce an `expired_minute` event, do **not** tombstone whole minutes, and
do **not** sync any expiry-related fact between peers. The earlier sections
(1–5) describe an `expired_minute`-event-based design that was abandoned;
this note records what actually got built and why.

### What ships

  * **Per-message stamping (slices 1 + 3).** Each `MessageEvent` commits in
    canonical bytes to its own `expires_at_minute: u64` and a
    `disappearing_setting_id: EventId` — the policy under which it was
    authored, either a signed `disappearing_messages_setting` or the
    workspace event id (slice-1 fallback). The projector validates the
    stamped expiry against the referenced policy.
  * **Per-peer clock-driven retirement (slice 1).** The
    `disappearing_minute_expiry` daemon-step worker scans `sealed_messages`
    every tick. For each row whose `expires_at_minute < now_unix_minute`,
    it deletes the read-model + sealed rows, writes a
    `MESSAGE_TOMBSTONES` row (which triggers the existing `content_purge`
    cascade for reactions/files), purges the message's canonical bytes,
    and calls `RetireDeletedEventLeaf` for the message's per-event leaf.
  * **Re-arrival rejection.** The message projector reads
    `now_unix_minute` from `EventContext` and tombstones expired-at-receive
    messages with a deletion label so re-arrivals can't resurrect them.
  * **Cascade through `content_purge` (slice 4).** Reactions, files, and
    file_slices are reclaimed in the same daemon tick via `content_purge`
    by gating on the parent message's tombstone. Reaction leaves are
    additionally retired by the disappearing-minute worker
    (parent-driven).

### What does *not* ship (deliberate simplifications)

  * **No `expired_minute` event.** Convergence is provided by canonical-bytes
    equality of the original messages: every peer admits the same bytes,
    derives the same `expires_at_minute`, and reaches the same retirement
    decision when its own clock crosses the boundary. There is no shared
    "expiry fact" event to converge on.
  * **No whole-minute tombstone — and not as a future optimization
    either.** The encryption-worker TODO at
    `src/workers/encryption.rs:1147` describes a `RetireExpiredMinute`
    primitive that would consolidate retirement to one tombstone per
    minute instead of one per leaf. **This optimization is permanently
    off the table for mutable-TTL disappearing messages**, because
    whole-minute retirement breaks eventual consistency in two ways:

      1. *Same minute, different TTLs.* A setting change mid-minute
         leaves message X (TTL=1h) and message Y (TTL=24h) both in
         minute M with different stamped expiries. When the clock
         crosses M+1h, whole-minute retire would wipe Y along with X
         even though Y still has 23h to live.
      2. *Late-arriving messages in a "retired" minute.* Peer A's
         clock crosses M+TTL and whole-minute retires M. Peer B
         delivers a message Y authored in M with a longer effective
         TTL (or under a setting peer A hasn't seen yet). Peer A
         cannot decrypt Y — the minute_node is gone — and silently
         drops it. Peer C (clock not yet crossed) admits Y normally.
         Permanent divergence on Y's existence.

    Per-leaf retirement avoids both: the minute_node is wiped on the
    descend path of *one* leaf at a time, and surviving siblings in
    the same minute remain reachable via the trie cover materialized
    by that walk. We pay per-leaf cost for the consistency.
  * **No deletion-summary commitment** (the abandoned slice-3
    `Hset(deleted_set, retained_cover, expired_minute_set)`). Convergence
    on the cover summary already implies agreement on retained state, and
    the deletion *path* is implied by canonical-bytes equality of the
    original messages.

### Mutable-TTL ⇒ dirty-tree consequence

Per-message stamping monotonically fixes each message's expiry at
authoring; the admin can still flip-flop the policy ("strict" 1 minute
→ "less strict" 5 minutes → strict again) without retroactively
changing already-authored messages' stamps. That gives us monotonicity
*per message*, but loses the property that "all leaves in minute M
retire together at minute M+TTL" — different leaves in a minute can
retire at different boundaries. The FS tree therefore accumulates
per-leaf tombstones over time; pruning that debris requires either:

  1. A future fixed-TTL workspace mode (immutable disappearing setting
     baked into workspace creation), enabling whole-minute retirement.
  2. A periodic key rotation (new `removal_frontier`) that starts a
     fresh subtree, leaving the old debris tombstoned in a frontier
     nobody authors under anymore.

### Why keep the time axis at all (under mutable TTL)

The 2-axis tree (time tree + within-minute trie) is preserved despite
not exploiting whole-minute retirement under mutable TTLs. The
**actual** reason is per-retirement cover-cost reduction, which I had
wrong in an earlier draft. Walking through it:

The retire walk wipes the **F root** in addition to the descend path
(see `after_retire_authoring_under_wiped_frontier_errors`). Once F is
wiped, no future event under F can derive *anything* — F is dead.
That means the FS guarantee for the retired leaf doesn't depend on
covering unknown future events; it depends on the trunk being gone.

Therefore the retire walk only needs to materialize coverage at
**actually-existing tree levels** (the path from F root through to the
leaf), not at every possible bit depth from 0 to 256. The cost is
**constant per retirement**, set by the **tree's structural depth**:

  * **Time tree**: depth ≤ log₂(`TIME_TREE_ROOT_WIDTH`) ≈ 57. The
    walk materializes both descend and sibling at each level
    (skipping the width-1 sibling). All ~57 sibling internals are
    retained; all ~57 descend internals are wiped + tombstoned.
  * **Within-minute trie**: depth = log₂(messages_per_minute). For
    typical chat workloads this is ≤ 7. Sibling internals at each
    divergence depth are retained; descend internals are wiped.

Per-retirement cost ≈ 30 KB cover state + ~7 KB tombstones in
practice. **Constant**, set by tree dimensions.

If we collapsed to a single 256-bit trie keyed on event_id, the
constant would be tree-depth-256 instead of tree-depth-57 + log(N):

  * Per retirement: ~256 sibling internals × 400 B ≈ **130 KB**
  * Plus ~256 tombstones × 128 B ≈ **33 KB**
  * Total ≈ **160 KB per retirement**, vs the 2-axis tree's ~30 KB.

The time axis is **paying for itself** in per-retirement cover-state
reduction (~5× cheaper), independently of whether mutable or fixed
TTLs are in play. Whole-minute retirement (one tombstone per minute
instead of per leaf) is an *additional* optimization that fixed-TTL
workspaces could claw back, but the depth-bound benefit is already
present.

So the design choice for this branch is unambiguously "keep the time
axis." Eliminating it would *increase* per-retirement cost, not
decrease it.

### Frontier rotation cost

Because every retirement wipes F, the workspace must rotate to a new
removal_frontier before authoring continues. With slice-1's
clock-driven expiry firing whenever a stamped expiry boundary is
crossed, the disappearing-messages worker can rapidly trigger
frontier rotations.

In practice retirements within a single tick under the same
already-wiped F are cheap (only the leaf row + tombstone, no walk).
The expensive part is the **first** retirement under each frontier.
Frontier rotation cadence is therefore a practical operational
concern: too frequent and the workspace pays the ~30 KB-per-rotation
cost often; too infrequent and stale debris accumulates under wiped
frontiers. The cleanup story is mostly amortized via rotation
itself — once a frontier is dead, its accumulated tombstone debris
is no longer touched by any walk.

### Future work: compact retirement event

Today the retire walk admits ~57 individual `LocalHistoryNodeSecret`
events (one per materialized sibling + descend-path internal) plus
the wipe transaction writes ~58 tombstone rows. The on-disk shape is
many small records.

A cleaner design batches the entire retirement into **one** local
event (`retirement_cover` or similar) whose canonical bytes carry
the compact representation of:

  * The full descend path being wiped (each entry: `range_start`,
    `range_width`, `bit_depth`, `event_id_prefix`, retired
    `node_id`).
  * Every sibling-side internal materialized along that path (each
    entry: same coords + the retained `node_secret`).
  * The retired leaf id.

The projector decodes the compact event and writes all rows +
tombstones in a single projection transaction. Benefits:

  * Single canonical event id for the entire retirement → auditable
    as one fact, not ~115 facts.
  * Wire size dropped from ~30 KB (separate events + their
    canonical-bytes overhead, dependency lists, signing-prefix
    headers per event) to ~8 KB (one event with packed entries).
  * Determinism still holds: both peers compute the same retirement
    walk from the same shared state, yielding byte-identical
    canonical bytes for the cover event, and therefore the same
    event id.
  * Idempotent admission: a re-admit of the same retirement event is
    a no-op via the standard duplicate-id check.

Implementation requires:

  * A new event type `local_retirement_cover` (or similar) in the
    encryption module. Local-only scope (each peer derives its own).
  * Codec encoding for the compact path/sibling/tombstone arrays.
  * Projector that walks the array and writes
    `LOCAL_HISTORY_NODE_SECRETS` rows for siblings, exact-deletes
    descend-path rows, writes
    `LOCAL_HISTORY_NODE_TOMBSTONES` rows.
  * Replacing the per-node `ensure_time_split` /
    `ensure_trie_split` admissions in
    `retire_deleted_event_leaf` with a single compute-then-admit
    step.

This is a substantial restructure of `src/workers/encryption.rs`
(which is ~950 lines today, much of it the per-node walk
machinery). It deserves its own slice. Documented here so the
refactor target is clear; not implemented in the
disappearing-messages branch.

### Latest-setting trust gap (recap)

Authors pick which admitted setting to reference. A malicious peer can
reference an *older more-permissive* setting to extend their messages'
effective TTL. Honest authors always reference the latest. Closing the
gap requires committing to a specific epoch (time-based, logical
order, or counter-based — see §6). Out of scope.

## Chosen Direction: Option 5 (Monotonic Floor + Per-Message TTL with FS)

> **CORRECTION TO EARLIER FRAMING IN THIS DOC.** Below this section,
> earlier prose treated "decoupled from rotation" as forcing
> best-effort (no-FS) deletion. That was based on conflating two
> concepts: **rotation** (creating a fresh root key F + re-wrapping
> to all N recipients — expensive) versus **F-wipe** (the retire
> walk's wipe of F's row + materialization of sibling cover —
> local, deterministic, no wraps).
>
> **Rotation is the expensive thing we are avoiding. F-wipe is the
> FS mechanism we are keeping.** After F-wipe, sibling internals
> serve as the new effective roots for their subtrees. Each peer
> derived those siblings locally during the walk via the
> deterministic KDF — no new key wraps to recipients are required.
> A correctly-implemented `closest_retained_ancestor` falls back to
> the deepest covering sibling when F is wiped, and authoring of
> new messages continues from that sibling.
>
> So option 5 = per-message TTL **with full crypto-FS** + monotonic
> floor + per-leaf retirement (no whole-minute coalescing) + cover
> horizon (see below). The "best-effort / give up FS" framing in
> the rest of this section is wrong and will be rewritten.

After mapping six coherent design options for slice 5, we are landing on
**option 5: a monotonically-advancing workspace deletion floor combined
with the existing per-message TTL stamping, full F-wipe FS per
retirement, and a sync-delay cover horizon that bounds long-run
storage**. The decision is driven explicitly by:

  1. **Decoupled from key rotation in the user's sense (no fresh
     root key, no re-wrapping to N recipients).** F-wipe and
     sibling cover are the FS mechanism; new authoring continues
     under the materialized siblings. No `removal_frontier` change
     is forced by any disappearing-messages event.
  2. **What users actually wanted** (per product research). Users
     want a monotonic, all-history-respecting floor — when the
     admin tightens the policy, messages older than the new floor
     are gone everywhere within sync latency.

### UI prompt on tightening

Tightening is the only operation that destroys past content. The admin
console must present the consequence explicitly before the change is
authored:

> **You are about to change to a shorter disappearing messages limit.**
> Messages older than 18 months will be deleted now as users' apps
> become aware of this change. This will delete all messages older
> than 18 months and cannot be undone.

(The "18 months" example assumes the new floor is `now − 18 months`;
the prompt fills in the actual floor based on the new setting.) On
loosening, no prompt is required — past messages are unaffected and
new messages get the longer TTL going forward.

### The rotation/FS/determinism trilemma

Forward secrecy for an individual retired leaf requires *some* secret
on the F→leaf derivation path to be irrecoverable. With the current
deterministic-from-parent KDF, this means **at least one ancestor
must be wiped**. The choices are:

  * **Wipe F (current slice 1–4 model).** Forward secrecy holds. But
    F is the workspace's authoring root — wiping it forces a frontier
    rotation. **Rejected** by the no-rotation constraint above.
  * **Wipe a strict ancestor of F.** Not possible: F *is* the root;
    nothing above it is on the deterministic chain.
  * **Wipe only intermediate nodes between F and the leaf, keep F.**
    Useless: F's KDF is deterministic, so the wiped intermediates can
    be recomputed from F. No FS gain. Confirmed by reading
    `derive_event_leaf` at `src/workers/encryption.rs:599` — the
    closest retained ancestor walk descends from any retained
    ancestor whose range covers the target coord, and F covers
    everything.

Conclusion: **without rotation, deterministic-KDF-tree FS for the
retired leaf is not available**. We do not get cryptographic forward
secrecy on the disappeared message under this constraint. We get
**best-effort deletion**: the row is exact-deleted, the canonical
bytes are purged, peers converge on the deletion within sync latency,
and any peer that had not yet snapshotted the plaintext loses it.
This is the same regime that Signal/WhatsApp disappearing messages
operate in (best-effort device-side deletion; not crypto-FS), and it
matches the product expectation per the research above.

If true crypto-FS is later required for a higher-tier policy, the
escape hatch is option 6 (TTL as frontier property + scheduled
rotation), which is explicitly *not* what we are landing here.

### Cost of key cover per deletion (option 5, no-rotation)

Because we cannot get FS for the retired leaf without wiping F, the
retire walk that materializes sibling cover **does not exist** in this
model. There is nothing to "preserve" — F still covers everything via
KDF. The cost shape splits into two regimes:

There are two distinct retirement events, with very different cost
shapes. The chop happens on **every** setting admit (cheap GC of
debris below the floor); the per-message tombstone happens once per
disappearance and is the dominant ongoing cost.

#### Every setting admit: chop + GC

The signed `disappearing_messages_setting` event carries
`expires_at_or_before_minute` (the floor). At admit time, the client
computes the floor as

```
new_floor = max(previous_floor, current_minute - new_ttl_minutes)
```

This is monotonic non-decreasing by construction. Crucially, the
floor advances on **every** setting admit (because elapsed time
since the previous admit is non-zero), regardless of whether the
admin tightened or loosened the TTL. So every setting admit gets a
chop for `[previous_floor, new_floor)` — a prefix-range deletion in
the time tree (root width `2^57`):

  * **At most ~57 "fully-left subtree" tombstones**, one per bit of
    `new_floor` where the boundary places an entire subtree inside
    the chop range. Each tombstone covers an entire subtree in one
    row.
  * **At most ~57 boundary descend-path tombstones** for the
    `root → new_floor` walk where the boundary cuts the subtree.

~128 B raw per tombstone → **~14 KB per setting admit, constant in
the number of messages chopped**.

The directional UX semantics fall out for free:

  * **Tightening** (smaller `new_ttl`): the floor advances
    aggressively because `current - new_ttl` is close to `now`.
    Many live messages may be swept. Admin UI fires the deletion
    warning prompt.
  * **Loosening** (larger `new_ttl`): the floor still advances by
    roughly `(time_since_previous_admit)` worth, but in this case
    every message it crosses has *already* been disposed of by its
    own per-message TTL stamp (since the previous TTL was strict).
    No live content is deleted; the chop is pure GC of accumulated
    tombstone debris. No prompt needed.
  * **Re-issue at same TTL** (admin "compact" action): identical to
    loosening — floor advances by elapsed time, sweeps debris, no
    live content touched.

The "compact" action is the operational escape hatch for workspaces
that rarely change their disappearing-messages policy: re-issuing
the current setting is free GC and can be wired into a "compact
workspace" admin action or scheduled monthly.

Determinism: the chop is a pure function of `(previous_floor,
new_floor, TIME_TREE_ROOT_WIDTH)`. Both peers compute byte-identical
tombstone rows from byte-identical inputs.

#### Per-message TTL retirement (the dominant ongoing cost)

After (and between) any chops, every message disappears on its own
stamped `expires_at_minute`. **These cannot be coalesced into a coarse
range tombstone**, because messages in the same minute can carry
different stamped TTLs.

> **Note on sibling-key cost.** A reasonable question is: doesn't every
> per-message retirement create a giant set of sibling keys (~30 KB
> from the F-wipe walk)? In the slice 1–4 (F-wipe) implementation,
> yes — each retirement materializes the time-tree + trie sibling
> chain. **Option 5 explicitly skips that walk** because it does not
> attempt crypto-FS for the disappeared leaf; F is retained, F still
> derives every other live message via KDF, so no sibling cover needs
> to be persisted. The ~30 KB per-retirement debris that the F-wipe
> model produces is the very cost option 5 is designed to avoid. The
> cost numbers below are for option 5, not the F-wipe model.

Mixed-TTL example:

  * A message authored under a strict TTL (say, 1 day) stamps
    `expires_at_minute = authored_minute + 1440`.
  * A message authored under a permissive TTL (say, 7 days) stamps
    `expires_at_minute = authored_minute + 10080`.
  * Both can occur in the same minute if a setting change happened
    mid-minute, or even just under a permissive policy where some
    authors choose tighter per-author defaults.

Coalescing all of minute M's leaves into one minute-node tombstone
would require all messages in M to share a TTL, which is not
guaranteed under monotonic-floor + per-message-stamping.

Per per-message retirement:

| Component | Bytes |
|---|---|
| `LOCAL_HISTORY_NODE_TOMBSTONES` row for the leaf | ~128 |
| `MESSAGE_TOMBSTONES` row | ~128 |
| `MESSAGES` + `SEALED_MESSAGES` row deletes | reclaims storage |
| Canonical bytes purge | reclaims storage |
| **Net cover overhead per disappearance** | **~256 B** |

Plus ~128 B per cascaded reaction/file/file_slice leaf tombstone.

These accumulate at the message-disappearance rate. A workspace with
1000 disappearances/day produces ~256 KB/day of tombstone debris;
over a year, ~93 MB. **This is the dominant ongoing cost of
disappearing messages in option 5.**

Determinism: the leaf coord is a deterministic function of the
message's canonical bytes (`workspace_id`, `author_user_id`,
`removal_frontier_id`, `created_at_ms`). All peers tombstone the same
coord with byte-identical tombstone rows; clock skew may stagger the
firing time but cannot change the result.

#### Bulk GC happens only at tightening, and only for already-debris

When a tightening chop fires, its coarse subtree tombstones subsume
any pre-existing per-message tombstones whose coords fall within the
chopped range. The chop projector can exact-delete those subsumed
rows; their convergence purpose is now served by the coarser
tombstone. **This is a one-shot reclaim at chop time; it does not
prevent future accumulation.**

Going forward, debris above the floor accumulates linearly. Only
*another* tightening can sweep it. Without periodic tightening, the
tombstone table grows unbounded at the message rate.

Operational implication: the implementation should make periodic
re-tightening (or an admin-initiated "compact" action that re-issues
the current floor) cheap and obvious in the UI, since this is the
only mechanism that bounds tombstone storage.

#### Comparison

Compare to the F-wipe model documented in earlier sections: ~30 KB
walk per first-retirement-under-frontier and forced rotation. The
no-rotation model is ~two orders of magnitude cheaper *per
retirement* at the cost of (a) dropping crypto-FS for the disappeared
message and (b) accepting unbounded tombstone accumulation between
tightening events.

#### Hypothetical: cost if we *did* walk to full depth

The earlier user question — "what if we walk all the way down the path
for each delete to a depth where birthday collision is very
improbable" — assumes the F-wipe regime. Reproduced here for the
record because the numbers are useful for sizing:

For a target trie depth `D` chosen so that the probability of two
event ids sharing a `D`-bit prefix is below ~2⁻⁴⁰ across the workspace
lifetime (`P ≈ N² / 2^(D+1)` for `N` events), reasonable choices are:

| `N` lifetime events | Required `D` | Per-retirement cost (with time-tree, F-wipe regime) |
|---|---|---|
| 10⁶ (≈ 2²⁰) | 80 | ~72 KB |
| 10⁹ (≈ 2³⁰) | 110 | ~88 KB |
| any (paranoid) | 128 | **~97 KB** |
| any (full BLAKE3) | 256 | ~155 KB |

Breakdown at `D = 128` (time tree depth 57 + trie depth 128):

  * Retained sibling internals: `(57 + 128) × ~400 B = ~74 KB`
  * Descend-path tombstones: `(57 + 128 + 2) × ~128 B = ~24 KB`

Per-row sizes used: `LOCAL_HISTORY_NODE_SECRETS` row (178 B) + the
admitted `LocalHistoryNodeSecret` event canonical bytes (~217 B) ≈
400 B per retained sibling; `LOCAL_HISTORY_NODE_TOMBSTONES` row 128 B.

These numbers are not the chosen design — they are the cost we'd pay
if we kept F-wipe and chased birthday safety via depth. Option 5
discards the walk entirely, so neither the depth nor the sibling
materialization is incurred.

### Setting-change work shape

A setting change admits a new `disappearing_messages_setting`. Its
shape depends on whether the new setting tightens or loosens:

**Tightening** (new floor `> latest floor`):

  1. Admit the setting event.
  2. Apply the prefix-range deletion `[0, new_floor)` against the
     time tree: ≤57 fully-left subtree tombstones + ≤57 boundary
     descend-path tombstones (~14 KB constant time-tree work).
  3. GC-delete any per-message tombstone rows whose coords fall
     under one of the new subtree tombstones (subsumed by the
     coarser tombstone).
  4. Exact-delete `MESSAGES`, `SEALED_MESSAGES`, `MESSAGE_TOMBSTONES`
     rows for messages with `created_at_ms / UNIX_MINUTE_MS <
     new_floor`, and purge their canonical bytes.

**Loosening** (new floor `=` latest floor; only the per-message TTL
authoring policy changes):

  1. Admit the setting event.
  2. Done. No chop, no retirement.

The per-message TTL stamping at *authoring time* keys off "the latest
admitted setting at the moment of authoring", so a loosening setting
takes effect for new messages immediately. Messages already authored
under a stricter prior setting keep their stricter stamped
`expires_at_minute` and continue to disappear on schedule via the
ordinary per-message expiry worker.

Cost scaling:

  * Tightening: **one-time ~14 KB** time-tree work, plus
    linear-in-locally-stored-subsumed-rows GC reclaim.
  * Loosening: **zero** retirement work.
  * Ongoing per-message TTL expiry (always running, in both regimes):
    per-leaf retirement walk (~1–22 KB cover depending on tree
    proximity to existing siblings; see "Cover horizon" below for
    the long-run bound).

### Cover horizon: GC sibling cover after the sync-delay horizon

Per-message retirements maintain sibling cover so future messages in
not-yet-seen minutes can still be derived. But "future messages in
old minutes" only matters during the **sync-delay horizon** — the
maximum plausible time a peer is offline before delivering messages
it authored. After that horizon no new authentic messages will
arrive in those old minutes, and the sibling cover for those
minutes is dead weight on disk.

The two-phase lifetime per time range:

  1. **Active window** (`[now − sync_horizon, now]`). Sibling cover
     is maintained. Per-leaf retirements walk from the closest
     covering sibling to the leaf, materializing siblings along
     the way. Stragglers can still deliver messages in this window
     and have their leaves derived. FS for retired messages comes
     from F-wipe + sibling cover, exactly as in slices 1–4.
  2. **Sealed** (older than `now − sync_horizon`). Sibling cover
     for the range is exact-deleted. A coarse "sealed range"
     tombstone replaces it (the same shape as a monotonic-floor
     chop: ≤57 subtree tombstones + ≤57 boundary descend
     tombstones, ~14 KB constant per sealing). No new messages are
     admittable in this range — a peer attempting to deliver one
     finds no covering ancestor and rejects the admit. Already-
     admitted messages stay on disk; their leaf rows hold the
     secret directly so cover removal does not affect decryption.
     FS for past retirements is preserved by the wiped descend
     path and the now-removed cover.

Determinism: the horizon is part of the workspace setting (or a
fixed protocol constant). All peers compute byte-identical sealing
boundaries from `(now, sync_horizon)`.

#### Storage in steady state

With cover horizon, per-peer storage is bounded by **active-window
activity**, not by lifetime retirement count:

```
working_set ≈
    active_window_retirements × ~5 KB     // sibling cover within horizon
  + alive_messages × ~400 B               // leaf rows for live messages
  + sealed_ranges × ~14 KB                // sealing tombstones
  + retired_messages × ~150 B             // message-tombstone markers
```

Worked example: workspace at 100 retirements/day, 30-day horizon,
~5 K alive messages, running for a year:

  * Active-window cover: 3 000 retirements × 5 KB ≈ **15 MB**
  * Live leaf rows: 5 000 × 400 B ≈ **2 MB**
  * 12 sealings (one per month): 12 × 14 KB ≈ **170 KB**
  * Tombstones for retired-but-still-tracked messages:
    36 500/year × 150 B ≈ **5.5 MB/year** (themselves swept by
    sealings on a longer timescale)

Per-peer steady-state working set: **tens of MB**, stable as
old ranges seal and new ones enter the active window. Without the
horizon, the same workload monotonically grows into hundreds of
MB to GBs (per the table earlier in this doc).

#### Trade-off

A peer offline longer than the sync horizon cannot deliver
messages it authored before the horizon — on receivers' machines,
the cover is gone and the leaf is non-derivable. For chat-style
products this is acceptable (~30-day offline tolerance is plenty)
and the upper bound is part of the design rather than an
accidental property.

### What slice 5 needs to ship

  1. Extend `disappearing_messages_setting` canonical bytes with an
     `expires_at_or_before_minute: u64` floor field, monotonically
     non-decreasing across successive admitted settings.
  2. Projector enforces monotonicity: a setting with a smaller floor
     than the workspace's current latest floor is rejected at admit
     time.
  3. Worker fans out per-message retirements for all messages whose
     `created_at_ms / UNIX_MINUTE_MS < floor`, regardless of their
     stamped `expires_at_minute`. The floor wins.
  4. Per-message `expires_at_minute` continues to drive the time-based
     expiry path (slice 1 behavior); the floor only adds a second
     trigger.
  5. CLI test: tightening the floor deletes pre-floor messages on both
     peers; loosening does not resurrect.
  6. Keep the F-wipe walk and sibling-cover materialization. The
     existing `RetireDeletedEventLeaf` primitive is the FS mechanism
     for option 5 — there is no "best-effort" fallback variant.
  7. Fix `closest_retained_ancestor` (`src/workers/encryption.rs:534`)
     to fall back to the deepest covering sibling when F is wiped
     instead of erroring at `root_source(...)?`. This is a slice-1
     follow-up that is a *prerequisite* for slice 5 — without it the
     workspace wedges on the first retirement.
  8. Add a `cover_horizon_minutes` field to the workspace setting (or
     a protocol constant) and a periodic worker that seals time-tree
     subtrees fully behind `now − cover_horizon_minutes`. Sealing
     reuses the same chop primitive as the monotonic-floor tightening
     path; the only difference is what triggers it (clock advance vs
     setting admit).
  9. CLI test: a peer offline for longer than `cover_horizon_minutes`
     cannot deliver pre-horizon messages — receivers reject the
     admit cleanly with a "no covering ancestor" error.

### What this gives up

  * **No cryptographic forward secrecy on the disappeared leaf.** A
    peer who snapshotted the encrypted bytes plus the workspace's
    F secret before the deletion can still decrypt the message. We
    rely on the deletion fact propagating before snapshots are taken
    by attackers.
  * **No per-frontier debris bound from F-wipe.** The frontier stays
    alive as long as the admin wants; tombstones accumulate under it
    until an explicit rotation is triggered for other reasons (key
    compromise, recipient turnover, etc.).

Both of these are acceptable per the product research: users
prioritized "the message is gone everywhere on schedule" over "an
attacker who already has my workspace key cannot decrypt the
already-snapshotted ciphertext".

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

## 6. Convergence, Per-Message Setting Reference, And The Trust Model

### Convergence comes from per-message stamping, not from a global
deletion summary

Each message commits to its own `expires_at_minute` in canonical bytes.
Two peers admitting the same byte sequence reach the same retirement
decision once their local clocks cross the stamped boundary. There is
no need for a shared "history of deletions" hash: every peer derives
identical retirement behavior from the byte-equal admitted set.

This is the load-bearing convergence claim. An earlier draft of this
section described an `Hset` deletion-summary commitment over
`(deleted_set, retained_cover, expired_minute_set)`. That commitment is
not necessary for convergence — it summarizes a state that is already
implied by canonical-bytes equality. It is preserved at the bottom of
this section as a future-work option for cross-peer audit / reporting,
but it is not part of the slice that ships.

### Per-message setting reference

`MessageEvent` carries `disappearing_setting_id: EventId` in canonical
bytes. The reference is one of:

  * The event id of a signed `disappearing_messages_setting` event for
    the workspace, when one has been admitted at authoring time. The
    author records *which setting they honored*.
  * The workspace event id, as the slice-1 fallback when no setting has
    been authored yet. The workspace event itself carries
    `disappearing_ttl_minutes` for this purpose.

The reference is added to the message's dependencies, so the projector
loads it through normal context. The projector enforces:

  * The reference is either the workspace event for that workspace, or
    a signed `disappearing_messages_setting` for that workspace; any
    other dep type is rejected.
  * `expires_at_minute` matches what the referenced setting permits:
    - If `permitted_ttl == 0` → `expires_at_minute == EXPIRES_NEVER`
    - Else → `expires_at_minute == authored_minute + permitted_ttl`
      where `authored_minute = floor(created_at_ms / 60_000)`
  * Mismatches are rejected at projection.

This eliminates the trust gap of the prior draft, where authors could
stamp arbitrary expiry. An author can now only stamp an expiry that
*some* admin-authored setting (or the workspace creation TTL) explicitly
permits.

### Trust model and known gap: latest-setting enforcement

A peer can still pick any setting it wants as the reference, including
an *older* setting whose `ttl_minutes` is larger than the latest. The
projector accepts any reference that is *some* admitted setting, not
specifically the *latest*. This is intentional for the slice that
ships: closing the gap requires an answer to the epoch question.

Concretely, a malicious peer can extend the effective TTL of its own
messages by referencing a stale setting. They cannot stamp arbitrary
expiry, but they can pick the maximum TTL ever set for the workspace.
Honest peers honor the stamped expiry as canonical fact, and
disappearance still happens; it just happens at the older setting's
boundary instead of the latest.

### Future work: closing the latest-setting gap with epochs

Three options for upgrading from "best effort" to "strict enforcement"
of the latest setting:

  * **Time-based** (simplest): the projector enumerates admitted
    settings for the workspace and rejects a message whose referenced
    setting was already superseded by a strictly newer setting at
    `message.created_at_ms`. Trusts admin clocks within a clock-skew
    bound.
  * **Logical order**: each setting carries a sequence number signed by
    the admin, or chains a dep on the prior setting. Eliminates clock
    trust but requires admins to coordinate.
  * **Counter-based**: a per-workspace monotonic counter, e.g. derived
    from a hash chain over admitted settings. Self-converging without
    clock trust.

All three are out of scope for this slice. The per-message reference
field gives us the hook for any of them later.

### Future work: optional `Hset` deletion summary commitment

The earlier draft of this section proposed:

```text
history_summary_id = Hset(
    "history-delete-summary v1",
    deleted_set,           // sorted by (unix_minute, event_id)
    retained_cover,        // sorted by canonical node prefix
    expired_minute_set,    // sorted by unix_minute
)
```

with a domain-separated BLAKE3 over the canonical sorted concatenation.
Useful as an audit primitive — it lets an external observer see two
peers agree on the entire deletion-and-expiry path that produced the
current cover, not just on the cover itself. Not required for
convergence (convergence is implied by canonical-bytes equality of
admitted messages), so deferred.

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

### Slice 5: monotonic floor + rotation decoupling (option 5, chosen)

See "Chosen Direction: Option 5" above for the full design rationale,
the rotation/FS/determinism trilemma, and the cost analysis. The
shipping work for this slice is:

16. Add `expires_at_or_before_minute: u64` floor field to
    `disappearing_messages_setting` canonical bytes. Projector
    enforces monotonic non-decreasing across successive settings
    (tightenings advance the floor; loosenings keep it equal).
17. Add a `RetireDeletedEventLeafBestEffort` primitive (or a flag on
    the existing one) that writes only the leaf tombstone +
    read-model deletes + canonical bytes purge — *no F-wipe, no
    sibling materialization walk*. This is the per-message
    disappearing-messages retirement path used by the ongoing
    expiry worker.
18. Add a `ChopTimeTreePrefix(floor_minute)` primitive that performs
    the prefix-range deletion `[0, floor_minute)` against the time
    tree: writes ≤57 subtree tombstones + ≤57 boundary descend
    tombstones, deterministically derived from `(floor_minute,
    TIME_TREE_ROOT_WIDTH)`. This fires *only on tightening setting
    changes* (when the floor strictly advances). Loosenings do not
    invoke the chop.
19. Setting projector, on a tightening change, calls
    `ChopTimeTreePrefix(new_floor)` and then GC-deletes any
    pre-existing per-message tombstone rows whose coords fall under
    a new subtree tombstone (subsumed). On a loosening change, the
    projector only persists the new setting; nothing else fires.
20. The ongoing expiry worker (slice 1's
    `disappearing_minute_expiry`) fans out per-message best-effort
    retirements for messages whose stamped `expires_at_minute` has
    been crossed by the clock — regardless of whether the message is
    above or below the floor (it usually is above; the chop already
    cleared everything below). The F-wipe walk is swapped out for
    the best-effort primitive from step 17.
19. Admin UI prompt on tightening:
    > You are about to change to a shorter disappearing messages
    > limit. Messages older than {floor_age} will be deleted now as
    > users' apps become aware of this change. This will delete all
    > messages older than {floor_age} and cannot be undone.
20. CLI tests:
    * Tightening the floor deletes pre-floor messages on both peers.
    * Loosening does not resurrect deleted messages and does not
      retroactively extend live messages' stamped TTLs.
    * Setting events with a floor below the current latest floor are
      rejected at admit time.
21. Test interaction with `removal_frontier` rotation initiated for
    *other* reasons (recipient turnover, key compromise): old-frontier
    leaf tombstones survive the rotation as best-effort cleanup
    artifacts; new-frontier authoring is uninterrupted.
22. Test invite-time history grant: a newly invited endpoint never
    receives canonical bytes for messages already past the floor, even
    if their stamped `expires_at_minute` had not yet been crossed.

After slice 5, disappearing messages are decoupled from rotation:
admins can change the policy freely, the clock-driven and floor-driven
expiry workers do their work without forcing a frontier change, and
rotation cadence is governed solely by recipient/key-compromise
concerns (its actual scaling cost driver). The trade-off — best-effort
deletion rather than crypto-FS for the disappeared leaf — is accepted
per the product research documented above.

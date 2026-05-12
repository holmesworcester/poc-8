# Encryption and Disappearing Messages

This document describes how the current poc-8 codebase encrypts content
events and disappears them on schedule. It is not a roadmap; every section
references code that exists today.

## Overview

Every workspace has a `removal_frontier` event. The frontier identifies one
content-derivation context whose root is the workspace's `local_key_secret`
(F). Per-event content (`message`, `reaction`, `file`, `file_slice`) derives
its own per-event leaf via a deterministic BLAKE3-keyed-hash KDF chain
`F → minute_node → trie → leaf`, with the leaf coord
`(unix_minute, event_id_in_minute)` recoverable from the event's canonical
identifying fields. Disappearing messages stamp a per-message
`expires_at_minute` into canonical bytes at authoring time and expire via
the `disappearing_minute_expiry` worker. Admin-driven tightenings advance
a workspace-wide monotonic floor; the `disappearing_floor_dispatcher`
worker chops the time-tree prefix below that floor. A 30-day cover
horizon (`COVER_HORIZON_MINUTES`) seals subtrees outside the active sync
window and bounds steady-state storage.

## Event vocabulary

| Event type | Description | Module |
|---|---|---|
| `encryption::local_key_secret` | F per `(workspace_id, removal_frontier_id)`; local-only; the root secret for the content-derivation tree. | `src/protocol/event_modules/encryption/local_key_secret/` |
| `encryption::local_history_node_secret` | Sibling and descend-path node secrets along the F → leaf chain; local-only; materialized opportunistically by retire/chop walks and per-event leaf derivation. | `src/protocol/event_modules/encryption/local_history_node_secret/` |
| `encryption::removal_frontier` | Shared admin-signed event naming F's derivation context. Its event id is the `removal_frontier_id` named by everything below. | `src/protocol/event_modules/encryption/removal_frontier/` |
| `encryption::recipient_key` | Shared per-endpoint X25519 public encryption key for a workspace. | `src/protocol/event_modules/encryption/recipient_key/` |
| `encryption::recipient_key_tombstone` | Shared signed supersession fact; exact-deletes a retired recipient key row. | `src/protocol/event_modules/encryption/recipient_key_tombstone/` |
| `encryption::local_recipient_key` | Local-only X25519 private key paired to a `recipient_key`. | `src/protocol/event_modules/encryption/local_recipient_key/` |
| `encryption::key_wrap` | Shared event carrying F wrapped to one `recipient_key` under XChaCha20-Poly1305. | `src/protocol/event_modules/encryption/key_wrap/` |
| `encryption::disappearing_messages_setting` | Shared admin-signed event setting `ttl_minutes` and the monotonic deletion floor `expires_at_or_before_minute`; chained via `previous_setting_id`. | `src/protocol/event_modules/encryption/disappearing_messages_setting/` |
| `content::message` | Shared encrypted message event; stamps `expires_at_minute` and `disappearing_setting_id` in canonical bytes. | `src/protocol/event_modules/content/message/` |
| `content::reaction` | Shared encrypted reaction event; inherits the parent message's expiry. | `src/protocol/event_modules/content/reaction/` |
| `content::file` / `content::file_slice` | Shared encrypted file descriptor and chunked payload. | `src/protocol/event_modules/content/file/`, `.../file_slice/` |
| `content::message_deletion` / `content::file_deletion` | Author-signed deletion facts. | `src/protocol/event_modules/content/message_deletion/`, `.../file_deletion/` |

## Key derivation

- F (`local_key_secret`) is decoded from a `key_wrap` payload by
  `derive_key_secrets` in `src/workers/encryption.rs` (using
  `crypto::x25519_xchacha20poly1305_decrypt`), then admitted as a
  deterministic local event through the common pipeline. The fast path that
  derives a leaf directly from F is in
  `local_history_node_secret::commands::derive_event_leaf_from_root`, which
  walks `(0, ROOT_TIME_TREE_WIDTH) → … → (unix_minute, 1)` on the time
  axis, then takes one trie split to depth 256. The KDF is
  `crypto::blake3_keyed_hash` with domain tags `TIME_SPLIT_DOMAIN`
  (`b"topo time split v1"`) and `TRIE_SPLIT_DOMAIN`
  (`b"topo trie split v1"`).
- `core::crypto::hkdf_sha256_key` exists for purpose-keyed key derivation
  but the leaf chain is BLAKE3-keyed; HKDF-SHA256 is the helper available
  for non-leaf purposes (e.g. wrap-secret derivation in `x25519_*`).
- Time tree root width: `TIME_TREE_ROOT_WIDTH = 1u64 << 63` (see
  `src/workers/encryption.rs:90`). The implicit root covers
  `(range_start=0, range_width=TIME_TREE_ROOT_WIDTH)` at
  `TIME_TREE_BIT_DEPTH = 0`. Depth is log₂(width) ≈ 63 levels above
  `range_width=1` (the minute_node).
- Within-minute trie: 256-bit BLAKE3 event_id_in_minute coord. Leaves sit at
  `TRIE_LEAF_BIT_DEPTH = 256` (see
  `src/protocol/event_modules/encryption/local_history_node_secret/types.rs`).
- Per-event leaf coord = `(unix_minute, event_id_in_minute)`. `unix_minute`
  is `created_at_ms / UNIX_MINUTE_MS` (UNIX_MINUTE_MS = 60_000);
  `event_id_in_minute` is a BLAKE3-keyed-hash of `(workspace_id,
  author_user_id, removal_frontier_id, created_at_ms)` (see
  `message::types::message_event_id_in_minute` and the parallel
  `reaction::types::reaction_event_id_in_minute`). Both peers can recover
  the coord from canonical identifying fields alone, before AEAD opening.
- `closest_retained_ancestor` (`src/workers/encryption.rs:628`) finds the
  deepest local row whose `(range_start, range_width, bit_depth,
  event_id_prefix)` covers the target coord, falling back from F to the
  deepest covering sibling row when F's row has been wiped.
- `derive_event_leaf` (`src/workers/encryption.rs:709`) walks down from
  that ancestor to the leaf, materializing only the leaf row in the common
  fresh-encryption path.

## Per-event leaf retirement (FS mechanism)

`Work::RetireDeletedEventLeaf` in `src/workers/encryption.rs:1301`
(`retire_deleted_event_leaf`) walks the F → leaf path. At each time-split
and trie-split level it admits both the descend-side child (to keep the
chain valid for the source-dependency invariant) and the sibling child as
local `local_history_node_secret` events. In a single transaction it then
exact-deletes the entire descend chain — F's row plus every descend-side
internal — calls `purging::purge_event_storage_in_tx` to drop their
canonical bytes, writes one `LOCAL_HISTORY_NODE_TOMBSTONES` row per wiped
internal, and finally exact-deletes the leaf row, purges its bytes, and
tombstones it.

After F-wipe, `closest_retained_ancestor` falls back to the deepest
covering sibling row admitted during the walk; future authoring in any
minute except the wiped one is uninterrupted because the time-axis
siblings collectively cover every minute. Coords whose subtree was
inside the wiped descend chain wedge legitimately (the
`closest_retained_ancestor` "no covering ancestor" error). No new key
wraps to recipients are required — every peer's KDF is deterministic,
so each peer derives the same sibling secrets locally.

Per-retirement cost scales with tree-structural depth (~63 time-axis
levels + log₂(messages_in_minute) trie levels): ~5 KB in active workspaces
where clustered authoring shares most of the path, up to ~22 KB worst-case
under sparse retirements (see the `sparse_delete_materializes_log_n_internals_not_n_leaves`
and `cover_summary_after_sparse_delete_is_logarithmic` tests in
`src/workers/encryption.rs`).

## Disappearing messages

- Each `MessageEvent` stamps `expires_at_minute = authored_minute +
  ttl_minutes` in canonical bytes at authoring time (where
  `ttl_minutes` is read from the active `disappearing_messages_setting`
  for the workspace, or the workspace event's
  `disappearing_ttl_minutes` fallback). The codec
  (`message::codec::validate_expires_at_minute`) rejects any stamp earlier
  than `authored_minute`. `EXPIRES_NEVER = u64::MAX` is the sentinel for
  "no expiry".
- Active setting: the latest admitted `disappearing_messages_setting` for
  a workspace, looked up by
  `disappearing_messages_setting::queries::active_for_workspace`. Setting
  events chain via `previous_setting_id`, and the projector
  (`disappearing_messages_setting::projector::validate_monotonic_floor`)
  rejects a setting whose `expires_at_or_before_minute` is smaller than
  the predecessor's.
- Monotonic floor (`expires_at_or_before_minute`): a workspace-wide minute
  below which all messages are gone regardless of per-message stamp. It is
  non-decreasing across admitted settings by projector enforcement.
- `disappearing_minute_expiry` worker
  (`src/workers/disappearing_minute_expiry.rs`): per daemon tick, scans
  every workspace's sealed messages (`message_queries::list_sealed`),
  retires every row whose `expires_at_minute < now_minute` (where
  `now_minute = logical_clock::logical_time / UNIX_MINUTE_MS`). For each
  expired message it writes a `MESSAGE_TOMBSTONES` row, exact-deletes
  the `MESSAGES` and `SEALED_MESSAGES` rows, purges canonical bytes via
  `purging::purge_event_storage_in_tx`, and calls
  `encryption_worker::run(Work::RetireDeletedEventLeaf)` for the
  message's per-event leaf. After the per-message phase it retires
  reaction leaves whose `target_message_id` is in the expired set
  (`retire_reaction_leaves_for_expired_messages`), then triggers
  `content_purge::run` to cascade read-model and canonical-bytes
  cleanup for reactions, files, and file_slices.
- `disappearing_floor_dispatcher` worker
  (`src/workers/disappearing_floor_dispatcher.rs`): per tick, computes
  `effective_floor = max(setting_floor, now_minute -
  COVER_HORIZON_MINUTES)` per workspace. If higher than the persisted
  `last_chopped_floor` (table `setting_schema::WORKSPACE_CHOP_FLOOR`), it
  invokes `encryption_worker::run(Work::ChopTimeTreePrefix {
  floor_minute: effective_floor })` and upserts the new floor. The two
  workers run in this order in `daemon_workers()`: expiry first so the
  chop subsumes any per-leaf tombstones whose minutes fall under the new
  floor.
- Why whole-minute retirement was rejected: under mutable per-message
  TTL, two messages in one minute can have different stamped expiries
  (mixed TTLs from a setting change mid-minute), and late-arriving
  messages can land in already-retired minutes. Whole-minute retirement
  would wipe live or yet-to-arrive content. Per-leaf retirement carries
  per-leaf cost for eventual-consistency correctness.

## Chop primitive

`Work::ChopTimeTreePrefix { workspace_id, removal_frontier_id,
floor_minute }` in `src/workers/encryption.rs:1574`
(`chop_time_tree_prefix`) performs prefix-range deletion `[0,
floor_minute)` on the time tree:

- Walks the boundary descend path from F (or, when F is wiped, from the
  deepest sibling row whose range covers `floor_minute`).
- At each level: if the floor lives in the right half, the entire left
  subtree is `< floor_minute` and gets one subtree tombstone; if the floor
  lives in the left half, the right half is fully surviving and gets a
  right-side sibling materialization so future authoring above the floor
  still has a covering ancestor.
- At most ~63 fully-left subtree tombstones (one per bit where the
  boundary places an entire subtree inside the chop range) plus at most
  ~63 boundary descend tombstones. Total ~14 KB, constant in the number
  of messages chopped.
- If F's row is alive at chop time, F is wiped along with the boundary
  chain (forward secrecy for the chopped range).
- GC: `gc_subsumed_tombstones` exact-deletes pre-existing
  `LOCAL_HISTORY_NODE_TOMBSTONES` rows (for this `removal_frontier_id`)
  and `MESSAGE_TOMBSTONES` rows whose ranges fall fully under
  `[0, floor_minute)`, since the coarse subtree tombstones now cover
  them.

## 30-day cover horizon

`COVER_HORIZON_MINUTES = 30 * 24 * 60` is defined in
`src/protocol/event_modules/encryption/disappearing_messages_setting/types.rs:25`.

The dispatcher uses it to compute `horizon_floor =
now_minute.saturating_sub(COVER_HORIZON_MINUTES)`. Per-message
retirements maintain sibling cover so future messages in not-yet-seen
minutes can still be derived, but that cover is dead weight once no
straggler can plausibly still deliver an old message. The dispatcher
seals old subtrees by chopping them past the horizon.

Steady-state effect: per-peer storage stabilizes — without the horizon,
sibling cover from per-message retirements grows monotonically.

Trade-off: a peer offline longer than `COVER_HORIZON_MINUTES` cannot
deliver messages it authored before the horizon — receivers will have
chopped the covering ancestor and the message's leaf will have no
covering ancestor, so `admit_check_received` (or the deferred derivation
in the encryption worker) will drop the event with a clean
"no covering ancestor" error.

## Negentropy purge plumbing

- `encryption.negentropy_pending_purges.v1` is a workspace-keyed table
  declared in `src/protocol/event_modules/sync/schema.rs` and named via
  the `NEGENTROPY_PENDING_PURGES` constant. Every call to
  `purge_event_storage_in_tx`
  (`src/workers/pipeline_helpers/purging.rs:37`) that drops a shared
  workspace-scoped event enqueues a row in this table inside the same
  transaction as the canonical-bytes delete.
- The drainer is folded into the sync worker:
  `drain_pending_purges_in_tick`
  (`src/workers/sync.rs:464`) runs as the first step of every sync tick,
  pulls up to `DEFAULT_PURGE_DRAIN_LIMIT` rows, calls
  `SyncIndex::remove_event` for each id (which XOR-folds the per-id
  hash out of the warm fingerprint), and then exact-deletes the queue
  rows.
- This is the cross-worker communication channel: `content_purge` (for
  author-driven deletions and cascade purges), the per-leaf retire walk
  in `retire_deleted_event_leaf`, the chop walk in
  `chop_time_tree_prefix`, and retired recipient material in
  `purge_retired_recipient_material` all enqueue purge rows through the
  same `purge_event_storage_in_tx` helper; sync drains them. The
  `daemon_workers()` order in `src/workers/mod.rs` runs the dispatcher
  (which writes purge rows during a chop) before the sync tick, so a
  single tick observes the purges from both expiry and chop in one
  fold.

## Admission contract

- Event-level dependencies are listed in `EventContext.dependencies`. The
  common pipeline records blocked/unblocked edges via tables
  `event_modules.blocked_events_by_missing_dep.v1` and
  `event_modules.missing_deps_by_blocked_event.v1` (see
  `src/protocol/event_modules/schema.rs`). Workers process newly-admitted
  events; unblocking is driven by the
  `dependency_unblock` worker (`src/workers/dependency_unblock.rs`).
- Local key state (F's row, sibling history-node rows) is not part of the
  event-dep graph. It is filled in by the encryption worker's derive /
  retire / chop walks; the `drain_pending_message_leaves` work shape
  scans blocked content events and derives their named leaves so the
  dependency unblock can proceed.
- The receive-side admit gate `admit_check_received`
  (`src/protocol/event_modules/content/mod.rs:51`, dispatching to
  per-event-type implementations like
  `message::schema::admit_check_received` at
  `src/protocol/event_modules/content/message/schema.rs:47`) runs in the
  common pipeline's `drain_canonical_in` step before storage. It drops
  re-deliveries whose id is already in `MESSAGE_TOMBSTONES`; for
  messages whose `expires_at_minute` is past the local clock it writes
  a tombstone row directly and drops the bytes
  (`AdmitDecision::WriteRowsAndDrop`). It does not consult the
  history-tree cover directly — coords with no covering ancestor wedge
  later, when `derive_event_leaf` fails inside the encryption worker.

## Decryption

After admission the message lands as a `SEALED_MESSAGES` row carrying
ciphertext, nonce, and `local_history_node_secret_id`. The encryption
worker's `Work::DrainPendingMessageLeaves`
(`src/workers/encryption.rs:2275`) opportunistically scans blocked
content events, calls `derive_event_leaf` against the closest retained
ancestor, and admits the leaf so the projector can decrypt and write
the plaintext row.

If derivation fails (no covering ancestor for the coord), the message
stays in `SEALED_MESSAGES` until cover materializes (transient
bootstrap case below) or forever (cover-horizon and tightening cases).

## Storage shape in steady state

A workspace at 100 retirements/day with the 30-day horizon and 5K alive
messages settles at:

- Active-window cover: 3000 × ~5 KB ≈ 15 MB
- Live leaf rows: 5000 × ~400 B ≈ 2 MB
- Sealed ranges (one per month): 12 × ~14 KB ≈ 170 KB
- Per-message tombstones: ~5.5 MB/year; subsumed by subsequent chops

Per-peer working set: tens of MB, stable. Without the cover horizon the
same workload would grow into hundreds of MB to GBs.

## Determinism invariants

- Per-leaf retirement coord: deterministic function of message canonical
  bytes (`workspace_id`, `author_user_id`, `removal_frontier_id`,
  `created_at_ms`) — see `message_event_id_in_minute` and
  `unix_minute_for`. Two peers retire the same coord with byte-identical
  tombstone rows; clock skew may stagger the firing tick but cannot
  change the result.
- Chop output: deterministic function of `(floor_minute,
  TIME_TREE_ROOT_WIDTH)`. Both peers compute byte-identical tombstone
  rows from byte-identical inputs (the `chop_is_deterministic` tests in
  `src/workers/encryption.rs`).
- Negentropy drainer: `SyncIndex::remove_event` XOR-fold is
  order-independent; the final fingerprint depends only on the set of
  purged ids (the `drain_pending_purges_is_deterministic_under_two_drain_orderings`
  and `drain_pending_purges_partial_subset_yields_same_summary_for_two_orderings`
  tests in `src/workers/sync.rs`).
- Two peers admitting the same canonical bytes write byte-identical
  rows; running the same retire / chop on identical state produces
  byte-identical effects.

## Three scenarios where a message arrives with no local covering ancestor

1. **Cover-horizon sealing (terminal).** Peer offline for longer than
   `COVER_HORIZON_MINUTES`; the dispatcher on receivers has chopped the
   message's range while the author was offline. On reconnect, receivers'
   `admit_check_received` admits the bytes if the stamped expiry is
   future, but `derive_event_leaf` then fails — there is no covering
   ancestor — and the message stays sealed forever on those peers. Not
   decryptable.
2. **Tightening (terminal).** Admin tightened the floor; pre-floor
   messages from peers who hadn't seen the new setting yet arrive on
   chopped peers. Same outcome as case 1.
3. **Transient bootstrap (recoverable).** A peer just joined; F is being
   derived in the background (waiting on `key_wrap` unwrap +
   `local_key_secret` admission). The message admits and lands in
   `SEALED_MESSAGES`; `derive_event_leaf` fails on the current tick.
   When F arrives, `drain_pending_message_leaves` on the next encryption
   tick derives the leaf and the projector decrypts.

## Trust model and known gaps

- Latest-setting trust gap: each `MessageEvent` references a specific
  admitted `disappearing_messages_setting` (or the workspace event id as
  the bootstrap fallback) via `disappearing_setting_id` and the
  projector validates that `expires_at_minute` matches what that
  referenced setting permits. But authors can choose *which* setting to
  reference — honest authors pick the latest, malicious authors could
  reference an older more-permissive setting to extend their messages'
  effective TTL. Closing the gap requires committing to a specific
  epoch (time-based, logical-order, or counter-based); not implemented.
- Newly-invited endpoints: no special grant for retained cover state. A
  new endpoint receives the workspace `key_wrap`, derives F, and can
  decrypt only what F still derives. Messages whose ancestor was wiped
  before the join are not recoverable.
- Forward secrecy for retired leaves is enforced against on-disk
  attackers: after F-wipe + descend-chain wipe, no retained sibling row
  derives the wiped leaf's secret (the
  `adversary_cannot_re_derive_deleted_leaf_from_unrelated_retained_rows`
  and `strict_adversary_no_retained_row_derives_deleted_leaf` tests in
  `src/workers/encryption.rs`). An attacker who snapshotted F before
  the wipe can still recompute the wiped chain — best-effort device
  deletion is the bound, the same regime Signal / WhatsApp disappearing
  messages operate in.

## Rejected designs

- **Whole-minute retirement of expired minutes.** Breaks eventual
  consistency under mutable per-message TTL: mixed TTLs within a minute,
  late-arriving messages in retired minutes. Permanently off the table.
- **Deletion-summary `Hset` commitment over `(deleted_set,
  retained_cover, expired_minute_set)`.** Redundant: per-message stamping
  monotonically fixes each message's expiry in canonical bytes, the
  monotonic floor provides the admin override, and chop output is a
  deterministic function of `(floor_minute, TIME_TREE_ROOT_WIDTH)`. A
  separate Hset summary added no convergence guarantees and was
  abandoned.
- **Per-leaf F-wipe forces frontier rotation.** False. F-wipe locally is
  fine; sibling cover serves as the effective root for surviving
  subtrees and each peer derives those siblings via the deterministic
  KDF — no new wraps to recipients required. Rotation only happens for
  recipient-revocation / key-compromise reasons, not retirement.
- **"Best-effort" retirement that skips the F-wipe walk.** Briefly
  considered for slice 5 as a way to avoid rotation. Discarded because
  F-wipe and rotation are different things: F-wipe is local + cheap +
  the FS mechanism; rotation (fresh root + re-wrap to N recipients) is
  the expensive thing being avoided. The current implementation keeps
  F-wipe.
- **Drop semantic-validation checks in codec.** Codec is strictly bytes
  ↔ struct + sign/verify. Validation belongs in
  `commands.rs` (authoring) and `projector.rs` (receive). Codec only
  validates structural well-formedness (field ranges, length checks like
  `validate_expires_at_minute` in `message::codec` for the
  authored-minute ≤ stamp invariant).

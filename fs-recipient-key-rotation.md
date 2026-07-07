# FS Recipient-Key Rotation — Design & Open Challenges (Handoff)

## Purpose of this document

This worktree (`fs-recipient-key-rotation`, branched off `master` at `175cd11`)
is a handoff. The forward-secrecy recipient-key rotation feature is **implemented
and green** on `master`, but it carries an unresolved architectural tension
around event-graph dependencies for deletion-style events. This document
captures the design as built, the three-way tension we hit, and the open
decision so the next agent can resolve it without re-deriving the context.

**What the next agent needs to decide:** whether to accept the current
"keep-the-dep, suppress-the-row" design, or push to remove the
predecessor-as-dependency edge entirely. Section "The open decision" lays out
both options. Related task #43 (audit of other deletion-style deps) is blocked
on this decision.

---

## 1. The FS rotation rule (what + why)

Canonical statements live in:
- `RULES.md` § "Forward Secrecy Requires Recipient Key Rotation On Wrap-Bound Deletion" (line ~1025)
- `encryption.md` § "Forward-secrecy scope and the recipient-key rotation requirement" (line ~128)

Condensed:

**F** is a workspace's content-derivation root. F is wrapped to each recipient
via a `key_wrap` event; each peer derives F locally by unwrapping the wrap
addressed to that peer's `recipient_key`. **F's secret value is shared across
peers; F's local storage is per-peer.** There is exactly ONE
`local_recipient_key` private half per peer per F.

Forward secrecy of a retired leaf comes from wiping `local_key_secret(F)` plus
sibling-cover. But that only works if F is also unrecoverable through every
*other* disk path. The non-trivial path: a surviving `key_wrap` encrypts F to a
recipient pubkey whose `local_recipient_key` private half can unwrap it. If both
survive a deletion, F is reconstructible and the local F-wipe is moot.

**Therefore:** any deletion that wipes F MUST also force every recipient that
received a `key_wrap` for that F to rotate their recipient keypair.

Key properties of the rule:
- **Trigger is the F-wipe itself**, not every deletion. Per-leaf retire / chop /
  frontier rotation all eventually wipe F's row. Whichever deletion is the FIRST
  under F to wipe F triggers rotation. Subsequent deletions under the
  already-wiped F do not re-rotate.
- **Per peer, per F: at most ONE rotation** in F's lifetime.
- **Cost per peer: O(1) per F** — one keypair regeneration + one signed event.
- **Network cost: O(N peers) per F** over F's lifetime — each peer rotates once
  when its own deletion path first wipes F. Eventually consistent.
- The rotation is a **single self-signed `recipient_key` event** carrying
  `previous_recipient_key_id` (the wiped pubkey's event id). It acts as BOTH the
  tombstone of the old pubkey AND the introduction of the new one. The recipient
  authored the original `recipient_key` event, so it has authority to replace it
  — no admin involvement.

---

## 2. Current implementation state (on `master`, also this branch)

Three commits, all green (`cargo test` passes, `cargo test --test
rules_boundary_test` = 90):

| Commit    | What                                                                    |
|-----------|-------------------------------------------------------------------------|
| `ed04d84` | Single `recipient_key` event with `previous_recipient_key_id`; codec encodes/decodes the field + declares the predecessor as an event-graph dependency when non-zero; projector validates predecessor (same workspace + same endpoint) and emits `TableDelete` for the old row. |
| `95aef86` | Re-delivery defense: supersession projector emits a persistent `EventLabel` on the predecessor's event id; the main `recipient_key` projection branch self-checks `event.context.labels` and skips writing the row when the label is present. |
| `175cd11` | Removed the now-unused `recipient_key_tombstone` event module (7 files); the single-event supersession design replaced it. |

`cargo test --lib` count: 459 (the tombstone module's ~8 internal tests were
removed; +1 suppression test added).

### Key files

- `src/protocol/event_modules/encryption/recipient_key/types.rs`
  - `RecipientKeyEvent.previous_recipient_key_id` field
  - `NO_PREVIOUS_RECIPIENT_KEY = [0; 32]` sentinel
  - `SUPERSEDED_LABEL_PREFIX = b"encrypt.rk.supr:"`, `superseded_label()`,
    `is_superseded_label()` (label is prefix ‖ successor id, 48 bytes)
- `src/protocol/event_modules/encryption/recipient_key/codec.rs`
  - Lines ~123–130: **declares `previous_recipient_key_id` as a dependency**
    when non-zero (`push_unique(&mut dependencies, metadata.previous_recipient_key_id)`)
  - Line ~238: test `signed_record_with_predecessor_carries_previous_recipient_key_dependency`
    asserts the dep IS added
- `src/protocol/event_modules/encryption/recipient_key/projector.rs`
  - Lines ~87–99: re-delivery suppression — reads `event.context.labels`, returns
    no rows if the event's own id carries a supersession label
  - Lines ~101–120: supersession branch — calls `validate_predecessor`, pushes a
    `TableDelete` for the old row, pushes an `EventLabel` on the predecessor's id
  - Lines ~130–165: `validate_predecessor` — looks up the predecessor via
    `event.context.dependency(previous_recipient_key_id)` and checks same
    workspace + same endpoint. **This is the consumer of the dep edge.**
- `src/workers/encryption.rs`
  - Line ~459: `rotate_local_recipient_keys_for_wiped_frontier` — the F-wipe
    trigger; called from `retire_deleted_event_leaf` (~line 999) and
    `chop_time_tree_prefix` (~line 1159) after the wipe transaction commits, when
    `frontier_root.is_some()`
  - Line ~546: `rotate_recipient_key` — generates the fresh keypair, publishes
    the supersession `recipient_key` event(s), wipes old private rows + retired
    wrap rows. **Its doc comment (lines ~538–542) still asserts the dep edge is
    load-bearing** ("The supersession dependency in (2) guarantees every peer
    admits the new recipient_key only after admitting the old one") — that
    comment must be revisited under either option below.

---

## 3. The core tension

The supersession event references its predecessor (`previous_recipient_key_id`).
Three forces pull in different directions on how that reference is modeled:

### Challenge A — declaring the predecessor as a dep "fails on replay"

The original `ed04d84` design declares `previous_recipient_key_id` as an
event-graph dependency. The stated project policy is **"no dep for deletion"**,
because the dep model fails on replay:

If a fresh peer's admit pipeline ever *drops* the predecessor (because the
predecessor is known-superseded), then the supersession event — which deps on
that predecessor — blocks forever waiting for an event that will never be
admitted. The dep edge and a drop-the-superseded-predecessor admit-gate are
mutually incompatible.

### Challenge B — drop-at-admit breaks negentropy convergence

The natural fix for re-delivery (don't let a re-delivered superseded
`recipient_key` resurrect its row) was originally specced as an **admit-gate
that drops the re-delivery**. But drop-at-admit was found to break negentropy
sync:

- The peer that admits the supersession first never admits the predecessor.
- The peer that admits the predecessor first does admit it.
- → the two peers' EVENTS state is **asymmetric** → their negentropy
  fingerprints diverge → sync never converges.
- This failed 3 `negentropy_purge_sync_test` cases.

So drop-at-admit is off the table regardless of the dep question.

### Challenge C — the resolution as built, and its residual tension

`95aef86` resolved B by **not dropping anything at admit**. Instead:
- The predecessor stays admitted on every peer (EVENTS symmetric → negentropy
  converges).
- The supersession projector emits a persistent label on the predecessor's id.
- The main `recipient_key` projection branch self-checks that label and
  **suppresses the row write** (the *projection*, not the *event*).

Because the predecessor stays admitted everywhere, the dep edge from Challenge A
is *always satisfiable* — so `95aef86` **kept the dep** (`ed04d84`'s codec
change was not reverted).

**Residual tension:** the dep edge still exists, which violates the letter of
the "no dep for deletion" policy. It is currently *safe* only because:
1. Nothing drops the predecessor at admit (Challenge B's fix guarantees this).
2. `recipient_key` canonical bytes are **not** content-purged, so
   `validate_predecessor`'s `event.context.dependency(...)` lookup always
   resolves.

If either assumption changes — e.g. a future change content-purges old
`recipient_key` bytes for storage, or a fresh peer joins after the predecessor
has been purged at its source — the dep fails on that peer and the supersession
event blocks forever. The policy exists precisely to avoid depending on those
assumptions.

---

## 4. The open decision

### Option 1 — accept the current design ("keep the dep")

Keep `95aef86` as-is. Reframe the policy from "no dep for deletion, period" to
**"no dep for deletion when an admit-gate would drop the target."** Under the
projector-suppression model the target is never dropped, so the dep is sound.

- **Pros:** already implemented, green, negentropy converges. `validate_predecessor`
  gets the predecessor's real bytes, so same-endpoint / same-workspace validation
  is straightforward and fully verified.
- **Cons:** the dep edge survives. Soundness depends on "`recipient_key` bytes are
  never purged" staying true forever. The policy becomes conditional and needs to
  be re-documented so future contributors don't reintroduce a drop-at-admit and
  silently break it. Task #43's other deletion-style deps would be judged by the
  same (softer) standard.

### Option 2 — remove the dep ("no dep, validate from the event's own bytes")

Revert the codec dep declaration (`recipient_key/codec.rs:123–130`), invert the
dep test at line ~238, and replace `validate_predecessor`'s
`event.context.dependency(...)` lookup with **self-contained validation**:

- The supersession event is already signed by the recipient's endpoint key
  (the same endpoint that signed the predecessor). The projector can verify the
  supersession's own signature against a legitimate workspace endpoint without
  touching the predecessor's bytes.
- To enforce "supersession's signer == predecessor's signer" without reading the
  predecessor, add `previous_signer_endpoint_id` (or equivalent) to the
  supersession's canonical bytes, so the check reads a field of the event itself.
- The label mechanism from `95aef86` is unchanged and still provides re-delivery
  suppression.

- **Pros:** honors the policy literally; the supersession event is
  self-validating; no soundness dependency on purge behavior; gives a clean
  template for resolving #43.
- **Cons:** non-trivial revision of `ed04d84` + `95aef86`. Requires a
  canonical-bytes field addition (another wire-schema bump for `recipient_keys`,
  which `ed04d84` already bumped `v1`→`v2`; this would be `v3` or fold into the
  same bump if not yet released). **Must re-verify the 3
  `negentropy_purge_sync_test` cases still pass** — removing the dep changes
  admission ordering and the tests that broke under drop-at-admit are the
  canary here. Same-endpoint validation now trusts a self-declared field rather
  than the predecessor's actual bytes; think through whether that weakens the
  cross-endpoint-supersession rejection (the `supersession_event_rejects_predecessor_from_different_endpoint`
  test in `projector.rs` must still hold — under Option 2 it would be checking
  the supersession's *claimed* `previous_signer_endpoint_id` against its own
  signer, not against the predecessor's real endpoint).

**Note on the security check.** Under Option 1 the cross-endpoint rejection is
airtight: it reads the predecessor's actual `endpoint_shared_id`. Under Option 2
the rejection becomes "the supersession's signer must equal the
`previous_signer_endpoint_id` it declares" — an attacker cannot forge a
supersession for a victim's key because they cannot produce the victim's
signature, but the next agent should confirm this reasoning end-to-end before
committing to Option 2.

---

## 5. Related open work — task #43

Task #43 ("Audit + remove other deletion-style event-graph deps") found two more
sites that declare deletion-style relationships as deps:

- **`src/protocol/event_modules/encryption/removal_frontier/codec.rs:149–151`** —
  each removed event id is pushed as a dependency. Removed events are typically
  messages/reactions that *do* get content-purged, so this is the clearest case
  of "dep fails on replay": a fresh peer that joins after the messages aged out
  never receives them, and the `removal_frontier` blocks forever.
- **`src/protocol/event_modules/encryption/local_history_node_secret/codec.rs:81–83`** —
  `tombstone_node_id` declared as a dep. Lower priority: `local_history_node_secret`
  is `EventScope::Local` and doesn't propagate cross-peer, so the replay risk is
  bounded to local re-projection. Still worth auditing whether re-projection
  after the predecessor's bytes are wiped fails.
- **Not a candidate:** `disappearing_messages_setting`'s `previous_setting_id` is
  a monotonicity chain pointer, not a deletion. Settings accumulate; they don't
  tombstone predecessors. Leave as-is.

#43 should be resolved *consistently* with whichever option is chosen here. If
Option 2 (remove deps), `removal_frontier` is the priority fix and the
recipient_key work is the template. If Option 1 (conditional policy), #43 needs
each site judged against "would anything drop the target at admit?" — and
`removal_frontier`'s removed-events likely fail that test because they get
purged, so `removal_frontier` probably still needs the dep removed even under
Option 1.

---

## 6. Suggested next steps for the handoff agent

1. Read this doc, then `RULES.md` §1025 and `encryption.md` §128 for the full rule.
2. Read `recipient_key/{codec,projector,types}.rs` and `workers/encryption.rs`
   around the line refs in §2.
3. Make the Option 1 vs Option 2 call (this is the decision the user wants made).
4. If Option 2: revert the codec dep, invert its test, rework `validate_predecessor`
   to be self-contained, add the canonical-bytes field if needed, and **re-run the
   `negentropy_purge_sync_test` suite explicitly** — those 3 cases are the canary.
5. Either way: fix the stale doc comment in `workers/encryption.rs` lines ~538–542,
   which currently asserts the dep edge is load-bearing for cross-peer ordering.
6. Resolve task #43 consistently with the decision.

## Verification baseline (must stay green)

- `cargo build` — clean
- `cargo test --lib` — 459 passing
- `cargo test` — all binaries pass (incl. `negentropy_purge_sync_test`)
- `cargo test --test rules_boundary_test` — 90 passing

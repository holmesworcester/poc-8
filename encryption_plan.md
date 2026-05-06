# Event-Centered Encryption Plan

This document brings forward the useful parts of
`event-centered-encryption-auth-plan` for the current poc-8 branch. It is a
roadmap, not a license to bypass the current architecture rules.

The goal is:

```text
shared auth/encryption facts + local-only secret events
  -> ordinary dependency blocking/unblocking
  -> bounded derivation of new events
  -> encrypted content availability
```

The most important correction from the older plan is that local secrets are
events. They should participate in the common event pipeline like any other
dependency. A missing local-only key event blocks projection; creating that
local event unblocks through the normal worker.

## Hard Rules

- All crypto must be real. No fake ciphers, no hash-only "encryption", no XOR,
  no placeholder sealed bytes, and no tests that prove security with identity
  transforms.
- Primitive crypto lives in `src/core/crypto.rs`. Event modules choose purpose,
  associated data, authority, dependencies, and projection semantics.
- Projectors do not emit events. Projectors return rows, exact row deletes, and
  labels only.
- The common event worker remains the dependency authority. Encryption work must
  not introduce a second blocking system.
- Local-only key events are ordinary durable local events. Shared encrypted
  events can depend on deterministic local key event ids and block until those
  local events exist.
- Derivation workers may create events, but only by calling commands and sending
  proposed events back through common admission.
- Work rows and obligation rows are scheduling aids. They are not substitutes
  for dependency edges.
- Transit wrapping is separate from content/key wrapping. `connection.wrap`
  produces opaque transit bytes and is not an event. `key_wrap` is a canonical
  shared event.

## Current Poc-8 Mapping

Use current names and ownership:

- `workspace_id`, not tenant or recorded_by.
- `endpoint_shared`, not peer_shared.
- `endpoint_id` is the transport/X25519 endpoint identity.
- `signing_public_key` is the Ed25519 event-signing key.
- Identity/auth events stay under `identity`.
- Encryption consumes identity/auth read models; it does not re-own users,
  admins, endpoint membership, workspace creation, or invites.

Expected module shape:

```text
src/protocol/event_modules/encryption/
  mod.rs
  cli.rs
  worker.rs
  recipient_key/
  recipient_key_tombstone/
  local_recipient_key/
  removal_frontier/
  local_key_secret/
  local_history_node_secret/
  key_wrap/
  key_wrap_receipt/
  encrypted_message/          # or encrypted content leaf; exact shape TBD
```

Keep leaf commands and tests local to their event modules. Domain-level
`worker.rs` owns bounded derivation that spans more than one encryption child.

## Event And Secret Vocabulary

Initial phase-one terms:

- `recipient_key`: a shared workspace-scoped public encryption key for one
  endpoint membership. It is authorized by the endpoint's signing key and names
  the `endpoint_shared_id`.
- `local_recipient_key`: a local-only private encryption key corresponding to a
  recipient key.
- `removal_frontier`: a shared workspace-scoped frontier event. The event id is
  the `removal_frontier_id`; there is no separate frontier hash or key-period
  term. A frontier is a compact boundary over removal facts, not a list of all
  previous workspace events. Its refs should be the minimal canonical set whose
  dependency closure covers the removals incorporated by the key generation.
- `local_key_secret`: local-only symmetric secret material for exactly one
  `removal_frontier_id`. Its event id is the `local_key_secret_id` named by
  wraps and later content events.
- `key_wrap`: a shared event carrying sealed key-secret bytes for one
  `recipient_key` and one `removal_frontier_id`.
- `recipient_key_tombstone`: a shared endpoint-signed supersession fact. It
  names an old `recipient_key`, a replacement `recipient_key`, and projects a
  durable tombstone while purging the old public-key row from the active read
  model.
- `key_wrap_receipt`: a shared signed acknowledgement that an endpoint decrypted
  a key wrap. The receipt does not expose or depend on local secret material.
- `encrypted_message`: a shared encrypted content event whose projection depends
  on a local-only key event.

Later phase-two terms:

- `local_history_node_secret`: local-only secret material for a canonical
  history range node under one `removal_frontier_id`. The node is named by
  `(workspace_id, removal_frontier_id, range_start, range_width)`, where
  `range_width` is a power of two and `range_start` is width-aligned.
- `history_delete`
- `invite_history_grant`
- retained cover / purge cover / puncturing

Phase two is now being introduced in narrow slices. The current slice makes
history range-node keys and recipient-key supersession ordinary events, but it
does not yet implement encrypted filesystem content, retained-cover
calculation, deletion facts, invite history grants, or retained-node key wraps.

## Dependency Model

Encrypted content uses ordinary dependencies:

```text
encrypted_message record dependencies:
  workspace_id
  author user/admin/auth deps
  signer endpoint_shared_id
  local_key_secret_id
```

If `local_key_secret_id` is absent, the common worker stores the event as
Blocked. When a local-only event with that id is later admitted and projected,
the common worker unblocks and reprojects the encrypted content.

The encrypted-content projector may decrypt using dependency context because the
key is already in `EventWithContext`. That path does not need an encryption
worker.

## Derivation Model

Incoming shared facts can make new local or shared events derivable. Projectors
must not create those follow-on events directly. The encryption worker owns
bounded derivation:

```text
key_wrap projects
  -> writes key_wrap row

encryption worker sees:
  key_wrap row + local_recipient_key row
  -> decrypts with core crypto
  -> command creates deterministic local_key_secret event
  -> common worker admits local event
  -> blocked encrypted content unblocks normally
  -> command may create signed key_wrap_receipt event
  -> common worker admits shared receipt
```

For outbound availability:

```text
removal_frontier / recipient_key / key_wrap_receipt project
  -> write public rows and labels
  -> write or refresh key_wrap_obligation rows

encryption worker sees:
  key_wrap_obligation + local_key_secret
  -> command creates key_wrap event using real AEAD
  -> common worker admits shared key_wrap
```

The worker is a derivation runner, not a projector and not a dependency
resolver. It should be restart-safe: if memory queues vanish, projected rows and
local-only secret events are enough to derive the same remaining obligations.

For history-tree secrets:

```text
local_key_secret or local_history_node_secret source
  -> encryption worker derives local_history_node_secret with HKDF-SHA256
  -> common worker admits local event
  -> projector writes the node row
  -> if the event names tombstone_node_id, projector writes a durable tombstone
     row and exact-deletes the retired path-node row
```

The tombstone is intentionally an event-shaped dependency, not a storage-side
shortcut. A sibling node that retires a path node depends on that path-node event,
so the common worker applies the sibling only after the path node is valid. Once
the sibling is projected, the retired node row is purged and workers can no
longer derive children from it.

For recipient-key rotation:

```text
encryption worker creates new local_recipient_key
  -> publishes new recipient_key signed by the endpoint membership
  -> emits recipient_key_tombstone events for old active local recipient keys
  -> tombstone projection removes old recipient_key rows from the active model
```

The current active-key boundary is the projected read model used by CLI and
workers. A future retained-node wrap projector may need an explicit recipient
key status dependency if we decide that shared wrap events themselves must be
invalid after supersession rather than merely ignored by honest workers.

## Crypto Direction

Use real, reviewed constructions only:

- random X25519 recipient keys for wrapping
- XChaCha20-Poly1305 for authenticated encryption
- random nonces unless a deterministic construction has a written security
  argument and tests
- domain-separated associated data for every encrypted event type
- Ed25519 signatures for shared authority claims

The older plan discussed deterministic key-wrap bytes. That is not the current
implementation direction. We dedupe by deterministic semantic keys such as
`(workspace_id, removal_frontier_id, recipient_key_id)`, while `key_wrap`
ciphertext uses a random nonce. Projection also writes a frontier-level
`(workspace_id, removal_frontier_id) -> local_key_secret_id` commitment row so
all wraps for one frontier agree on the same key-secret event id. Conflicting
semantic duplicates are rejected by row conflict instead of forcing
deterministic encryption just to make event ids stable.

Required crypto tests:

- round trip with real primitives
- wrong key rejection
- associated-data rejection
- nonce/ciphertext tamper rejection
- no plaintext in shared rows, transit frames, CLI output, or logs that claim
  encryption

## Phase One

Phase one proves encrypted key availability without history-tree puncturing.

1. Add core symmetric AEAD helpers and tests.
2. Add `recipient_key` and `local_recipient_key`.
3. Add `removal_frontier` and `local_key_secret`.
4. Add `key_wrap` and `key_wrap_receipt`.
5. Add the bounded encryption derivation worker.
6. Add encrypted content for one narrow content type, likely message text.
7. Prove the flow through black-box CLI/network tests.

Phase-one success criteria:

- Replaying the same shared event set plus local secret events converges.
- Missing local key material blocks encrypted content through the common worker.
- Receiving a key wrap plus having a local recipient private key derives a local
  key secret through normal event admission.
- Receipt projection stops retry/projection for that frontier/recipient without
  erasing the semantic receipt fact.
- Restart after clearing memory work still derives pending key wraps from
  projected facts and local-only secret events.
- A non-member cannot receive or decrypt another workspace's encrypted content.

## Phase Two

Phase two adds forward secrecy for deletion and expiry through retained
history-tree nodes. It should begin only after phase one is stable.

Rules retained from the old plan:

- Delete and expiry facts commute by set union.
- The same delete set must produce the same retained cover, purge cover, and
  summary id independent of event order.
- Production purge may remove ciphertext or local secrets only after durable
  labels/summaries/retained-node commitments preserve the semantic facts.
- New recipients receive only the retained nodes authorized by invite/grant
  policy.
- Removed recipients are excluded from future frontiers and future retained-node
  wraps.

Current phase-two slice:

- Real HKDF-SHA256 derivation in `core::crypto` for local range-node secrets.
- `recipient_key_tombstone` shared events purge old recipient public keys from
  the active key table.
- `local_history_node_secret` local events name canonical range nodes and can
  tombstone an older local path node by exact row delete.
- Black-box CLI coverage proves key rotation purges old recipient keys and a
  sibling history node tombstones a retired path node.

Still pending:

- Functional retained-cover and purge-cover calculation from delete/expiry sets.
- Shared delete facts and deterministic deletion summaries.
- Real encrypted message and reaction events. Plaintext message/reaction rows
  cannot support deletion forward secrecy.
- Wrap obligations for retained history nodes.
- Invite-time history grants for newly authorized endpoints.
- Encrypted filesystem content events that depend on local history node secrets.
- Durable purge of obsolete ciphertext/event bytes and local secrets after the
  durable deletion/frontier facts, labels, summaries, or retained-node
  commitments preserve the semantic state. Projector read-model deletion alone
  is not a forward-secrecy boundary against an on-disk attacker.
- Property tests comparing incremental retained-cover projection with a pure
  functional reference implementation.

## Implementation Order

1. Import this plan and keep rules honest.
2. Add only real core crypto helpers needed for phase one.
3. Add encryption module skeleton with one local-only secret event.
4. Add recipient key and removal frontier facts with pure projector tests.
5. Add key wrap codec/commands/projector using real AEAD.
6. Add derivation worker with bounded fuel and restart tests.
7. Add encrypted message projection that blocks on a local key event.
8. Add black-box CLI tests proving two endpoints can exchange encrypted content
   after invite/join and sync.

Each implementation slice must include realistic tests and must be committed on
this worktree branch before handoff.

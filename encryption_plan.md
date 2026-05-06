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
  schema.rs
  worker.rs
  recipient_key/
  local_recipient_key/
  key_epoch/
  local_epoch_secret/
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
- `key_epoch`: a shared workspace-scoped group/content epoch. Phase one creates
  epochs for workspace creation and later removals. Removal is documented here
  but should not be implemented before basic availability works.
- `local_epoch_secret`: local-only symmetric secret material for one epoch.
- `key_wrap`: a shared event carrying an encrypted epoch secret for one
  recipient key.
- `key_wrap_receipt`: a shared signed acknowledgement that an endpoint decrypted
  a key wrap. The receipt does not expose or depend on local secret material.
- `encrypted_message`: a shared encrypted content event whose projection depends
  on a local-only key event.

Later phase-two terms:

- `history_node_secret`
- `history_delete`
- `invite_history_grant`
- retained cover / purge cover / puncturing

Phase two stays out of scope until phase-one replay, restart, and black-box
availability tests are stable.

## Dependency Model

Encrypted content uses ordinary dependencies:

```text
encrypted_message record dependencies:
  workspace_id
  author user/admin/auth deps
  signer endpoint_shared_id
  local_epoch_secret_event_id
```

If `local_epoch_secret_event_id` is absent, the common worker stores the event as
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
  -> command creates deterministic local_epoch_secret event
  -> common worker admits local event
  -> blocked encrypted content unblocks normally
  -> command may create signed key_wrap_receipt event
  -> common worker admits shared receipt
```

For outbound availability:

```text
key_epoch / recipient_key / key_wrap_receipt project
  -> write public rows and labels
  -> write or refresh key_wrap_obligation rows

encryption worker sees:
  key_wrap_obligation + local_epoch_secret
  -> command creates key_wrap event using real AEAD
  -> common worker admits shared key_wrap
```

The worker is a derivation runner, not a projector and not a dependency
resolver. It should be restart-safe: if memory queues vanish, projected rows and
local-only secret events are enough to derive the same remaining obligations.

## Crypto Direction

Use real, reviewed constructions only:

- random X25519 recipient keys for wrapping
- XChaCha20-Poly1305 for authenticated encryption
- random nonces unless a deterministic construction has a written security
  argument and tests
- domain-separated associated data for every encrypted event type
- Ed25519 signatures for shared authority claims

The older plan discussed deterministic key-wrap bytes. That is not the default
implementation direction here. We should dedupe by deterministic semantic
obligation keys such as `(epoch_id, recipient_key_id, node_prefix)`, while
`key_wrap` ciphertext may use a random nonce. Projection can accept the first
valid wrap for an obligation and ignore or reject conflicting duplicates by
semantic key. Do not force deterministic encryption just to make event ids
stable.

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
3. Add `key_epoch` and `local_epoch_secret`.
4. Add `key_wrap` and `key_wrap_receipt`.
5. Add the bounded encryption derivation worker.
6. Add encrypted content for one narrow content type, likely message text.
7. Prove the flow through black-box CLI/network tests.

Phase-one success criteria:

- Replaying the same shared event set plus local secret events converges.
- Missing local key material blocks encrypted content through the common worker.
- Receiving a key wrap plus having a local recipient private key derives a local
  epoch secret through normal event admission.
- Receipt projection stops retry/projection for that epoch/recipient without
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
- Removed recipients are excluded from future epochs and future retained-node
  wraps.

## Implementation Order

1. Import this plan and keep rules honest.
2. Add only real core crypto helpers needed for phase one.
3. Add encryption module skeleton with one local-only secret event.
4. Add recipient key and key epoch facts with pure projector tests.
5. Add key wrap codec/commands/projector using real AEAD.
6. Add derivation worker with bounded fuel and restart tests.
7. Add encrypted message projection that blocks on a local key event.
8. Add black-box CLI tests proving two endpoints can exchange encrypted content
   after invite/join and sync.

Each implementation slice must include realistic tests and must be committed on
this worktree branch before handoff.

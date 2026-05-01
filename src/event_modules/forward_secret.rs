//! Forward-secret encryption model as pure events plus a deterministic projector.
//!
//! This module deliberately does not register with the core pipeline yet. It is a
//! standalone model of the facts and expansions the pipeline should eventually be
//! able to host: pubkeys tombstone older pubkeys, removal frontiers drive wrap
//! obligations, receipts stop repeat wrapping, and history deletes puncture a
//! BLAKE3-addressed tree by retaining the siblings needed for undeleted history.

use crate::pipeline::{EventId, WorkspaceId};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecipientKind {
    Device,
    Invite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodePrefix {
    pub bytes: [u8; 32],
    pub bit_len: u16,
}

impl NodePrefix {
    pub const ROOT: Self = Self {
        bytes: [0; 32],
        bit_len: 0,
    };

    pub fn leaf(index: EventId) -> Self {
        Self {
            bytes: index,
            bit_len: 256,
        }
    }

    pub fn contains_leaf(self, leaf: EventId) -> bool {
        prefix_matches(&self.bytes, &leaf, self.bit_len)
    }

    fn parent(self) -> Option<Self> {
        if self.bit_len == 0 {
            return None;
        }
        let mut bytes = self.bytes;
        clear_suffix(&mut bytes, self.bit_len - 1);
        Some(Self {
            bytes,
            bit_len: self.bit_len - 1,
        })
    }

    fn sibling(self) -> Option<Self> {
        if self.bit_len == 0 {
            return None;
        }
        let mut bytes = self.bytes;
        flip_bit(&mut bytes, self.bit_len - 1);
        clear_suffix(&mut bytes, self.bit_len);
        Some(Self {
            bytes,
            bit_len: self.bit_len,
        })
    }

    fn last_bit(self) -> Option<u8> {
        (self.bit_len > 0).then(|| bit_at(&self.bytes, self.bit_len - 1))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HistoryCoord {
    pub unix_minute: u64,
    pub event_id: EventId,
}

impl HistoryCoord {
    pub fn leaf_index(self) -> EventId {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"topo.fs.history-coord.v1");
        hasher.update(&self.unix_minute.to_be_bytes());
        hasher.update(&self.event_id);
        *hasher.finalize().as_bytes()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsEvent {
    RecipientCreated {
        workspace_id: WorkspaceId,
        recipient_id: EventId,
        kind: RecipientKind,
    },
    DevicePubkey {
        workspace_id: WorkspaceId,
        recipient_id: EventId,
        prev_pubkey_id: Option<EventId>,
        public_key: [u8; 32],
    },
    KeyEpoch {
        workspace_id: WorkspaceId,
        prev_epoch_id: Option<EventId>,
        removed_recipient_id: Option<EventId>,
        root_commitment: [u8; 32],
    },
    KeyWrap {
        workspace_id: WorkspaceId,
        epoch_id: EventId,
        pubkey_id: EventId,
        node_prefix: NodePrefix,
        secret_commitment: [u8; 32],
        ciphertext_commitment: [u8; 32],
    },
    KeyWrapReceipt {
        workspace_id: WorkspaceId,
        epoch_id: EventId,
        pubkey_id: EventId,
        node_prefix: NodePrefix,
        wrap_id: EventId,
    },
    MessageEncrypted {
        workspace_id: WorkspaceId,
        epoch_id: EventId,
        coord: HistoryCoord,
        ciphertext_commitment: [u8; 32],
    },
    HistoryDelete {
        workspace_id: WorkspaceId,
        epoch_id: EventId,
        deleted_coords: Vec<HistoryCoord>,
    },
    InviteHistoryGrant {
        workspace_id: WorkspaceId,
        invite_recipient_id: EventId,
        epoch_id: EventId,
        retained_cover: Vec<NodePrefix>,
    },
}

impl FsEvent {
    pub fn event_id(&self) -> EventId {
        *blake3::hash(&self.canonical_bytes()).as_bytes()
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            FsEvent::RecipientCreated {
                workspace_id,
                recipient_id,
                kind,
            } => {
                out.push(1);
                push_id(&mut out, workspace_id);
                push_id(&mut out, recipient_id);
                out.push(match kind {
                    RecipientKind::Device => 1,
                    RecipientKind::Invite => 2,
                });
            }
            FsEvent::DevicePubkey {
                workspace_id,
                recipient_id,
                prev_pubkey_id,
                public_key,
            } => {
                out.push(2);
                push_id(&mut out, workspace_id);
                push_id(&mut out, recipient_id);
                push_optional_id(&mut out, prev_pubkey_id);
                push_id(&mut out, public_key);
            }
            FsEvent::KeyEpoch {
                workspace_id,
                prev_epoch_id,
                removed_recipient_id,
                root_commitment,
            } => {
                out.push(3);
                push_id(&mut out, workspace_id);
                push_optional_id(&mut out, prev_epoch_id);
                push_optional_id(&mut out, removed_recipient_id);
                push_id(&mut out, root_commitment);
            }
            FsEvent::KeyWrap {
                workspace_id,
                epoch_id,
                pubkey_id,
                node_prefix,
                secret_commitment,
                ciphertext_commitment,
            } => {
                out.push(4);
                push_id(&mut out, workspace_id);
                push_id(&mut out, epoch_id);
                push_id(&mut out, pubkey_id);
                push_node(&mut out, *node_prefix);
                push_id(&mut out, secret_commitment);
                push_id(&mut out, ciphertext_commitment);
            }
            FsEvent::KeyWrapReceipt {
                workspace_id,
                epoch_id,
                pubkey_id,
                node_prefix,
                wrap_id,
            } => {
                out.push(5);
                push_id(&mut out, workspace_id);
                push_id(&mut out, epoch_id);
                push_id(&mut out, pubkey_id);
                push_node(&mut out, *node_prefix);
                push_id(&mut out, wrap_id);
            }
            FsEvent::MessageEncrypted {
                workspace_id,
                epoch_id,
                coord,
                ciphertext_commitment,
            } => {
                out.push(6);
                push_id(&mut out, workspace_id);
                push_id(&mut out, epoch_id);
                push_coord(&mut out, *coord);
                push_id(&mut out, ciphertext_commitment);
            }
            FsEvent::HistoryDelete {
                workspace_id,
                epoch_id,
                deleted_coords,
            } => {
                out.push(7);
                push_id(&mut out, workspace_id);
                push_id(&mut out, epoch_id);
                let mut coords = deleted_coords.clone();
                coords.sort();
                push_len(&mut out, coords.len());
                for coord in coords {
                    push_coord(&mut out, coord);
                }
            }
            FsEvent::InviteHistoryGrant {
                workspace_id,
                invite_recipient_id,
                epoch_id,
                retained_cover,
            } => {
                out.push(8);
                push_id(&mut out, workspace_id);
                push_id(&mut out, invite_recipient_id);
                push_id(&mut out, epoch_id);
                let mut cover = retained_cover.clone();
                cover.sort();
                push_len(&mut out, cover.len());
                for node in cover {
                    push_node(&mut out, node);
                }
            }
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct WrapKey {
    pub epoch_id: EventId,
    pub pubkey_id: EventId,
    pub node_prefix: NodePrefix,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Projection {
    pub emitted_events: Vec<FsEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecipientFact {
    kind: RecipientKind,
    removed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PubkeyFact {
    recipient_id: EventId,
    prev_pubkey_id: Option<EventId>,
    public_key: [u8; 32],
    superseded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EpochFact {
    workspace_id: WorkspaceId,
    prev_epoch_id: Option<EventId>,
    removed_recipient_id: Option<EventId>,
    root_commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WrapFact {
    epoch_id: EventId,
    pubkey_id: EventId,
    node_prefix: NodePrefix,
    secret_commitment: [u8; 32],
    ciphertext_commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct EpochHistory {
    messages: BTreeSet<HistoryCoord>,
    deleted: BTreeSet<HistoryCoord>,
    retained_cover: BTreeSet<NodePrefix>,
    purge_cover: BTreeSet<NodePrefix>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PublicSnapshot {
    pub active_pubkeys: Vec<(EventId, EventId)>,
    pub wraps: Vec<WrapKey>,
    pub receipts: Vec<WrapKey>,
    pub retained_cover: Vec<(EventId, NodePrefix)>,
    pub purge_cover: Vec<(EventId, NodePrefix)>,
}

#[derive(Debug, Clone, Default)]
pub struct ForwardSecretProjector {
    seen_events: BTreeSet<EventId>,
    recipients: BTreeMap<EventId, RecipientFact>,
    pubkeys: BTreeMap<EventId, PubkeyFact>,
    pubkey_tombstones: BTreeSet<(EventId, EventId)>,
    epochs: BTreeMap<EventId, EpochFact>,
    removed_recipients: BTreeSet<EventId>,
    wraps: BTreeMap<EventId, WrapFact>,
    receipts: BTreeSet<WrapKey>,
    histories: BTreeMap<EventId, EpochHistory>,
    invite_grants: BTreeMap<EventId, Vec<NodePrefix>>,
    local_epoch_roots: BTreeMap<EventId, [u8; 32]>,
    local_node_secrets: BTreeMap<(EventId, NodePrefix), [u8; 32]>,
    local_private_keys: BTreeMap<EventId, [u8; 32]>,
}

impl ForwardSecretProjector {
    pub fn apply_event(&mut self, event: FsEvent, fuel: usize) -> Projection {
        let event_id = event.event_id();
        if self.seen_events.insert(event_id) {
            match event {
                FsEvent::RecipientCreated {
                    recipient_id, kind, ..
                } => {
                    let removed = self.removed_recipients.contains(&recipient_id);
                    self.recipients
                        .entry(recipient_id)
                        .or_insert(RecipientFact { kind, removed });
                }
                FsEvent::DevicePubkey {
                    recipient_id,
                    prev_pubkey_id,
                    public_key,
                    ..
                } => {
                    if let Some(prev) = prev_pubkey_id {
                        self.pubkey_tombstones.insert((prev, recipient_id));
                        if let Some(prev_fact) = self.pubkeys.get_mut(&prev) {
                            if prev_fact.recipient_id == recipient_id {
                                prev_fact.superseded = true;
                            }
                        }
                    }
                    let superseded = self.pubkey_is_tombstoned(event_id, recipient_id);
                    self.pubkeys.entry(event_id).or_insert(PubkeyFact {
                        recipient_id,
                        prev_pubkey_id,
                        public_key,
                        superseded,
                    });
                }
                FsEvent::KeyEpoch {
                    workspace_id,
                    prev_epoch_id,
                    removed_recipient_id,
                    root_commitment,
                } => {
                    if let Some(recipient_id) = removed_recipient_id {
                        self.removed_recipients.insert(recipient_id);
                        if let Some(recipient) = self.recipients.get_mut(&recipient_id) {
                            recipient.removed = true;
                        }
                    }
                    self.epochs.entry(event_id).or_insert(EpochFact {
                        workspace_id,
                        prev_epoch_id,
                        removed_recipient_id,
                        root_commitment,
                    });
                }
                FsEvent::KeyWrap {
                    epoch_id,
                    pubkey_id,
                    node_prefix,
                    secret_commitment,
                    ciphertext_commitment,
                    ..
                } => {
                    self.wraps.entry(event_id).or_insert(WrapFact {
                        epoch_id,
                        pubkey_id,
                        node_prefix,
                        secret_commitment,
                        ciphertext_commitment,
                    });
                }
                FsEvent::KeyWrapReceipt {
                    epoch_id,
                    pubkey_id,
                    node_prefix,
                    ..
                } => {
                    self.receipts.insert(WrapKey {
                        epoch_id,
                        pubkey_id,
                        node_prefix,
                    });
                }
                FsEvent::MessageEncrypted {
                    epoch_id, coord, ..
                } => {
                    self.histories
                        .entry(epoch_id)
                        .or_default()
                        .messages
                        .insert(coord);
                    self.recompute_history(epoch_id);
                }
                FsEvent::HistoryDelete {
                    epoch_id,
                    deleted_coords,
                    ..
                } => {
                    let history = self.histories.entry(epoch_id).or_default();
                    history.deleted.extend(deleted_coords);
                    self.recompute_history(epoch_id);
                }
                FsEvent::InviteHistoryGrant {
                    invite_recipient_id,
                    retained_cover,
                    ..
                } => {
                    self.invite_grants
                        .entry(invite_recipient_id)
                        .or_insert(retained_cover);
                }
            }
        }

        self.derive_events(fuel)
    }

    pub fn insert_local_epoch_root(&mut self, epoch_id: EventId, root_secret: [u8; 32]) {
        self.local_epoch_roots.insert(epoch_id, root_secret);
        if let Some(history) = self.histories.get(&epoch_id) {
            if !history.deleted.is_empty() {
                self.puncture_epoch(epoch_id);
            }
        }
    }

    pub fn insert_local_private_key(&mut self, pubkey_id: EventId, private_key: [u8; 32]) {
        self.local_private_keys.insert(pubkey_id, private_key);
    }

    pub fn derive_events(&self, fuel: usize) -> Projection {
        let mut emitted_events = Vec::new();

        for obligation in self.wrap_obligations() {
            if emitted_events.len() >= fuel {
                break;
            }
            if self.receipts.contains(&obligation) || self.has_wrap_for(&obligation) {
                continue;
            }
            let Some(secret) = self.local_secret_for(obligation.epoch_id, obligation.node_prefix)
            else {
                continue;
            };
            let epoch = self
                .epochs
                .get(&obligation.epoch_id)
                .expect("obligation epoch exists");
            let pubkey = self
                .pubkeys
                .get(&obligation.pubkey_id)
                .expect("obligation pubkey exists");
            emitted_events.push(FsEvent::KeyWrap {
                workspace_id: epoch.workspace_id,
                epoch_id: obligation.epoch_id,
                pubkey_id: obligation.pubkey_id,
                node_prefix: obligation.node_prefix,
                secret_commitment: secret_commitment(secret),
                ciphertext_commitment: deterministic_wrap_commitment(
                    obligation.epoch_id,
                    obligation.pubkey_id,
                    obligation.node_prefix,
                    secret,
                    pubkey.public_key,
                ),
            });
        }

        for (wrap_id, wrap) in &self.wraps {
            if emitted_events.len() >= fuel {
                break;
            }
            let key = WrapKey {
                epoch_id: wrap.epoch_id,
                pubkey_id: wrap.pubkey_id,
                node_prefix: wrap.node_prefix,
            };
            if self.receipts.contains(&key) {
                continue;
            }
            let Some(private_key) = self.local_private_keys.get(&wrap.pubkey_id) else {
                continue;
            };
            let Some(pubkey) = self.pubkeys.get(&wrap.pubkey_id) else {
                continue;
            };
            if public_key_for_private(*private_key) != pubkey.public_key {
                continue;
            }
            let epoch = self.epochs.get(&wrap.epoch_id).expect("wrap epoch exists");
            emitted_events.push(FsEvent::KeyWrapReceipt {
                workspace_id: epoch.workspace_id,
                epoch_id: wrap.epoch_id,
                pubkey_id: wrap.pubkey_id,
                node_prefix: wrap.node_prefix,
                wrap_id: *wrap_id,
            });
        }

        Projection { emitted_events }
    }

    pub fn wrap_obligations(&self) -> BTreeSet<WrapKey> {
        let mut obligations = BTreeSet::new();
        for epoch_id in self.epochs.keys().copied() {
            let nodes = self.nodes_to_wrap(epoch_id);
            for pubkey_id in self.active_pubkey_ids_for_epoch(epoch_id) {
                for node_prefix in &nodes {
                    obligations.insert(WrapKey {
                        epoch_id,
                        pubkey_id,
                        node_prefix: *node_prefix,
                    });
                }
            }
        }
        obligations
    }

    pub fn retained_cover(&self, epoch_id: EventId) -> BTreeSet<NodePrefix> {
        self.histories
            .get(&epoch_id)
            .map(|history| history.retained_cover.clone())
            .unwrap_or_default()
    }

    pub fn purge_cover(&self, epoch_id: EventId) -> BTreeSet<NodePrefix> {
        self.histories
            .get(&epoch_id)
            .map(|history| history.purge_cover.clone())
            .unwrap_or_default()
    }

    pub fn can_decrypt(&self, epoch_id: EventId, coord: HistoryCoord) -> bool {
        let Some(history) = self.histories.get(&epoch_id) else {
            return false;
        };
        if !history.messages.contains(&coord) || history.deleted.contains(&coord) {
            return false;
        }
        if self.local_epoch_roots.contains_key(&epoch_id) && history.deleted.is_empty() {
            return true;
        }
        let leaf = coord.leaf_index();
        self.local_node_secrets
            .keys()
            .any(|(secret_epoch, node)| *secret_epoch == epoch_id && node.contains_leaf(leaf))
    }

    pub fn invite_history_grant(
        &self,
        workspace_id: WorkspaceId,
        invite_recipient_id: EventId,
        epoch_id: EventId,
    ) -> FsEvent {
        FsEvent::InviteHistoryGrant {
            workspace_id,
            invite_recipient_id,
            epoch_id,
            retained_cover: self.retained_cover(epoch_id).into_iter().collect(),
        }
    }

    pub fn grant_allows(&self, grant: &FsEvent, coord: HistoryCoord) -> bool {
        let FsEvent::InviteHistoryGrant { retained_cover, .. } = grant else {
            return false;
        };
        let leaf = coord.leaf_index();
        retained_cover.iter().any(|node| node.contains_leaf(leaf))
    }

    pub fn public_snapshot(&self) -> PublicSnapshot {
        let mut retained_cover = Vec::new();
        let mut purge_cover = Vec::new();
        for (epoch_id, history) in &self.histories {
            retained_cover.extend(
                history
                    .retained_cover
                    .iter()
                    .copied()
                    .map(|node| (*epoch_id, node)),
            );
            purge_cover.extend(
                history
                    .purge_cover
                    .iter()
                    .copied()
                    .map(|node| (*epoch_id, node)),
            );
        }
        PublicSnapshot {
            active_pubkeys: self
                .pubkeys
                .iter()
                .filter_map(|(pubkey_id, pubkey)| {
                    (!self.pubkey_is_tombstoned(*pubkey_id, pubkey.recipient_id)
                        && !self.recipient_removed(pubkey.recipient_id))
                    .then_some((pubkey.recipient_id, *pubkey_id))
                })
                .collect(),
            wraps: self
                .wraps
                .values()
                .map(|wrap| WrapKey {
                    epoch_id: wrap.epoch_id,
                    pubkey_id: wrap.pubkey_id,
                    node_prefix: wrap.node_prefix,
                })
                .collect(),
            receipts: self.receipts.iter().cloned().collect(),
            retained_cover,
            purge_cover,
        }
    }

    fn recompute_history(&mut self, epoch_id: EventId) {
        let Some(history) = self.histories.get_mut(&epoch_id) else {
            return;
        };
        let deleted = history
            .deleted
            .iter()
            .map(|coord| coord.leaf_index())
            .collect::<BTreeSet<_>>();

        history.retained_cover = retained_complement_cover(&deleted);
        history.purge_cover = canonical_minimal_cover(&deleted);
        if !history.deleted.is_empty() {
            self.puncture_epoch(epoch_id);
        }
    }

    fn puncture_epoch(&mut self, epoch_id: EventId) {
        let Some(root_secret) = self.local_epoch_roots.remove(&epoch_id) else {
            return;
        };
        let Some(history) = self.histories.get(&epoch_id) else {
            return;
        };
        self.local_node_secrets
            .retain(|(secret_epoch, _), _| *secret_epoch != epoch_id);
        for node in &history.retained_cover {
            self.local_node_secrets
                .insert((epoch_id, *node), derive_node_secret(root_secret, *node));
        }
    }

    fn nodes_to_wrap(&self, epoch_id: EventId) -> BTreeSet<NodePrefix> {
        let Some(history) = self.histories.get(&epoch_id) else {
            return BTreeSet::from([NodePrefix::ROOT]);
        };
        if history.deleted.is_empty() {
            BTreeSet::from([NodePrefix::ROOT])
        } else {
            history.retained_cover.clone()
        }
    }

    fn local_secret_for(&self, epoch_id: EventId, node_prefix: NodePrefix) -> Option<[u8; 32]> {
        if node_prefix == NodePrefix::ROOT {
            self.local_epoch_roots.get(&epoch_id).copied()
        } else {
            self.local_node_secrets
                .get(&(epoch_id, node_prefix))
                .copied()
        }
    }

    fn has_wrap_for(&self, obligation: &WrapKey) -> bool {
        self.wraps.values().any(|wrap| {
            wrap.epoch_id == obligation.epoch_id
                && wrap.pubkey_id == obligation.pubkey_id
                && wrap.node_prefix == obligation.node_prefix
        })
    }

    fn active_pubkey_ids_for_epoch(&self, epoch_id: EventId) -> BTreeSet<EventId> {
        let removed_at_epoch = self.removed_recipients_at_epoch(epoch_id);
        self.pubkeys
            .iter()
            .filter_map(|(pubkey_id, pubkey)| {
                let recipient_is_active = !self
                    .pubkey_is_tombstoned(*pubkey_id, pubkey.recipient_id)
                    && !self.recipient_removed(pubkey.recipient_id)
                    && !removed_at_epoch.contains(&pubkey.recipient_id);
                recipient_is_active.then_some(*pubkey_id)
            })
            .collect()
    }

    fn removed_recipients_at_epoch(&self, epoch_id: EventId) -> BTreeSet<EventId> {
        let mut removed = BTreeSet::new();
        let mut cursor = Some(epoch_id);
        while let Some(id) = cursor {
            let Some(epoch) = self.epochs.get(&id) else {
                break;
            };
            if let Some(recipient_id) = epoch.removed_recipient_id {
                removed.insert(recipient_id);
            }
            cursor = epoch.prev_epoch_id;
        }
        removed
    }

    fn recipient_removed(&self, recipient_id: EventId) -> bool {
        self.removed_recipients.contains(&recipient_id)
            || self
                .recipients
                .get(&recipient_id)
                .is_some_and(|recipient| recipient.removed)
    }

    fn pubkey_is_tombstoned(&self, pubkey_id: EventId, recipient_id: EventId) -> bool {
        self.pubkey_tombstones.contains(&(pubkey_id, recipient_id))
            || self
                .pubkeys
                .get(&pubkey_id)
                .is_some_and(|pubkey| pubkey.superseded)
    }
}

pub fn public_key_for_private(private_key: [u8; 32]) -> [u8; 32] {
    hash_parts(b"topo.fs.public-key.v1", &[&private_key])
}

pub fn root_commitment(root_secret: [u8; 32]) -> [u8; 32] {
    hash_parts(b"topo.fs.root-commitment.v1", &[&root_secret])
}

pub fn message_ciphertext_commitment(
    epoch_id: EventId,
    coord: HistoryCoord,
    plaintext_commitment: [u8; 32],
) -> [u8; 32] {
    hash_parts(
        b"topo.fs.message-ciphertext.v1",
        &[
            &epoch_id,
            &coord.unix_minute.to_be_bytes(),
            &coord.event_id,
            &plaintext_commitment,
        ],
    )
}

fn deterministic_wrap_commitment(
    epoch_id: EventId,
    pubkey_id: EventId,
    node_prefix: NodePrefix,
    secret: [u8; 32],
    public_key: [u8; 32],
) -> [u8; 32] {
    let node_bytes = node_bytes(node_prefix);
    hash_parts(
        b"topo.fs.key-wrap.v1",
        &[&epoch_id, &pubkey_id, &node_bytes, &secret, &public_key],
    )
}

fn secret_commitment(secret: [u8; 32]) -> [u8; 32] {
    hash_parts(b"topo.fs.secret-commitment.v1", &[&secret])
}

fn derive_node_secret(root_secret: [u8; 32], node_prefix: NodePrefix) -> [u8; 32] {
    let node_bytes = node_bytes(node_prefix);
    hash_parts(b"topo.fs.history-node.v1", &[&root_secret, &node_bytes])
}

fn retained_complement_cover(deleted_leaves: &BTreeSet<EventId>) -> BTreeSet<NodePrefix> {
    let mut cover = BTreeSet::from([NodePrefix::ROOT]);
    for leaf in deleted_leaves {
        let mut next = BTreeSet::new();
        for node in cover {
            if !node.contains_leaf(*leaf) {
                next.insert(node);
                continue;
            }
            next.extend(node_without_leaf_cover(node, *leaf));
        }
        cover = next;
    }
    cover
}

fn node_without_leaf_cover(node: NodePrefix, leaf: EventId) -> BTreeSet<NodePrefix> {
    let mut siblings = BTreeSet::new();
    let mut cursor = NodePrefix::leaf(leaf);
    while cursor.bit_len > node.bit_len {
        siblings.insert(cursor.sibling().expect("non-root path node has sibling"));
        cursor = cursor.parent().expect("non-root path node has parent");
    }
    siblings
}

fn canonical_minimal_cover(leaves: &BTreeSet<EventId>) -> BTreeSet<NodePrefix> {
    let mut nodes = leaves
        .iter()
        .copied()
        .map(NodePrefix::leaf)
        .collect::<BTreeSet<_>>();

    loop {
        let mut changed = false;
        let mut next = nodes.clone();
        for node in &nodes {
            let Some(sibling) = node.sibling() else {
                continue;
            };
            if node.last_bit() == Some(0) && nodes.contains(&sibling) {
                let parent = node.parent().expect("non-root has parent");
                next.remove(node);
                next.remove(&sibling);
                next.insert(parent);
                changed = true;
            }
        }
        nodes = next;
        if !changed {
            return nodes;
        }
    }
}

fn push_id(out: &mut Vec<u8>, id: &[u8; 32]) {
    out.extend_from_slice(id);
}

fn push_optional_id(out: &mut Vec<u8>, id: &Option<[u8; 32]>) {
    match id {
        Some(id) => {
            out.push(1);
            push_id(out, id);
        }
        None => out.push(0),
    }
}

fn push_node(out: &mut Vec<u8>, node: NodePrefix) {
    out.extend_from_slice(&node.bit_len.to_be_bytes());
    out.extend_from_slice(&node.bytes);
}

fn push_coord(out: &mut Vec<u8>, coord: HistoryCoord) {
    out.extend_from_slice(&coord.unix_minute.to_be_bytes());
    push_id(out, &coord.event_id);
}

fn push_len(out: &mut Vec<u8>, len: usize) {
    out.extend_from_slice(&(len as u32).to_be_bytes());
}

fn node_bytes(node: NodePrefix) -> [u8; 34] {
    let mut out = [0; 34];
    out[..2].copy_from_slice(&node.bit_len.to_be_bytes());
    out[2..].copy_from_slice(&node.bytes);
    out
}

fn prefix_matches(prefix: &EventId, leaf: &EventId, bit_len: u16) -> bool {
    let full_bytes = (bit_len / 8) as usize;
    let remaining_bits = (bit_len % 8) as u8;

    if prefix[..full_bytes] != leaf[..full_bytes] {
        return false;
    }
    if remaining_bits == 0 {
        return true;
    }

    let mask = 0xffu8 << (8 - remaining_bits);
    prefix[full_bytes] & mask == leaf[full_bytes] & mask
}

fn bit_at(bytes: &EventId, bit_index: u16) -> u8 {
    let byte = bytes[(bit_index / 8) as usize];
    let shift = 7 - (bit_index % 8);
    (byte >> shift) & 1
}

fn flip_bit(bytes: &mut EventId, bit_index: u16) {
    let byte = &mut bytes[(bit_index / 8) as usize];
    let shift = 7 - (bit_index % 8);
    *byte ^= 1 << shift;
}

fn clear_suffix(bytes: &mut EventId, bit_len: u16) {
    let full_bytes = (bit_len / 8) as usize;
    let remaining_bits = (bit_len % 8) as u8;

    if full_bytes >= bytes.len() {
        return;
    }

    if remaining_bits == 0 {
        bytes[full_bytes..].fill(0);
        return;
    }

    let mask = 0xffu8 << (8 - remaining_bits);
    bytes[full_bytes] &= mask;
    bytes[full_bytes + 1..].fill(0);
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

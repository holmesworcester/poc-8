//! Encryption worker.
//!
//! Projection records shared key-wrap facts; this worker performs the bounded
//! active step that can follow from those facts. It opens wraps only when the
//! matching local recipient private material is present, then admits the
//! resulting local key-secret event through the common event worker.
//!
//! History-node derivation is the worker's other responsibility. The retained
//! tree is a real binary tree on both axes:
//!
//!   * Time axis. Internal nodes cover `(range_start, range_width)` where
//!     `range_width` is a power of two minutes. The frontier root
//!     (`local_key_secret`) implicitly covers `(0, TIME_TREE_ROOT_WIDTH)`.
//!   * Within-minute hash trie. Trie internal nodes carry `bit_depth` and
//!     `event_id_prefix`. Leaves sit at `bit_depth=256` with the full
//!     `event_id_in_minute`.
//!
//! Most nodes stay implicit and are derived on the fly via two BLAKE3 keyed-hash
//! KDFs (`topo time split v1` and `topo trie split v1`). A row is materialized
//! only when delete or expiry punches a hole that splits a covering range, or
//! when an AEAD operation wants the leaf to be a single-row read.
//!
//! `derive_event_leaf` walks from any retained ancestor down through the time
//! tree to the event's minute_node, then down the trie to its leaf, returning
//! the leaf's `node_secret` for AEAD use. For a fresh encryption with no deletes
//! in the region the walk descends straight from the workspace root and only
//! the leaf row is materialized.
//!
//! `RetireDeletedEventLeaf` walks the same path, materializing BOTH children
//! at every split so the projector's source-dependency invariant holds while
//! we admit the chain. After the walk, the descend-side rows AND the F root
//! row are exact-deleted, their canonical bytes are purged, and tombstone
//! rows are written into `local_history_node_tombstones`. Only sibling rows
//! survive, plus other event leaves.
//!
//! After retire, an adversary on the device has access to:
//!
//!   * Sibling rows, each of which derives only its own subtree (the deleted
//!     leaf coord's path bit at the sibling's depth differs from the
//!     sibling's prefix, so a `derive_trie_split`/`derive_time_split` from a
//!     sibling cannot reach the deleted leaf).
//!   * Surviving event leaf rows (each carries its own AEAD key material —
//!     unchanged by retire).
//!   * Tombstone rows naming wiped event ids (no secret material).
//!
//! No retained row can re-derive the deleted leaf's `node_secret`, even when
//! combined with the deleted event's canonical bytes (which give the
//! adversary the deterministic `event_id_in_minute`). Forward secrecy of the
//! deleted message's AEAD key is therefore enforced against an on-disk
//! attacker holding the ciphertext.
//!
//! Future encryption under the wiped frontier `F` continues to work
//! without explicit rotation: the time-tree siblings admitted along
//! the descend path collectively cover every minute *except* the
//! wiped one, so `derive_event_leaf` for a coord in any other minute
//! falls back to the deepest covering time-axis sibling and walks
//! down from there. (Same-minute new authoring works only when the
//! coord's prefix lies under a surviving trie sibling; coords whose
//! subtree was inside the wiped descend chain legitimately wedge —
//! that's the "no covering ancestor" branch in
//! `closest_retained_ancestor`.) Each peer derives the sibling
//! secrets locally because the KDF is deterministic, so no new wraps
//! to recipients are required. Rotation can still happen for
//! unrelated reasons (e.g. recipient turnover via `key-frontier`);
//! retirement does not force it.

use crate::core::crypto;
use crate::core::logical_clock;
use crate::core::store::Store;
use crate::protocol::event_modules::identity::{endpoint, endpoint_shared};
use crate::protocol::event_modules::queries as event_queries;
use crate::protocol::event_modules::schema as event_schema;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::{self, EventRegistry};
use crate::workers::pipeline_helpers::purging;

use crate::protocol::event_modules::encryption::{
    key_wrap, local_history_node_secret, local_key_secret, local_recipient_key, recipient_key,
    recipient_key_tombstone,
};

use local_history_node_secret::types::{
    bit_at, first_diverging_bit, mask_prefix_to_depth, HistoryNodeSecret, TIME_TREE_BIT_DEPTH,
    TRIE_LEAF_BIT_DEPTH,
};

/// The implicit time-tree root covers `(0, TIME_TREE_ROOT_WIDTH)`. Set to
/// `2^63` so widths stay clean powers of two through `range_width=1`. This
/// supports unix minutes through year 1.7 * 10^14 — vastly larger than the
/// useful range; the constant is a fixed structural choice, not a deadline.
pub const TIME_TREE_ROOT_WIDTH: u64 = 1u64 << 63;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    DeriveKeySecrets {
        batch_size: usize,
    },
    RotateRecipientKey {
        workspace_id: EventId,
    },
    /// Idempotently derive (or look up) the per-event leaf for one
    /// `(workspace_id, removal_frontier_id, created_at_ms, event_id_in_minute)`
    /// tuple. Senders call this before authoring an event so the canonical
    /// event can name the leaf id; receivers call it after admission blocks
    /// on the named leaf so dependency unblock can let the event project.
    /// `event_id_in_minute` is the deterministic 32-byte coordinate computed
    /// by the event-type's `event_id_in_minute_derived()`.
    DeriveEventLeaf {
        workspace_id: EventId,
        removal_frontier_id: EventId,
        created_at_ms: u64,
        event_id_in_minute: EventId,
    },
    /// Retire one deleted event's per-event leaf by walking the tree from the
    /// closest retained ancestor down to the leaf, materializing splits at
    /// every level so siblings retain implicit cover, then purging the leaf
    /// row and canonical bytes.
    RetireDeletedEventLeaf {
        workspace_id: EventId,
        removal_frontier_id: EventId,
        created_at_ms: u64,
        event_id_in_minute: EventId,
    },
    /// Scan a bounded batch of admitted message, reaction, and file events
    /// and derive their per-event leaves. This is the receiver-side wiring.
    DrainPendingMessageLeaves {
        batch_size: usize,
    },
    /// Range-deletion primitive: tombstone every minute in `[0, floor_minute)`
    /// of the time tree. Walks the boundary descend path from F (or the
    /// deepest covering sibling, if F is wiped); at each level whose
    /// floor-minute bit is 1 the entire left subtree is in `[0, floor_minute)`
    /// and gets tombstoned (one tombstone per fully-left subtree, regardless
    /// of how many minutes/messages live underneath). At each level whose
    /// floor-minute bit is 0 the right half survives intact and is
    /// materialized so future authoring above the floor still has a
    /// covering ancestor. Cost is O(log time_tree_root_width), not
    /// O(messages_in_range). Determinism: same `floor_minute` produces
    /// byte-identical tombstones on every peer.
    ChopTimeTreePrefix {
        workspace_id: EventId,
        removal_frontier_id: EventId,
        /// Minute boundary; everything `< floor_minute` is chopped.
        floor_minute: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    DerivedKeySecrets(DeriveReport),
    RotatedRecipientKey(RotateRecipientKeyReport),
    DerivedEventLeaf(DeriveEventLeafReport),
    RetiredDeletedEventLeaf(RetireDeletedEventLeafReport),
    DrainedPendingMessageLeaves(DrainPendingLeavesReport),
    ChoppedTimeTreePrefix(ChopReport),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DrainPendingLeavesReport {
    pub scanned_events: usize,
    pub derived_leaves: usize,
    pub admitted_events: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeriveReport {
    pub scanned_key_wraps: usize,
    pub derived_key_secrets: usize,
    pub failed_key_wraps: usize,
    pub admitted_events: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RotateRecipientKeyReport {
    pub old_active_recipient_keys: usize,
    pub tombstoned_recipient_keys: usize,
    pub local_recipient_key_id: Option<EventId>,
    pub recipient_key_id: Option<EventId>,
    pub admitted_events: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeriveEventLeafReport {
    pub local_history_node_secret_id: Option<EventId>,
    pub leaf_node_secret: Option<crate::core::crypto::XChaCha20Poly1305Key>,
    pub admitted_events: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetireDeletedEventLeafReport {
    pub leaf_id: Option<EventId>,
    pub admitted_events: usize,
    pub purged_event_bytes: usize,
    pub materialized_internal_rows: usize,
    /// Number of descend-path internal rows + the F root row that this retire
    /// wiped (rows exact-deleted AND canonical bytes purged AND tombstoned).
    /// Wiping these is what gives the deleted leaf its forward-secrecy
    /// property: an adversary on the device has no row whose secret descends
    /// down to the deleted leaf's coord.
    pub wiped_path_rows: usize,
    /// Number of tombstone rows the retire walk inserted into
    /// `local_history_node_tombstones`.
    pub tombstones_written: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ChopReport {
    /// Number of fully-left subtree tombstones written (one per boundary
    /// level whose floor-minute bit is 1). Bounded by the time-tree depth
    /// (at most `TIME_TREE_BIT_DEPTH` = ~63 for `TIME_TREE_ROOT_WIDTH = 2^63`).
    pub subtree_tombstones_written: usize,
    /// Number of boundary descend-path tombstones written (the chain of
    /// time-tree internals on the floor-minute boundary, plus F if F was
    /// alive at chop time). Bounded by the time-tree depth.
    pub boundary_descend_tombstones_written: usize,
    /// Number of right-side sibling rows materialized to provide cover for
    /// future authoring at minutes `>= floor_minute`. Bounded by the
    /// time-tree depth.
    pub right_side_siblings_materialized: usize,
    /// Canonical bytes purged from `event_modules.events` during the wipe
    /// phase (boundary descend rows + F root row when alive).
    pub purged_event_bytes: usize,
    /// Pre-existing per-leaf `LOCAL_HISTORY_NODE_TOMBSTONES` rows whose
    /// `(range_start + range_width) <= floor_minute` AND whose
    /// `removal_frontier_id` matches the chopped frontier — exact-deleted
    /// in the same transaction as the chop's wipe. Subsumed by the
    /// coarse subtree tombstones the chop just wrote.
    pub subsumed_leaf_tombstones_gcd: usize,
    /// Pre-existing `MESSAGE_TOMBSTONES` rows whose `authored_minute <
    /// floor_minute` — exact-deleted in the same transaction as the
    /// chop's wipe. Subsumed by the coarse subtree tombstones the chop
    /// just wrote.
    pub subsumed_message_tombstones_gcd: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RetiredRecipientKey {
    recipient_key_id: EventId,
    local_recipient_key_id: EventId,
}

pub fn run<R: EventRegistry>(store: &Store, registry: &R, work: Work) -> Result<Output, String> {
    match work {
        Work::DeriveKeySecrets { batch_size } => {
            derive_key_secrets(store, registry, batch_size).map(Output::DerivedKeySecrets)
        }
        Work::RotateRecipientKey { workspace_id } => {
            rotate_recipient_key(store, registry, workspace_id).map(Output::RotatedRecipientKey)
        }
        Work::DeriveEventLeaf {
            workspace_id,
            removal_frontier_id,
            created_at_ms,
            event_id_in_minute,
        } => derive_event_leaf(
            store,
            registry,
            workspace_id,
            removal_frontier_id,
            created_at_ms,
            event_id_in_minute,
        )
        .map(Output::DerivedEventLeaf),
        Work::RetireDeletedEventLeaf {
            workspace_id,
            removal_frontier_id,
            created_at_ms,
            event_id_in_minute,
        } => retire_deleted_event_leaf(
            store,
            registry,
            workspace_id,
            removal_frontier_id,
            created_at_ms,
            event_id_in_minute,
        )
        .map(Output::RetiredDeletedEventLeaf),
        Work::DrainPendingMessageLeaves { batch_size } => {
            drain_pending_message_leaves(store, registry, batch_size)
                .map(Output::DrainedPendingMessageLeaves)
        }
        Work::ChopTimeTreePrefix {
            workspace_id,
            removal_frontier_id,
            floor_minute,
        } => chop_time_tree_prefix(
            store,
            registry,
            workspace_id,
            removal_frontier_id,
            floor_minute,
        )
        .map(Output::ChoppedTimeTreePrefix),
    }
}

fn derive_key_secrets<R: EventRegistry>(
    store: &Store,
    registry: &R,
    batch_size: usize,
) -> Result<DeriveReport, String> {
    let mut report = DeriveReport::default();
    let mut consumed_pending = Vec::new();
    for pending in key_wrap::queries::list_pending_unwraps(store, batch_size.max(1))? {
        if report.scanned_key_wraps >= batch_size {
            break;
        }
        let Some(row) = key_wrap::queries::key_wrap_for_pending(store, &pending)? else {
            consumed_pending.push(pending.key);
            continue;
        };
        if row.key_wrap_id != pending.key_wrap_id {
            report.failed_key_wraps += 1;
            continue;
        }
        report.scanned_key_wraps += 1;
        if local_key_secret::queries::get(store, row.workspace_id, row.removal_frontier_id)?
            .is_some()
        {
            consumed_pending.push(pending.key);
            continue;
        }
        let Some(recipient) = recipient_key_row(store, row.workspace_id, row.recipient_key_id)?
        else {
            continue;
        };
        let Some(local_recipient) =
            local_recipient_key::queries::list_for_workspace(store, row.workspace_id)?
                .into_iter()
                .find(|candidate| candidate.recipient_key == recipient.recipient_key)
        else {
            continue;
        };

        let key_wrap_event = key_wrap_event_from_row(&row);
        let plaintext = match crypto::x25519_xchacha20poly1305_decrypt(
            &local_recipient.recipient_secret,
            &row.sender_wrap_public_key,
            key_wrap::codec::KEY_WRAP_PURPOSE,
            &key_wrap::codec::associated_data(&key_wrap_event, row.signer_endpoint_shared_id),
            &row.nonce,
            &row.ciphertext,
        ) {
            Ok(plaintext) => plaintext,
            Err(_) => {
                report.failed_key_wraps += 1;
                continue;
            }
        };
        let key_secret = match plaintext.try_into() {
            Ok(secret) => secret,
            Err(_) => {
                report.failed_key_wraps += 1;
                continue;
            }
        };
        let output = local_key_secret::commands::from_key_secret(
            row.workspace_id,
            row.removal_frontier_id,
            key_secret,
        )?;
        if output.value.local_key_secret_id != row.local_key_secret_id {
            report.failed_key_wraps += 1;
            continue;
        }

        let admitted = worker::run(
            store,
            registry,
            worker::AdmitAndDrain {
                output,
                batch_size: worker::DEFAULT_READY_BATCH,
            },
        )
        .map_err(|err| format!("admit local key secret: {err}"))?;
        if admitted.admitted.inserted_events > 0 {
            report.derived_key_secrets += 1;
        }
        report.admitted_events += admitted.admitted.inserted_events;
        consumed_pending.push(pending.key);
    }
    if !consumed_pending.is_empty() {
        store
            .delete_table_rows(key_wrap::schema::PENDING_KEY_UNWRAPS, consumed_pending)
            .map_err(|err| format!("delete pending key unwraps: {err}"))?;
    }
    Ok(report)
}

fn rotate_recipient_key<R: EventRegistry>(
    store: &Store,
    registry: &R,
    workspace_id: EventId,
) -> Result<RotateRecipientKeyReport, String> {
    let membership = local_membership(store, workspace_id)?;
    let local = endpoint::commands::local_keypair(store)?
        .ok_or_else(|| "local endpoint is missing".to_string())?;
    if membership.signing_public_key != local.signing_public_key {
        return Err("local endpoint signing key does not match workspace membership".to_string());
    }
    if !membership.endpoint_role.can_receive_key_wraps() {
        return Err("local endpoint role cannot receive key wraps".to_string());
    }
    let old_active =
        active_local_recipient_keys(store, workspace_id, membership.endpoint_shared_id)?;
    let mut report = RotateRecipientKeyReport {
        old_active_recipient_keys: old_active.len(),
        ..RotateRecipientKeyReport::default()
    };

    let local_output = local_recipient_key::commands::create(workspace_id)?;
    let local_recipient_key_id = local_output.events[0].event_id();
    let local_public_key = local_output.value.recipient_key;
    let admitted = worker::run(
        store,
        registry,
        worker::AdmitAndDrain {
            output: local_output,
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("admit rotated local recipient key: {err}"))?;
    report.admitted_events += admitted.admitted.inserted_events;
    report.local_recipient_key_id = Some(local_recipient_key_id);

    let recipient_output =
        recipient_key::commands::publish(recipient_key::commands::PublishRecipientKey {
            workspace_id,
            created_at_ms: next_timestamp(store)?,
            endpoint_shared_id: membership.endpoint_shared_id,
            signer_private_key: local.signing_secret,
            recipient_key: local_public_key,
        })?;
    let new_recipient_key_id = recipient_output.value.recipient_key_id;
    let admitted = worker::run(
        store,
        registry,
        worker::AdmitAndDrain {
            output: recipient_output,
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("admit rotated recipient key: {err}"))?;
    report.admitted_events += admitted.admitted.inserted_events;
    report.recipient_key_id = Some(new_recipient_key_id);

    let mut retired = Vec::with_capacity(old_active.len());
    for old_key in &old_active {
        let tombstone = recipient_key_tombstone::commands::tombstone(
            recipient_key_tombstone::commands::TombstoneRecipientKey {
                workspace_id,
                created_at_ms: next_timestamp(store)?,
                endpoint_shared_id: membership.endpoint_shared_id,
                signer_private_key: local.signing_secret,
                old_recipient_key_id: old_key.recipient_key_id,
                new_recipient_key_id,
            },
        )?;
        let admitted = worker::run(
            store,
            registry,
            worker::AdmitAndDrain {
                output: tombstone,
                batch_size: worker::DEFAULT_READY_BATCH,
            },
        )
        .map_err(|err| format!("admit recipient key tombstone: {err}"))?;
        if admitted.admitted.inserted_events > 0 {
            report.tombstoned_recipient_keys += 1;
        }
        report.admitted_events += admitted.admitted.inserted_events;
        retired.push(*old_key);
    }

    purge_retired_recipient_material(store, workspace_id, &retired)
        .map_err(|err| format!("purge retired recipient material: {err}"))?;

    Ok(report)
}

/// Source-of-derivation node — either the workspace frontier root (which
/// implicitly covers the whole time axis at `range_width = TIME_TREE_ROOT_WIDTH`)
/// or a materialized history node row.
#[derive(Debug, Clone)]
struct DerivationSource {
    secret_id: EventId,
    secret: HistoryNodeSecret,
    range_start: u64,
    range_width: u64,
    bit_depth: u16,
    event_id_prefix: EventId,
}

/// Look up the workspace's `local_key_secret(F)` row and present it as a
/// `DerivationSource`. Returns `None` when the row has been wiped (e.g. by
/// a prior `retire_deleted_event_leaf`); callers must then fall back to
/// the deepest covering sibling row.
fn try_root_source(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
) -> Result<Option<DerivationSource>, String> {
    let Some(root) = local_key_secret::queries::get(store, workspace_id, removal_frontier_id)?
    else {
        return Ok(None);
    };
    Ok(Some(DerivationSource {
        secret_id: root.local_key_secret_id,
        secret: root.key_secret,
        range_start: 0,
        range_width: TIME_TREE_ROOT_WIDTH,
        bit_depth: TIME_TREE_BIT_DEPTH,
        event_id_prefix: [0; 32],
    }))
}

/// Compute (in memory, not stored) the next time-split secret along the path
/// to `target_minute`, given a parent that covers `target_minute`.
fn time_split_step(
    workspace_id: EventId,
    removal_frontier_id: EventId,
    parent: &DerivationSource,
    target_minute: u64,
) -> Result<(u64, u64, u8, HistoryNodeSecret), String> {
    let half = parent.range_width / 2;
    if half == 0 {
        return Err("time tree cannot split below range_width=1".to_string());
    }
    let mid = parent.range_start + half;
    let (child_side, child_start, child_width) = if target_minute < mid {
        (0u8, parent.range_start, half)
    } else {
        (1u8, mid, half)
    };
    let info = time_split_info(
        parent.range_start,
        parent.range_width,
        child_side,
        child_start,
        child_width,
    );
    let secret = crypto::blake3_keyed_hash(
        &parent.secret,
        local_history_node_secret::commands::TIME_SPLIT_DOMAIN,
        &info,
    );
    let _ = (workspace_id, removal_frontier_id);
    Ok((child_start, child_width, child_side, secret))
}

fn time_split_info(
    parent_range_start: u64,
    parent_range_width: u64,
    child_side: u8,
    child_range_start: u64,
    child_range_width: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 8 + 1 + 8 + 8);
    out.extend_from_slice(&parent_range_start.to_be_bytes());
    out.extend_from_slice(&parent_range_width.to_be_bytes());
    out.push(child_side);
    out.extend_from_slice(&child_range_start.to_be_bytes());
    out.extend_from_slice(&child_range_width.to_be_bytes());
    out
}

fn trie_split_info(
    parent_bit_depth: u16,
    parent_event_id_prefix: EventId,
    child_side: u8,
    child_bit_depth: u16,
    child_event_id_prefix: EventId,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 32 + 1 + 2 + 32);
    out.extend_from_slice(&parent_bit_depth.to_be_bytes());
    out.extend_from_slice(&mask_prefix_to_depth(
        parent_event_id_prefix,
        parent_bit_depth,
    ));
    out.push(child_side);
    out.extend_from_slice(&child_bit_depth.to_be_bytes());
    out.extend_from_slice(&mask_prefix_to_depth(
        child_event_id_prefix,
        child_bit_depth,
    ));
    out
}

/// Walk in-memory from `root` (the closest retained ancestor) down to the
/// minute_node at `target_minute`. Returns the in-memory `DerivationSource`
/// for the minute_node — its secret is the parent of the trie.
fn descend_time_axis_in_memory(
    workspace_id: EventId,
    removal_frontier_id: EventId,
    root: &DerivationSource,
    target_minute: u64,
) -> Result<DerivationSource, String> {
    let mut current = root.clone();
    while current.range_width > 1 {
        let (child_start, child_width, child_side, secret) =
            time_split_step(workspace_id, removal_frontier_id, &current, target_minute)?;
        current = DerivationSource {
            secret_id: current.secret_id, // virtual parent id chain; unused for in-memory walk
            secret,
            range_start: child_start,
            range_width: child_width,
            bit_depth: TIME_TREE_BIT_DEPTH,
            event_id_prefix: [0; 32],
        };
        let _ = child_side;
    }
    Ok(current)
}

/// Find the closest retained ancestor that covers
/// `(unix_minute, 1, TRIE_LEAF_BIT_DEPTH, event_id_in_minute)`. The starting
/// candidate is the frontier root's `DerivationSource` when its row is
/// present; if F's row has been wiped (post-retire), the scan starts with
/// no candidate and picks the deepest covering sibling row admitted by
/// an earlier retire walk. The retire walk's time-tree siblings
/// collectively cover every minute except the wiped one, so any coord
/// in a different minute has a covering ancestor; for a coord in the
/// same minute as a prior retirement, coverage depends on whether a
/// surviving trie sibling shares the coord's prefix.
///
/// Errors only when no covering ancestor exists at all (a genuine
/// wedge — either F has never been seeded, or the target lies inside
/// a wiped subtree that no sibling covers).
fn closest_retained_ancestor(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    unix_minute: u64,
    event_id_in_minute: EventId,
) -> Result<DerivationSource, String> {
    let mut best: Option<DerivationSource> =
        try_root_source(store, workspace_id, removal_frontier_id)?;
    for row in local_history_node_secret::queries::list_for_frontier(
        store,
        workspace_id,
        removal_frontier_id,
    )? {
        if !covers(&row, unix_minute, event_id_in_minute) {
            continue;
        }
        let take = match best.as_ref() {
            None => true,
            Some(current) => more_specific_than(&row, current),
        };
        if take {
            best = Some(DerivationSource {
                secret_id: row.local_history_node_secret_id,
                secret: row.node_secret,
                range_start: row.range_start,
                range_width: row.range_width,
                bit_depth: row.bit_depth,
                event_id_prefix: row.event_id_prefix,
            });
        }
    }
    best.ok_or_else(|| {
        "no retained ancestor covers the target leaf: F is wiped and no \
         sibling row covers this coordinate"
            .to_string()
    })
}

fn covers(
    row: &local_history_node_secret::types::LocalHistoryNodeSecretRow,
    unix_minute: u64,
    event_id_in_minute: EventId,
) -> bool {
    // Time-axis containment.
    let row_end = row.range_start.saturating_add(row.range_width);
    if unix_minute < row.range_start || unix_minute >= row_end {
        return false;
    }
    // Trie containment.
    if row.bit_depth == TIME_TREE_BIT_DEPTH {
        return true;
    }
    if row.bit_depth >= TRIE_LEAF_BIT_DEPTH {
        return row.event_id_prefix == event_id_in_minute;
    }
    let masked = mask_prefix_to_depth(event_id_in_minute, row.bit_depth);
    masked == row.event_id_prefix
}

/// Returns true when `row` is more specific (strictly closer to the leaf)
/// than `current`. Specificity ranks first by smaller `range_width`, then
/// by larger `bit_depth`.
fn more_specific_than(
    row: &local_history_node_secret::types::LocalHistoryNodeSecretRow,
    current: &DerivationSource,
) -> bool {
    if row.range_width < current.range_width {
        return true;
    }
    if row.range_width > current.range_width {
        return false;
    }
    row.bit_depth > current.bit_depth
}

/// Walk from the closest retained ancestor down to the leaf row for
/// `(unix_minute, event_id_in_minute)`. If the leaf row already exists,
/// return it; otherwise materialize ONLY the leaf row (the path stays
/// implicit) and return it. AEAD operations call this so the AEAD path is a
/// single row read.
fn derive_event_leaf<R: EventRegistry>(
    store: &Store,
    registry: &R,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    created_at_ms: u64,
    event_id_in_minute: EventId,
) -> Result<DeriveEventLeafReport, String> {
    if event_id_in_minute.iter().all(|byte| *byte == 0) {
        return Err("derive_event_leaf requires non-zero event_id_in_minute".to_string());
    }
    let unix_minute =
        crate::protocol::event_modules::content::message::types::unix_minute_for(created_at_ms);

    if let Some(existing) = local_history_node_secret::queries::get_leaf(
        store,
        workspace_id,
        removal_frontier_id,
        unix_minute,
        event_id_in_minute,
    )? {
        return Ok(DeriveEventLeafReport {
            local_history_node_secret_id: Some(existing.local_history_node_secret_id),
            leaf_node_secret: Some(existing.node_secret),
            admitted_events: 0,
        });
    }

    let ancestor = closest_retained_ancestor(
        store,
        workspace_id,
        removal_frontier_id,
        unix_minute,
        event_id_in_minute,
    )?;
    let minute_node = if ancestor.range_width == 1 {
        ancestor
    } else {
        descend_time_axis_in_memory(workspace_id, removal_frontier_id, &ancestor, unix_minute)?
    };
    if minute_node.range_start != unix_minute || minute_node.range_width != 1 {
        return Err("time-axis descent did not reach the target minute_node".to_string());
    }
    // From minute_node (bit_depth = 0) to leaf (bit_depth = 256) in one trie
    // split. The minute_node may itself be implicit; for implicit cases we
    // need a stable `source_secret_id` for the leaf row. Use the closest
    // materialized ancestor row id as the source for the leaf event so the
    // leaf's dependency chain is real.
    //
    // NOTE: we MUST descend fully through the trie when an intermediate
    // trie internal exists (e.g. after a delete materialized siblings). The
    // closest_retained_ancestor walk already accounts for this by returning
    // a deeper ancestor; the descent below from `minute_node` to the leaf
    // simply follows the bits past whatever depth the ancestor sits at.
    let mut current = minute_node.clone();
    if current.bit_depth < TRIE_LEAF_BIT_DEPTH {
        // Walk in-memory through any further materialized trie internals.
        // Each step looks up a row at the next-deeper materialized depth on
        // the side dictated by `event_id_in_minute`. If no more rows lie on
        // the path, the loop terminates and we fall through to the final
        // single-shot derivation to depth 256.
        loop {
            let Some(next_row) = next_materialized_trie_step(
                store,
                workspace_id,
                removal_frontier_id,
                unix_minute,
                &current,
                event_id_in_minute,
            )?
            else {
                break;
            };
            current = DerivationSource {
                secret_id: next_row.local_history_node_secret_id,
                secret: next_row.node_secret,
                range_start: next_row.range_start,
                range_width: next_row.range_width,
                bit_depth: next_row.bit_depth,
                event_id_prefix: next_row.event_id_prefix,
            };
            if current.bit_depth >= TRIE_LEAF_BIT_DEPTH {
                break;
            }
        }
    }

    let leaf_secret = if current.bit_depth >= TRIE_LEAF_BIT_DEPTH {
        // Already at the leaf (only possible if the closest ancestor was the
        // leaf itself, but we returned early above for that case).
        current.secret
    } else {
        let child_side = bit_at(&event_id_in_minute, current.bit_depth);
        let info = trie_split_info(
            current.bit_depth,
            current.event_id_prefix,
            child_side,
            TRIE_LEAF_BIT_DEPTH,
            event_id_in_minute,
        );
        crypto::blake3_keyed_hash(
            &current.secret,
            local_history_node_secret::commands::TRIE_SPLIT_DOMAIN,
            &info,
        )
    };
    // Materialize the leaf row through the projector, sourced from the
    // closest *materialized* ancestor (so the dependency edge is real). The
    // leaf row carries its own `node_secret` so subsequent encryptions are
    // single-row reads.
    let materialization_source = closest_materialized_source(
        store,
        workspace_id,
        removal_frontier_id,
        unix_minute,
        event_id_in_minute,
    )?;
    let admitted = admit_leaf_with_source(
        store,
        registry,
        workspace_id,
        removal_frontier_id,
        unix_minute,
        event_id_in_minute,
        leaf_secret,
        materialization_source,
    )?;
    Ok(DeriveEventLeafReport {
        local_history_node_secret_id: Some(admitted.event_id),
        leaf_node_secret: Some(leaf_secret),
        admitted_events: admitted.admitted_events,
    })
}

struct AdmittedLeaf {
    event_id: EventId,
    admitted_events: usize,
}

/// Admit a `local_history_node_secret` event for the leaf with a fixed
/// `node_secret` (so the leaf row carries the AEAD key already derived from
/// in-memory trie descent). The admission produces a normal local event
/// whose `source_secret_id` references the closest materialized ancestor.
///
/// To stay schema-clean we synthesize the leaf event by replaying the
/// minimum trie split chain from the materialized ancestor: we go from
/// `(ancestor_bit_depth, ancestor_prefix)` straight to
/// `(TRIE_LEAF_BIT_DEPTH, event_id_in_minute)`. Patricia compression makes
/// this a single split. The KDF info encodes the depth jump explicitly.
fn admit_leaf_with_source<R: EventRegistry>(
    store: &Store,
    registry: &R,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    unix_minute: u64,
    event_id_in_minute: EventId,
    expected_secret: HistoryNodeSecret,
    source: MaterializedSource,
) -> Result<AdmittedLeaf, String> {
    let split = if source.is_root {
        // Fresh encryption with no deletes in the region: short-circuit
        // straight from the workspace `local_key_secret` to the leaf with
        // a single bundled derivation that walks time + trie internally.
        // No intermediate rows are materialized; the leaf row is the only
        // new row admitted. AEAD decoding is then a single row read.
        let output = local_history_node_secret::commands::derive_event_leaf_from_root(
            local_history_node_secret::commands::DeriveEventLeafFromRoot {
                workspace_id,
                removal_frontier_id,
                root_secret_id: source.secret_id,
                root_secret: source.secret,
                unix_minute,
                event_id_in_minute,
            },
        )?;
        if output.value.event.node_secret != expected_secret {
            return Err(
                "leaf secret mismatch between in-memory walk and admitted root-fast-path event"
                    .to_string(),
            );
        }
        let event_id = output.value.local_history_node_secret_id;
        let admitted = worker::run(
            store,
            registry,
            worker::AdmitAndDrain {
                output,
                batch_size: worker::DEFAULT_READY_BATCH,
            },
        )
        .map_err(|err| format!("admit local history node secret leaf (root fast path): {err}"))?;
        AdmittedLeaf {
            event_id,
            admitted_events: admitted.admitted.inserted_events,
        }
    } else if source.range_width == 1 && source.bit_depth < TRIE_LEAF_BIT_DEPTH {
        // Trie split from materialized internal directly to leaf.
        admit_single_trie_leaf_split(
            store,
            registry,
            workspace_id,
            removal_frontier_id,
            unix_minute,
            event_id_in_minute,
            &source,
            expected_secret,
        )?
    } else if source.range_width == 1 && source.bit_depth >= TRIE_LEAF_BIT_DEPTH {
        return Err(
            "closest materialized ancestor is already the leaf; expected lookup short-circuit"
                .to_string(),
        );
    } else {
        // Materialized time-tree internal (range_width > 1, bit_depth = 0).
        // Walk the rest of the time tree (publishing each split) then take
        // the trie leaf split. This is the post-delete path where some
        // time-internal has been materialized as a sibling cover.
        admit_time_path_then_leaf(
            store,
            registry,
            workspace_id,
            removal_frontier_id,
            event_id_in_minute,
            unix_minute,
            &source,
            expected_secret,
        )?
    };
    Ok(split)
}

fn admit_single_trie_leaf_split<R: EventRegistry>(
    store: &Store,
    registry: &R,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    unix_minute: u64,
    event_id_in_minute: EventId,
    source: &MaterializedSource,
    expected_secret: HistoryNodeSecret,
) -> Result<AdmittedLeaf, String> {
    let child_side = bit_at(&event_id_in_minute, source.bit_depth);
    let output = local_history_node_secret::commands::derive_trie_split(
        local_history_node_secret::commands::DeriveTrieSplit {
            workspace_id,
            removal_frontier_id,
            parent_secret_id: source.secret_id,
            parent_secret: source.secret,
            range_start: unix_minute,
            parent_bit_depth: source.bit_depth,
            parent_event_id_prefix: source.event_id_prefix,
            child_side,
            child_bit_depth: TRIE_LEAF_BIT_DEPTH,
            child_event_id_prefix: event_id_in_minute,
            tombstone_node_id: None,
        },
    )?;
    if output.value.event.node_secret != expected_secret {
        return Err("leaf secret mismatch between in-memory walk and admitted event".to_string());
    }
    let event_id = output.value.local_history_node_secret_id;
    let admitted = worker::run(
        store,
        registry,
        worker::AdmitAndDrain {
            output,
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("admit local history node secret leaf: {err}"))?;
    Ok(AdmittedLeaf {
        event_id,
        admitted_events: admitted.admitted.inserted_events,
    })
}

/// Walk down the time tree from `source` to the minute_node at
/// `unix_minute` AND admit each split as a real event so subsequent calls
/// can short-circuit to a closer ancestor. Then take a single trie split
/// from the minute_node directly to the leaf.
///
/// This admits one row per time-tree level on the descending path PLUS the
/// minute_node row PLUS the leaf row. Subsequent calls in the same minute
/// short-circuit at the minute_node lookup and only admit one new leaf.
fn admit_time_path_then_leaf<R: EventRegistry>(
    store: &Store,
    registry: &R,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    event_id_in_minute: EventId,
    unix_minute: u64,
    source: &MaterializedSource,
    expected_secret: HistoryNodeSecret,
) -> Result<AdmittedLeaf, String> {
    let mut current = DerivationSource {
        secret_id: source.secret_id,
        secret: source.secret,
        range_start: source.range_start,
        range_width: source.range_width,
        bit_depth: source.bit_depth,
        event_id_prefix: source.event_id_prefix,
    };
    // Use the implicit root width when source is the frontier root.
    if source.is_root {
        current.range_start = 0;
        current.range_width = TIME_TREE_ROOT_WIDTH;
        current.bit_depth = TIME_TREE_BIT_DEPTH;
        current.event_id_prefix = [0; 32];
    }
    let mut admitted_events = 0usize;
    while current.range_width > 1 {
        // Skip if the next minute_node row for this minute already exists
        // (some other concurrent path built it). Look up by full coordinate.
        if let Some(existing) = local_history_node_secret::queries::get_minute_node(
            store,
            workspace_id,
            removal_frontier_id,
            unix_minute,
        )? {
            current = DerivationSource {
                secret_id: existing.local_history_node_secret_id,
                secret: existing.node_secret,
                range_start: existing.range_start,
                range_width: existing.range_width,
                bit_depth: existing.bit_depth,
                event_id_prefix: existing.event_id_prefix,
            };
            break;
        }
        let half = current.range_width / 2;
        let mid = current.range_start + half;
        let (child_side, child_start) = if unix_minute < mid {
            (0u8, current.range_start)
        } else {
            (1u8, mid)
        };
        let parent_range_start = current.range_start;
        let parent_range_width = current.range_width;
        let output = local_history_node_secret::commands::derive_time_split(
            local_history_node_secret::commands::DeriveTimeSplit {
                workspace_id,
                removal_frontier_id,
                parent_secret_id: current.secret_id,
                parent_secret: current.secret,
                parent_range_start,
                parent_range_width,
                child_side,
                child_range_start: child_start,
                child_range_width: half,
                tombstone_node_id: None,
            },
        )?;
        let admitted = worker::run(
            store,
            registry,
            worker::AdmitAndDrain {
                output: output.clone(),
                batch_size: worker::DEFAULT_READY_BATCH,
            },
        )
        .map_err(|err| format!("admit local history node time-split: {err}"))?;
        admitted_events += admitted.admitted.inserted_events;
        current = DerivationSource {
            secret_id: output.value.local_history_node_secret_id,
            secret: output.value.event.node_secret,
            range_start: child_start,
            range_width: half,
            bit_depth: TIME_TREE_BIT_DEPTH,
            event_id_prefix: [0; 32],
        };
    }
    if current.range_start != unix_minute || current.range_width != 1 {
        return Err("time descent did not reach target minute_node".to_string());
    }
    // current is now the minute_node. Admit the leaf via a single trie split.
    let leaf_source = MaterializedSource {
        secret_id: current.secret_id,
        secret: current.secret,
        range_start: current.range_start,
        range_width: 1,
        bit_depth: TIME_TREE_BIT_DEPTH,
        event_id_prefix: [0; 32],
        is_root: false,
    };
    let leaf = admit_single_trie_leaf_split(
        store,
        registry,
        workspace_id,
        removal_frontier_id,
        unix_minute,
        event_id_in_minute,
        &leaf_source,
        expected_secret,
    )?;
    Ok(AdmittedLeaf {
        event_id: leaf.event_id,
        admitted_events: admitted_events + leaf.admitted_events,
    })
}

#[derive(Debug, Clone)]
struct MaterializedSource {
    secret_id: EventId,
    secret: HistoryNodeSecret,
    range_start: u64,
    range_width: u64,
    bit_depth: u16,
    event_id_prefix: EventId,
    /// True iff this source is the frontier root (`local_key_secret`),
    /// implicitly covering `(0, TIME_TREE_ROOT_WIDTH)`.
    is_root: bool,
}

fn closest_materialized_source(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    unix_minute: u64,
    event_id_in_minute: EventId,
) -> Result<MaterializedSource, String> {
    // Start with the F root row when present. If F has been wiped, start
    // with no candidate and let the sibling scan below pick the deepest
    // covering sibling — the same fallback as `closest_retained_ancestor`.
    let mut best: Option<MaterializedSource> = local_key_secret::queries::get(
        store,
        workspace_id,
        removal_frontier_id,
    )?
    .map(|root| MaterializedSource {
        secret_id: root.local_key_secret_id,
        secret: root.key_secret,
        range_start: 0,
        range_width: TIME_TREE_ROOT_WIDTH,
        bit_depth: TIME_TREE_BIT_DEPTH,
        event_id_prefix: [0; 32],
        is_root: true,
    });
    for row in local_history_node_secret::queries::list_for_frontier(
        store,
        workspace_id,
        removal_frontier_id,
    )? {
        if !covers(&row, unix_minute, event_id_in_minute) {
            continue;
        }
        let candidate = MaterializedSource {
            secret_id: row.local_history_node_secret_id,
            secret: row.node_secret,
            range_start: row.range_start,
            range_width: row.range_width,
            bit_depth: row.bit_depth,
            event_id_prefix: row.event_id_prefix,
            is_root: false,
        };
        let better = match best.as_ref() {
            None => true,
            Some(current) if current.is_root => true,
            Some(current) if candidate.range_width < current.range_width => true,
            Some(current) if candidate.range_width > current.range_width => false,
            Some(current) => candidate.bit_depth > current.bit_depth,
        };
        if better {
            best = Some(candidate);
        }
    }
    best.ok_or_else(|| {
        "no materialized source covers the target leaf: F is wiped and no \
         sibling row covers this coordinate"
            .to_string()
    })
}

fn next_materialized_trie_step(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    unix_minute: u64,
    current: &DerivationSource,
    event_id_in_minute: EventId,
) -> Result<Option<local_history_node_secret::types::LocalHistoryNodeSecretRow>, String> {
    // Look at all trie rows in this minute and pick the closest descendant
    // of `current` along the path of `event_id_in_minute`.
    let rows = local_history_node_secret::queries::list_for_frontier(
        store,
        workspace_id,
        removal_frontier_id,
    )?;
    let mut best: Option<local_history_node_secret::types::LocalHistoryNodeSecretRow> = None;
    for row in rows {
        if row.range_start != unix_minute || row.range_width != 1 {
            continue;
        }
        if row.bit_depth <= current.bit_depth {
            continue;
        }
        if row.bit_depth > TRIE_LEAF_BIT_DEPTH {
            continue;
        }
        if !trie_extends(current, &row, event_id_in_minute) {
            continue;
        }
        match &best {
            Some(existing) if existing.bit_depth >= row.bit_depth => {}
            _ => best = Some(row),
        }
    }
    Ok(best)
}

fn trie_extends(
    parent: &DerivationSource,
    row: &local_history_node_secret::types::LocalHistoryNodeSecretRow,
    event_id_in_minute: EventId,
) -> bool {
    // The row must continue the trie path of `event_id_in_minute` past the
    // parent's depth. Concretely: the row's prefix must agree with
    // `event_id_in_minute` up to `row.bit_depth`, and with `parent.event_id_prefix`
    // up to `parent.bit_depth`.
    if mask_prefix_to_depth(event_id_in_minute, row.bit_depth) != row.event_id_prefix {
        return false;
    }
    if mask_prefix_to_depth(row.event_id_prefix, parent.bit_depth) != parent.event_id_prefix {
        return false;
    }
    true
}

/// Coordinates of one node-secret row that the retire walk wipes after the
/// walk completes. The walk admits both descending-side and sibling-side
/// internals so the projector's source-dependency invariant holds, then
/// goes back and exact-deletes every row that lies on the path to the
/// deleted leaf (including the F root) — leaving only the sibling rows.
#[derive(Debug, Clone)]
struct WipeTarget {
    event_id: EventId,
    range_start: u64,
    range_width: u64,
    bit_depth: u16,
    event_id_prefix: EventId,
    /// True iff this row is the workspace `local_key_secret(F)` row, which
    /// lives in `LOCAL_KEY_SECRETS` (one row per workspace + frontier),
    /// not in `LOCAL_HISTORY_NODE_SECRETS`.
    is_frontier_root: bool,
}

/// Retire one event's leaf so its `node_secret` can no longer be derived
/// from any retained row in the workspace.
///
/// Algorithm (forward-secrecy walk):
///
/// 1. If the leaf row is missing, no-op (idempotent).
/// 2. Walk the time tree from the workspace `local_key_secret(F)` root down
///    to the target minute_node. At each split, admit both the descending
///    child and the sibling child as ordinary `local_history_node_secret`
///    events so the chain has real source dependencies.
/// 3. Walk the trie from the minute_node down toward the leaf, splitting at
///    every depth where the deleted leaf's coord diverges from a surviving
///    leaf's coord. At each divergence, admit both descend and sibling.
/// 4. Wipe phase: exact-delete every descending-side row (rows on the path
///    from F root to the leaf) AND the F root row itself, purging their
///    canonical bytes from `event_modules.events` and writing tombstone
///    rows into `local_history_node_tombstones`. Only sibling rows
///    (off-path covers) and unrelated rows survive.
/// 5. Exact-delete the leaf row, purge its canonical bytes, write a
///    tombstone for the leaf.
///
/// After step 5 no retained row can re-derive the deleted leaf's
/// `node_secret`: the descending chain that produced it has been
/// exact-deleted, and BLAKE3 keyed-hash is one-way so siblings cannot
/// reach the deleted leaf's coord.
///
/// Future encryption under `F` keeps working without an explicit
/// frontier advance: the time-tree siblings admitted at step 2
/// collectively cover every minute except the wiped one, so
/// `closest_retained_ancestor` for a coord in any other minute
/// returns the deepest covering time-axis sibling and
/// `derive_event_leaf` walks down from there. (Same-minute new
/// authoring works only when the coord's prefix lies under a
/// surviving trie sibling admitted at step 3; coords whose prefix was
/// inside the wiped descend chain legitimately wedge.) Each peer
/// derives the same sibling secrets locally because the KDF is
/// deterministic, so no new wraps to recipients are required.
/// Rotation via `key-frontier` can still happen for unrelated reasons
/// (recipient turnover); it is not required by retirement.
///
/// TODO(disappearing-messages): whole-minute retirement is a separate
/// future flow. The time-tree shape supports it: walk the time tree, split
/// as needed so the expired range is covered by a small set of internal
/// nodes, then tombstone those internals (one tombstone per covering node,
/// not one per minute). The current implementation only handles per-event
/// leaf retirement; whole-minute (or whole-range) retirement will land
/// later behind a separate `Work` variant.
fn retire_deleted_event_leaf<R: EventRegistry>(
    store: &Store,
    registry: &R,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    created_at_ms: u64,
    event_id_in_minute: EventId,
) -> Result<RetireDeletedEventLeafReport, String> {
    let unix_minute =
        crate::protocol::event_modules::content::message::types::unix_minute_for(created_at_ms);
    let leaf_row = local_history_node_secret::queries::get_leaf(
        store,
        workspace_id,
        removal_frontier_id,
        unix_minute,
        event_id_in_minute,
    )?;
    let leaf_id = leaf_row
        .as_ref()
        .map(|row| row.local_history_node_secret_id);

    let mut report = RetireDeletedEventLeafReport {
        leaf_id,
        ..RetireDeletedEventLeafReport::default()
    };

    if leaf_id.is_none() {
        return Ok(report);
    }
    let leaf_id = leaf_id.expect("checked above");

    // Look up the F root row. If it's already wiped (a prior retire wiped
    // it), we still need to exact-delete this leaf row, purge its bytes,
    // and tombstone it — but there is no walk to perform.
    let frontier_root =
        local_key_secret::queries::get(store, workspace_id, removal_frontier_id)?;
    let mut path_rows_to_wipe: Vec<WipeTarget> = Vec::new();
    if let Some(root_row) = frontier_root {
        // Step 2: walk the time tree, materializing both descend and sibling
        // children at each split. Track the descend-side rows so we can wipe
        // them after the walk finishes.
        let mut current_secret_id = root_row.local_key_secret_id;
        let mut current_secret = root_row.key_secret;
        let mut current_range_start: u64 = 0;
        let mut current_range_width: u64 = TIME_TREE_ROOT_WIDTH;
        // F root is on the descend path by definition.
        path_rows_to_wipe.push(WipeTarget {
            event_id: root_row.local_key_secret_id,
            range_start: 0,
            range_width: TIME_TREE_ROOT_WIDTH,
            bit_depth: TIME_TREE_BIT_DEPTH,
            event_id_prefix: [0; 32],
            is_frontier_root: true,
        });
        while current_range_width > 1 {
            let half = current_range_width / 2;
            let mid = current_range_start + half;
            let (descend_side, descend_start, sibling_side, sibling_start) = if unix_minute < mid {
                (0u8, current_range_start, 1u8, mid)
            } else {
                (1u8, mid, 0u8, current_range_start)
            };

            // Admit descending child (real event) so the projector's
            // source-dependency chain holds for downstream siblings. We will
            // wipe this row in the final step.
            let descend = ensure_time_split(
                store,
                registry,
                workspace_id,
                removal_frontier_id,
                current_secret_id,
                current_secret,
                current_range_start,
                current_range_width,
                descend_side,
                descend_start,
                half,
            )?;
            report.admitted_events += descend.admitted_events;
            if descend.materialized_new_row {
                report.materialized_internal_rows += 1;
            }
            path_rows_to_wipe.push(WipeTarget {
                event_id: descend.row_event_id,
                range_start: descend_start,
                range_width: half,
                bit_depth: TIME_TREE_BIT_DEPTH,
                event_id_prefix: [0; 32],
                is_frontier_root: false,
            });

            // Admit sibling child. Skip the final sibling-at-width-1 (an
            // adjacent minute_node) — adjacent minutes have no events to
            // cover and their internal coverage is implicit under the
            // (now-wiped) width-2 parent. Siblings at width >= 2 cover real
            // surviving subtrees and must be materialized.
            if half > 1 {
                let sibling = ensure_time_split(
                    store,
                    registry,
                    workspace_id,
                    removal_frontier_id,
                    current_secret_id,
                    current_secret,
                    current_range_start,
                    current_range_width,
                    sibling_side,
                    sibling_start,
                    half,
                )?;
                report.admitted_events += sibling.admitted_events;
                if sibling.materialized_new_row {
                    report.materialized_internal_rows += 1;
                }
            }
            let _ = (sibling_side, sibling_start);

            current_secret_id = descend.row_event_id;
            current_secret = descend.row_secret;
            current_range_start = descend_start;
            current_range_width = half;
        }
        if current_range_start != unix_minute || current_range_width != 1 {
            return Err("retire walk did not reach the target minute_node".to_string());
        }
        // Step 3: walk the trie. The minute_node's id+secret are
        // current_secret_id+current_secret.
        walk_trie_for_retire(
            store,
            registry,
            workspace_id,
            removal_frontier_id,
            unix_minute,
            event_id_in_minute,
            current_secret_id,
            current_secret,
            &mut path_rows_to_wipe,
            &mut report,
        )?;
    }

    // Step 4 + 5: wipe phase. In one transaction, exact-delete every
    // descend-path row (including F root), purge their canonical bytes,
    // tombstone them, then exact-delete the leaf row, purge its bytes, and
    // tombstone it. Doing this in one transaction guarantees the
    // forward-secrecy invariant: at no point on disk do we have BOTH the
    // descend-path rows AND a missing leaf row that an attacker could
    // exploit.
    let leaf_secret_key = local_history_node_secret::schema::local_history_node_secret_key(
        workspace_id,
        removal_frontier_id,
        unix_minute,
        1,
        TRIE_LEAF_BIT_DEPTH,
        event_id_in_minute,
    );
    let path_clone = path_rows_to_wipe.clone();
    let (wiped_path_rows, tombstones_written, purged_event_bytes) = store
        .write_transaction(move |store| {
            let mut wiped: usize = 0;
            let mut tombstones: usize = 0;
            let mut purged: usize = 0;
            for target in &path_clone {
                if target.is_frontier_root {
                    let key = local_key_secret::schema::local_key_secret_key(
                        workspace_id,
                        removal_frontier_id,
                    );
                    if store
                        .delete_table_rows_in_tx(
                            local_key_secret::schema::LOCAL_KEY_SECRETS,
                            vec![key],
                        )?
                        > 0
                    {
                        wiped += 1;
                    }
                } else {
                    let key = local_history_node_secret::schema::local_history_node_secret_key(
                        workspace_id,
                        removal_frontier_id,
                        target.range_start,
                        target.range_width,
                        target.bit_depth,
                        target.event_id_prefix,
                    );
                    if store
                        .delete_table_rows_in_tx(
                            local_history_node_secret::schema::LOCAL_HISTORY_NODE_SECRETS,
                            vec![key],
                        )?
                        > 0
                    {
                        wiped += 1;
                    }
                }
                if purging::purge_event_storage_in_tx(store, &target.event_id)? {
                    purged += 1;
                }
                let inserted = store.insert_table_rows_in_tx(vec![
                    local_history_node_secret::schema::local_history_node_tombstone_row_by_id(
                        workspace_id,
                        removal_frontier_id,
                        target.event_id,
                        leaf_id,
                        target.range_start,
                        target.range_width,
                    ),
                ])?;
                tombstones += inserted;
            }
            // Leaf row.
            let _ = store.delete_table_rows_in_tx(
                local_history_node_secret::schema::LOCAL_HISTORY_NODE_SECRETS,
                vec![leaf_secret_key.clone()],
            )?;
            if purging::purge_event_storage_in_tx(store, &leaf_id)? {
                purged += 1;
            }
            // The leaf is its own replacement; it's gone, so the replacement
            // is leaf_id which itself is wiped. This still uniquely names
            // the retired coord in tombstone rows. The leaf covers exactly
            // `(unix_minute, 1)` on the time axis.
            let inserted = store.insert_table_rows_in_tx(vec![
                local_history_node_secret::schema::local_history_node_tombstone_row_by_id(
                    workspace_id,
                    removal_frontier_id,
                    leaf_id,
                    leaf_id,
                    unix_minute,
                    1,
                ),
            ])?;
            tombstones += inserted;
            Ok((wiped, tombstones, purged))
        })
        .map_err(|err| format!("retire deleted event leaf wipe transaction: {err}"))?;
    report.wiped_path_rows = wiped_path_rows;
    report.tombstones_written = tombstones_written;
    report.purged_event_bytes = purged_event_bytes;
    let _ = path_rows_to_wipe;
    Ok(report)
}

/// Range-deletion primitive over the time tree.
///
/// Tombstones every minute in `[0, floor_minute)` by walking the boundary
/// descend path and applying these rules at each level (range_width >= 2):
///
///   * If `floor_minute >= mid` (floor lives in right half): the entire
///     LEFT half is `< mid <= floor_minute` and is fully chopped. Materialize
///     the left subtree row to obtain its event id, then wipe it (exact-delete
///     + canonical-byte purge + tombstone). Descend RIGHT (boundary).
///   * If `floor_minute < mid` (floor lives in left half, possibly == range_start):
///     the right half is fully `>= mid > floor_minute` and survives. Materialize
///     the right child as a sibling row so future authoring above the floor
///     has a covering ancestor. Descend LEFT (boundary).
///
/// At each step the descend-side child is also materialized; those descend-path
/// rows are wiped in a final transaction (same shape as the F-wipe block in
/// `retire_deleted_event_leaf`). When F's row is alive at chop time it is also
/// wiped at the end (forward secrecy for the chopped range). When F is already
/// wiped from a prior retirement, the walk starts from the deepest sibling
/// row that covers `floor_minute`.
///
/// Cost: at most `TIME_TREE_BIT_DEPTH + 1` boundary levels (~63), with at most
/// one subtree tombstone, one descend row, and one right-side sibling
/// materialization per level. O(log time_tree_root_width), not O(messages).
///
/// Determinism: every materialization uses the deterministic BLAKE3-keyed-hash
/// KDFs and every tombstone is keyed by a deterministic event id, so two peers
/// running the same chop produce byte-identical tombstone rows.
fn chop_time_tree_prefix<R: EventRegistry>(
    store: &Store,
    registry: &R,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    floor_minute: u64,
) -> Result<ChopReport, String> {
    let mut report = ChopReport::default();
    if floor_minute == 0 {
        // [0, 0) is empty — nothing to chop.
        return Ok(report);
    }

    // Pick the starting source covering `floor_minute`.
    //   * F root (when alive): covers the whole time axis.
    //   * Otherwise: deepest sibling row whose range contains `floor_minute`.
    //     If no row covers floor_minute, the boundary descend has no work
    //     (the chopped region either has no surviving cover at all or is
    //     already wiped). We still scan all surviving rows below for any
    //     fully inside `[0, floor_minute)`.
    let frontier_root =
        local_key_secret::queries::get(store, workspace_id, removal_frontier_id)?;
    let frontier_root_id = frontier_root.as_ref().map(|row| row.local_key_secret_id);

    enum StartSource {
        FrontierRoot {
            secret_id: EventId,
            secret: HistoryNodeSecret,
        },
        Sibling {
            secret_id: EventId,
            secret: HistoryNodeSecret,
            range_start: u64,
            range_width: u64,
        },
        None,
    }

    let start = if let Some(root_row) = frontier_root.as_ref() {
        StartSource::FrontierRoot {
            secret_id: root_row.local_key_secret_id,
            secret: root_row.key_secret,
        }
    } else {
        let mut best: Option<(EventId, HistoryNodeSecret, u64, u64)> = None;
        for row in local_history_node_secret::queries::list_for_frontier(
            store,
            workspace_id,
            removal_frontier_id,
        )? {
            // Time-tree internals only (range_width >= 1, bit_depth = 0).
            if row.bit_depth != TIME_TREE_BIT_DEPTH {
                continue;
            }
            let row_end = row.range_start.saturating_add(row.range_width);
            if floor_minute < row.range_start || floor_minute >= row_end {
                continue;
            }
            let take = match best {
                None => true,
                Some((_, _, _, current_width)) => row.range_width < current_width,
            };
            if take {
                best = Some((
                    row.local_history_node_secret_id,
                    row.node_secret,
                    row.range_start,
                    row.range_width,
                ));
            }
        }
        match best {
            Some((id, secret, range_start, range_width)) => StartSource::Sibling {
                secret_id: id,
                secret,
                range_start,
                range_width,
            },
            None => StartSource::None,
        }
    };

    // Track the descend-path rows we materialize (will be wiped at the end).
    // `WipeTarget` already exists in this module for the retire walk; reuse it.
    let mut descend_path: Vec<WipeTarget> = Vec::new();
    if let Some(root_row) = frontier_root.as_ref() {
        // F root is on the descend boundary by definition.
        descend_path.push(WipeTarget {
            event_id: root_row.local_key_secret_id,
            range_start: 0,
            range_width: TIME_TREE_ROOT_WIDTH,
            bit_depth: TIME_TREE_BIT_DEPTH,
            event_id_prefix: [0; 32],
            is_frontier_root: true,
        });
    }

    // Boundary descent.
    if let StartSource::None = start {
        // Nothing to descend; skip the walk.
    } else {
        let (mut current_secret_id, mut current_secret, mut current_range_start, mut current_range_width) =
            match start {
                StartSource::FrontierRoot { secret_id, secret } => {
                    (secret_id, secret, 0u64, TIME_TREE_ROOT_WIDTH)
                }
                StartSource::Sibling {
                    secret_id,
                    secret,
                    range_start,
                    range_width,
                } => (secret_id, secret, range_start, range_width),
                StartSource::None => unreachable!(),
            };

        while current_range_width > 1 {
            // Once we have descended past the floor on the left, stop:
            // current_range_start == floor_minute means the subtree is fully
            // surviving (no chopping inside it).
            if current_range_start >= floor_minute {
                break;
            }
            // Once we are entirely within the chopped range, stop: this
            // subtree should have been tombstoned at a higher level. Defensive.
            let current_end = current_range_start.saturating_add(current_range_width);
            if current_end <= floor_minute {
                break;
            }
            let half = current_range_width / 2;
            let mid = current_range_start + half;
            if floor_minute >= mid {
                // Left half [start, mid) is fully chopped. Materialize the
                // left child to get its event id, then track for wiping +
                // tombstoning. Descend right (boundary).
                let left = ensure_time_split(
                    store,
                    registry,
                    workspace_id,
                    removal_frontier_id,
                    current_secret_id,
                    current_secret,
                    current_range_start,
                    current_range_width,
                    0u8,
                    current_range_start,
                    half,
                )?;
                report.purged_event_bytes += 0; // accumulated in wipe phase
                let _ = left.admitted_events; // accounting noise
                let left_target = WipeTarget {
                    event_id: left.row_event_id,
                    range_start: current_range_start,
                    range_width: half,
                    bit_depth: TIME_TREE_BIT_DEPTH,
                    event_id_prefix: [0; 32],
                    is_frontier_root: false,
                };
                // Subtree tombstone for fully-chopped left subtree (counted
                // separately from boundary descend tombstones).
                descend_path.push(left_target);
                report.subtree_tombstones_written += 1;

                // Materialize right child as the boundary descend continuation.
                let right = ensure_time_split(
                    store,
                    registry,
                    workspace_id,
                    removal_frontier_id,
                    current_secret_id,
                    current_secret,
                    current_range_start,
                    current_range_width,
                    1u8,
                    mid,
                    half,
                )?;
                let _ = right.admitted_events;
                descend_path.push(WipeTarget {
                    event_id: right.row_event_id,
                    range_start: mid,
                    range_width: half,
                    bit_depth: TIME_TREE_BIT_DEPTH,
                    event_id_prefix: [0; 32],
                    is_frontier_root: false,
                });
                report.boundary_descend_tombstones_written += 1;

                current_secret_id = right.row_event_id;
                current_secret = right.row_secret;
                current_range_start = mid;
                current_range_width = half;
            } else {
                // Left half [start, mid) straddles the floor. Right half
                // [mid, end) is fully surviving — materialize as sibling
                // cover. Descend left (boundary).
                let right = ensure_time_split(
                    store,
                    registry,
                    workspace_id,
                    removal_frontier_id,
                    current_secret_id,
                    current_secret,
                    current_range_start,
                    current_range_width,
                    1u8,
                    mid,
                    half,
                )?;
                let _ = right.admitted_events;
                if right.materialized_new_row {
                    report.right_side_siblings_materialized += 1;
                }

                let left = ensure_time_split(
                    store,
                    registry,
                    workspace_id,
                    removal_frontier_id,
                    current_secret_id,
                    current_secret,
                    current_range_start,
                    current_range_width,
                    0u8,
                    current_range_start,
                    half,
                )?;
                let _ = left.admitted_events;
                descend_path.push(WipeTarget {
                    event_id: left.row_event_id,
                    range_start: current_range_start,
                    range_width: half,
                    bit_depth: TIME_TREE_BIT_DEPTH,
                    event_id_prefix: [0; 32],
                    is_frontier_root: false,
                });
                report.boundary_descend_tombstones_written += 1;

                current_secret_id = left.row_event_id;
                current_secret = left.row_secret;
                // current_range_start unchanged (left child starts at parent's start)
                current_range_width = half;
            }
        }
        // At width = 1 the boundary minute_node is `floor_minute` itself.
        // floor_minute is NOT in [0, floor_minute) — it survives. Nothing
        // to do here: the minute_node was either materialized as a descend
        // step at the previous level (it sits at width=2 → width=1), or it
        // was implicit. Either way it is the surviving boundary minute.
        let _ = (current_secret_id, current_secret, current_range_start, current_range_width);
    }

    // Wipe phase. Exact-delete every descend-path row (including F root if
    // alive), purge canonical bytes, write tombstones. The replacement node
    // id used in tombstones is the F root's event id when known, otherwise
    // the row's own event id (matches the per-leaf retire's convention that
    // the wiped row "is its own replacement" when no global replacement exists).
    let replacement_node_id = frontier_root_id.unwrap_or([0; 32]);
    let descend_path_clone = descend_path.clone();
    let (wiped, tombstones, purged) = store
        .write_transaction(move |store| {
            let mut wiped: usize = 0;
            let mut tombstones: usize = 0;
            let mut purged: usize = 0;
            for target in &descend_path_clone {
                if target.is_frontier_root {
                    let key = local_key_secret::schema::local_key_secret_key(
                        workspace_id,
                        removal_frontier_id,
                    );
                    if store
                        .delete_table_rows_in_tx(
                            local_key_secret::schema::LOCAL_KEY_SECRETS,
                            vec![key],
                        )?
                        > 0
                    {
                        wiped += 1;
                    }
                } else {
                    let key = local_history_node_secret::schema::local_history_node_secret_key(
                        workspace_id,
                        removal_frontier_id,
                        target.range_start,
                        target.range_width,
                        target.bit_depth,
                        target.event_id_prefix,
                    );
                    if store
                        .delete_table_rows_in_tx(
                            local_history_node_secret::schema::LOCAL_HISTORY_NODE_SECRETS,
                            vec![key],
                        )?
                        > 0
                    {
                        wiped += 1;
                    }
                }
                if purging::purge_event_storage_in_tx(store, &target.event_id)? {
                    purged += 1;
                }
                let inserted = store.insert_table_rows_in_tx(vec![
                    local_history_node_secret::schema::local_history_node_tombstone_row_by_id(
                        workspace_id,
                        removal_frontier_id,
                        target.event_id,
                        // Replacement: the chop has no single replacement
                        // node, so we use F's id (when known) or the wiped
                        // row's own id as a stable, deterministic marker.
                        if replacement_node_id == [0; 32] {
                            target.event_id
                        } else {
                            replacement_node_id
                        },
                        target.range_start,
                        target.range_width,
                    ),
                ])?;
                tombstones += inserted;
            }
            Ok((wiped, tombstones, purged))
        })
        .map_err(|err| format!("chop time tree prefix wipe transaction: {err}"))?;
    let _ = wiped;
    let _ = tombstones;
    report.purged_event_bytes = purged;
    let _ = descend_path;

    // GC pre-existing per-message tombstones subsumed by this chop's range.
    // The coarse subtree tombstones written above already convey
    // "everything in [0, floor_minute) is gone"; fine-grained per-message
    // tombstones below that floor are redundant and can be exact-deleted.
    //
    // For LOCAL_HISTORY_NODE_TOMBSTONES we only GC tombstones whose
    // `removal_frontier_id` matches AND whose `range_start + range_width
    // <= floor_minute`. Tombstones from a different removal_frontier
    // belong to a different tree and must not be touched. Tombstones we
    // just inserted above for the chop itself satisfy
    // `range_start + range_width <= floor_minute` only for the
    // fully-left subtrees (subtree tombstones); the boundary descend
    // tombstones span ranges that include `floor_minute` and so are
    // preserved (range_end > floor_minute). The F-root tombstone covers
    // the entire time axis (range_end = TIME_TREE_ROOT_WIDTH > floor),
    // so it is also preserved.
    //
    // For MESSAGE_TOMBSTONES we GC every row whose `authored_minute <
    // floor_minute`. The MESSAGE_TOMBSTONES table is keyed by
    // `(workspace_id, message_id)` and not partitioned by frontier, so
    // any subsumed authored_minute is fair game once the chop covers
    // it on this workspace.
    let subsumed = gc_subsumed_tombstones(
        store,
        workspace_id,
        removal_frontier_id,
        floor_minute,
    )?;
    report.subsumed_leaf_tombstones_gcd = subsumed.leaf_tombstones;
    report.subsumed_message_tombstones_gcd = subsumed.message_tombstones;
    Ok(report)
}

#[derive(Debug, Default, Clone, Copy)]
struct SubsumedTombstones {
    leaf_tombstones: usize,
    message_tombstones: usize,
}

/// Scan tombstone tables for `workspace_id` and exact-delete every row whose
/// covered range is fully under `[0, floor_minute)` (so the coarse chop
/// tombstones written above already convey that the range is gone).
///
/// LOCAL_HISTORY_NODE_TOMBSTONES is filtered by `removal_frontier_id` to
/// avoid GC'ing tombstones from other trees. MESSAGE_TOMBSTONES has no
/// frontier component in its key so all subsumed authored_minutes within
/// the workspace are fair game.
///
/// Both deletes happen in a single `write_transaction` so the GC is atomic
/// with respect to readers.
fn gc_subsumed_tombstones(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    floor_minute: u64,
) -> Result<SubsumedTombstones, String> {
    if floor_minute == 0 {
        return Ok(SubsumedTombstones::default());
    }
    // Collect leaf-tombstone keys that are subsumed.
    let leaf_keys_to_delete: Vec<Vec<u8>> = local_history_node_secret::queries::list_tombstones_for_workspace(
        store,
        workspace_id,
    )?
    .into_iter()
    .filter(|row| row.removal_frontier_id == removal_frontier_id)
    .filter(|row| row.range_start.saturating_add(row.range_width) <= floor_minute)
    .map(|row| {
        local_history_node_secret::schema::local_history_node_tombstone_key(
            row.workspace_id,
            row.removal_frontier_id,
            row.tombstone_node_id,
        )
    })
    .collect();
    // Collect message-tombstone keys whose authored_minute is subsumed.
    let message_keys_to_delete: Vec<Vec<u8>> =
        crate::protocol::event_modules::content::message::queries::list_message_tombstones_for_workspace(
            store,
            workspace_id,
        )?
        .into_iter()
        .filter(|row| row.authored_minute < floor_minute)
        .map(|row| {
            crate::protocol::event_modules::content::message::schema::message_key(
                row.workspace_id,
                row.message_id,
            )
        })
        .collect();
    if leaf_keys_to_delete.is_empty() && message_keys_to_delete.is_empty() {
        return Ok(SubsumedTombstones::default());
    }
    let leaf_table = local_history_node_secret::schema::LOCAL_HISTORY_NODE_TOMBSTONES;
    let message_table =
        crate::protocol::event_modules::content::message::schema::MESSAGE_TOMBSTONES;
    let (leaf_deleted, message_deleted) = store
        .write_transaction(move |tx_store| {
            let mut leaf_deleted = 0usize;
            if !leaf_keys_to_delete.is_empty() {
                leaf_deleted += tx_store
                    .delete_table_rows_in_tx(leaf_table, leaf_keys_to_delete)?;
            }
            let mut message_deleted = 0usize;
            if !message_keys_to_delete.is_empty() {
                message_deleted += tx_store
                    .delete_table_rows_in_tx(message_table, message_keys_to_delete)?;
            }
            Ok((leaf_deleted, message_deleted))
        })
        .map_err(|err| format!("gc subsumed tombstones transaction: {err}"))?;
    Ok(SubsumedTombstones {
        leaf_tombstones: leaf_deleted,
        message_tombstones: message_deleted,
    })
}

struct EnsureSplitOutcome {
    row_event_id: EventId,
    row_secret: HistoryNodeSecret,
    admitted_events: usize,
    materialized_new_row: bool,
}

#[allow(clippy::too_many_arguments)]
fn ensure_time_split<R: EventRegistry>(
    store: &Store,
    registry: &R,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    parent_secret_id: EventId,
    parent_secret: HistoryNodeSecret,
    parent_range_start: u64,
    parent_range_width: u64,
    child_side: u8,
    child_range_start: u64,
    child_range_width: u64,
) -> Result<EnsureSplitOutcome, String> {
    if let Some(existing) = local_history_node_secret::queries::get(
        store,
        workspace_id,
        removal_frontier_id,
        child_range_start,
        child_range_width,
        TIME_TREE_BIT_DEPTH,
        [0; 32],
    )? {
        return Ok(EnsureSplitOutcome {
            row_event_id: existing.local_history_node_secret_id,
            row_secret: existing.node_secret,
            admitted_events: 0,
            materialized_new_row: false,
        });
    }
    let output = local_history_node_secret::commands::derive_time_split(
        local_history_node_secret::commands::DeriveTimeSplit {
            workspace_id,
            removal_frontier_id,
            parent_secret_id,
            parent_secret,
            parent_range_start,
            parent_range_width,
            child_side,
            child_range_start,
            child_range_width,
            tombstone_node_id: None,
        },
    )?;
    let event_id = output.value.local_history_node_secret_id;
    let secret = output.value.event.node_secret;
    let admitted = worker::run(
        store,
        registry,
        worker::AdmitAndDrain {
            output,
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("admit retire-time-split: {err}"))?;
    Ok(EnsureSplitOutcome {
        row_event_id: event_id,
        row_secret: secret,
        admitted_events: admitted.admitted.inserted_events,
        materialized_new_row: true,
    })
}

#[allow(clippy::too_many_arguments)]
fn ensure_trie_split<R: EventRegistry>(
    store: &Store,
    registry: &R,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    range_start: u64,
    parent_secret_id: EventId,
    parent_secret: HistoryNodeSecret,
    parent_bit_depth: u16,
    parent_event_id_prefix: EventId,
    child_side: u8,
    child_bit_depth: u16,
    child_event_id_prefix: EventId,
) -> Result<EnsureSplitOutcome, String> {
    if let Some(existing) = local_history_node_secret::queries::get(
        store,
        workspace_id,
        removal_frontier_id,
        range_start,
        1,
        child_bit_depth,
        child_event_id_prefix,
    )? {
        return Ok(EnsureSplitOutcome {
            row_event_id: existing.local_history_node_secret_id,
            row_secret: existing.node_secret,
            admitted_events: 0,
            materialized_new_row: false,
        });
    }
    let output = local_history_node_secret::commands::derive_trie_split(
        local_history_node_secret::commands::DeriveTrieSplit {
            workspace_id,
            removal_frontier_id,
            parent_secret_id,
            parent_secret,
            range_start,
            parent_bit_depth,
            parent_event_id_prefix,
            child_side,
            child_bit_depth,
            child_event_id_prefix,
            tombstone_node_id: None,
        },
    )?;
    let event_id = output.value.local_history_node_secret_id;
    let secret = output.value.event.node_secret;
    let admitted = worker::run(
        store,
        registry,
        worker::AdmitAndDrain {
            output,
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("admit retire-trie-split: {err}"))?;
    Ok(EnsureSplitOutcome {
        row_event_id: event_id,
        row_secret: secret,
        admitted_events: admitted.admitted.inserted_events,
        materialized_new_row: true,
    })
}

#[allow(clippy::too_many_arguments)]
fn walk_trie_for_retire<R: EventRegistry>(
    store: &Store,
    registry: &R,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    unix_minute: u64,
    leaf_coord: EventId,
    minute_node_secret_id: EventId,
    minute_node_secret: HistoryNodeSecret,
    path_rows: &mut Vec<WipeTarget>,
    report: &mut RetireDeletedEventLeafReport,
) -> Result<(), String> {
    // Compute divergence depths between `leaf_coord` and every other
    // materialized leaf in this minute. Each unique divergence depth
    // requires a sibling internal at that depth (covering the surviving
    // events on the opposite side of the leaf path).
    let trie_rows: Vec<_> = local_history_node_secret::queries::list_leaves(store, workspace_id)?
        .into_iter()
        .filter(|row| {
            row.removal_frontier_id == removal_frontier_id
                && row.range_start == unix_minute
                && row.event_id_prefix != leaf_coord
        })
        .collect();
    let mut divergence_depths: Vec<u16> = trie_rows
        .iter()
        .map(|row| first_diverging_bit(&leaf_coord, &row.event_id_prefix))
        .collect();
    divergence_depths.sort_unstable();
    divergence_depths.dedup();

    let mut current = DerivationSource {
        secret_id: minute_node_secret_id,
        secret: minute_node_secret,
        range_start: unix_minute,
        range_width: 1,
        bit_depth: TIME_TREE_BIT_DEPTH,
        event_id_prefix: [0; 32],
    };

    for depth in divergence_depths.iter().copied() {
        if depth <= current.bit_depth {
            continue;
        }
        // Materialize sibling internal at `depth`, on the side opposite
        // `leaf_coord`'s bit at depth-1. Then materialize the descending
        // internal at `depth` on `leaf_coord`'s side. Both share the same
        // parent (`current`).
        let descend_side = bit_at(&leaf_coord, depth - 1);
        let sibling_side = 1 - descend_side;
        let descend_prefix = mask_prefix_to_depth(leaf_coord, depth);
        let sibling_prefix = sibling_prefix_at_depth(leaf_coord, depth);
        let descend = ensure_trie_split(
            store,
            registry,
            workspace_id,
            removal_frontier_id,
            unix_minute,
            current.secret_id,
            current.secret,
            current.bit_depth,
            current.event_id_prefix,
            descend_side,
            depth,
            descend_prefix,
        )?;
        report.admitted_events += descend.admitted_events;
        if descend.materialized_new_row {
            report.materialized_internal_rows += 1;
        }
        path_rows.push(WipeTarget {
            event_id: descend.row_event_id,
            range_start: unix_minute,
            range_width: 1,
            bit_depth: depth,
            event_id_prefix: descend_prefix,
            is_frontier_root: false,
        });
        let sibling = ensure_trie_split(
            store,
            registry,
            workspace_id,
            removal_frontier_id,
            unix_minute,
            current.secret_id,
            current.secret,
            current.bit_depth,
            current.event_id_prefix,
            sibling_side,
            depth,
            sibling_prefix,
        )?;
        report.admitted_events += sibling.admitted_events;
        if sibling.materialized_new_row {
            report.materialized_internal_rows += 1;
        }
        current = DerivationSource {
            secret_id: descend.row_event_id,
            secret: descend.row_secret,
            range_start: unix_minute,
            range_width: 1,
            bit_depth: depth,
            event_id_prefix: descend_prefix,
        };
    }
    let _ = workspace_id;
    let _ = registry;
    Ok(())
}

fn sibling_prefix_at_depth(leaf_coord: EventId, depth: u16) -> EventId {
    debug_assert!(depth > 0 && depth <= TRIE_LEAF_BIT_DEPTH);
    let mut prefix = mask_prefix_to_depth(leaf_coord, depth);
    let bit_index = depth - 1;
    let byte = (bit_index / 8) as usize;
    let shift = 7 - (bit_index % 8) as u8;
    let mask = 1u8 << shift;
    prefix[byte] ^= mask;
    mask_prefix_to_depth(prefix, depth)
}

fn drain_pending_message_leaves<R: EventRegistry>(
    store: &Store,
    registry: &R,
    batch_size: usize,
) -> Result<DrainPendingLeavesReport, String> {
    use crate::protocol::event_modules::content::{file, message, reaction};

    let mut report = DrainPendingLeavesReport::default();
    let blocked_pairs = store
        .table_rows_with_key_prefix(event_schema::BLOCKED_EVENTS_BY_MISSING_DEP, &[], batch_size)
        .map_err(|err| format!("load blocked edges: {err}"))?;
    for (key, _) in blocked_pairs {
        if report.scanned_events >= batch_size {
            break;
        }
        let Ok((_missing_dep_id, blocked_event_id)) = event_schema::split_edge_key(&key) else {
            continue;
        };
        let Some(bytes) = event_queries::event_bytes(store, &blocked_event_id)
            .map_err(|err| format!("load event bytes: {err}"))?
        else {
            continue;
        };
        let (workspace_id, removal_frontier_id, created_at_ms, leaf_id, event_id_in_minute) =
            match bytes.first().copied() {
                Some(message::codec::TYPE_SIGNED_MESSAGE) => {
                    let envelope = match message::codec::decode_signed(&bytes) {
                        Ok(envelope) => envelope,
                        Err(_) => continue,
                    };
                    let event = match message::codec::decode(&envelope.payload) {
                        Ok(event) => event,
                        Err(_) => continue,
                    };
                    let coord = event.event_id_in_minute_derived();
                    (
                        event.workspace_id,
                        event.removal_frontier_id,
                        event.created_at_ms,
                        event.local_history_node_secret_id,
                        coord,
                    )
                }
                Some(reaction::codec::TYPE_SIGNED_REACTION) => {
                    let envelope = match reaction::codec::decode_signed(&bytes) {
                        Ok(envelope) => envelope,
                        Err(_) => continue,
                    };
                    let event = match reaction::codec::decode(&envelope.payload) {
                        Ok(event) => event,
                        Err(_) => continue,
                    };
                    let coord = event.event_id_in_minute_derived();
                    (
                        event.workspace_id,
                        event.removal_frontier_id,
                        event.created_at_ms,
                        event.local_history_node_secret_id,
                        coord,
                    )
                }
                Some(file::codec::TYPE_SIGNED_FILE) => {
                    let envelope = match file::codec::decode_signed(&bytes) {
                        Ok(envelope) => envelope,
                        Err(_) => continue,
                    };
                    let event = match file::codec::decode(&envelope.payload) {
                        Ok(event) => event,
                        Err(_) => continue,
                    };
                    let coord = event.event_id_in_minute_derived();
                    (
                        event.workspace_id,
                        event.removal_frontier_id,
                        event.created_at_ms,
                        event.local_history_node_secret_id,
                        coord,
                    )
                }
                _ => continue,
            };
        report.scanned_events += 1;
        if local_key_secret::queries::get(store, workspace_id, removal_frontier_id)?.is_none() {
            continue;
        }
        if event_queries::has_event(store, &leaf_id)
            .map_err(|err| format!("look up leaf event: {err}"))?
        {
            continue;
        }
        let derived = derive_event_leaf(
            store,
            registry,
            workspace_id,
            removal_frontier_id,
            created_at_ms,
            event_id_in_minute,
        )?;
        if derived
            .local_history_node_secret_id
            .is_some_and(|id| id == leaf_id)
        {
            report.derived_leaves += 1;
            report.admitted_events += derived.admitted_events;
        }
    }
    Ok(report)
}

pub(crate) fn daemon_worker<C>() -> crate::core::daemon::Worker<C>
where
    C: crate::workers::DaemonWorkerContext,
{
    use crate::core::daemon::{StepContext, Worker};
    fn step<C>(ctx: &mut StepContext<'_, C>) -> Result<(), String>
    where
        C: crate::workers::DaemonWorkerContext,
    {
        let app = &*ctx.app;
        let store = app.store();
        let key_report = derive_key_secrets(store, app, ctx.options.work_limit)
            .map_err(|err| format!("derive key secrets: {err}"))?;
        let leaf_report = drain_pending_message_leaves(store, app, ctx.options.work_limit)
            .map_err(|err| format!("drain pending message leaves: {err}"))?;
        ctx.report
            .add("derived_key_secrets", key_report.derived_key_secrets);
        ctx.report
            .add("derived_message_leaves", leaf_report.derived_leaves);
        Ok(())
    }
    Worker {
        name: "encryption",
        run: step::<C>,
    }
}

fn recipient_key_row(
    store: &Store,
    workspace_id: EventId,
    recipient_key_id: EventId,
) -> Result<Option<recipient_key::types::RecipientKeyRow>, String> {
    let key = recipient_key::schema::recipient_key_key(workspace_id, recipient_key_id);
    store
        .table_row(recipient_key::schema::RECIPIENT_KEYS, &key)
        .map_err(|err| format!("load recipient key: {err}"))?
        .map(|value| recipient_key::schema::decode_recipient_key_row(&key, &value))
        .transpose()
}

fn local_membership(
    store: &Store,
    workspace_id: EventId,
) -> Result<endpoint_shared::types::EndpointMembershipRow, String> {
    let local = endpoint::commands::local_keypair(store)?
        .ok_or_else(|| "local endpoint is missing".to_string())?;
    let key = endpoint_shared::schema::endpoint_membership_key(local.endpoint, workspace_id);
    let value = store
        .table_row(endpoint_shared::schema::ENDPOINT_MEMBERSHIPS, &key)
        .map_err(|err| format!("load endpoint membership: {err}"))?
        .ok_or_else(|| "local endpoint is not joined to workspace".to_string())?;
    endpoint_shared::schema::decode_endpoint_membership_row(&key, &value)
}

fn active_local_recipient_keys(
    store: &Store,
    workspace_id: EventId,
    endpoint_shared_id: EventId,
) -> Result<Vec<RetiredRecipientKey>, String> {
    let local_keys = local_recipient_key::queries::list_for_workspace(store, workspace_id)?;
    let mut active = Vec::new();
    for row in recipient_key::queries::list_for_workspace(store, workspace_id)? {
        if row.endpoint_shared_id != endpoint_shared_id {
            continue;
        }
        let Some(local) = local_keys
            .iter()
            .find(|candidate| candidate.recipient_key == row.recipient_key)
        else {
            continue;
        };
        if recipient_key_tombstone::queries::get(store, workspace_id, row.recipient_key_id)?
            .is_some()
        {
            continue;
        }
        active.push(RetiredRecipientKey {
            recipient_key_id: row.recipient_key_id,
            local_recipient_key_id: local.local_recipient_key_id,
        });
    }
    Ok(active)
}

fn purge_retired_recipient_material(
    store: &Store,
    workspace_id: EventId,
    retired: &[RetiredRecipientKey],
) -> Result<(), String> {
    if retired.is_empty() {
        return Ok(());
    }
    let workspace_wraps = key_wrap::queries::list_for_workspace(store, workspace_id)?;
    let mut wraps_to_purge = Vec::new();
    for wrap in workspace_wraps {
        if retired
            .iter()
            .any(|key| key.recipient_key_id == wrap.recipient_key_id)
        {
            wraps_to_purge.push(wrap);
        }
    }

    let local_recipient_keys: Vec<Vec<u8>> = retired
        .iter()
        .map(|key| {
            local_recipient_key::schema::local_recipient_key_key(
                workspace_id,
                key.local_recipient_key_id,
            )
        })
        .collect();
    let key_wrap_row_keys: Vec<Vec<u8>> = wraps_to_purge
        .iter()
        .map(|wrap| {
            key_wrap::schema::key_wrap_key(
                wrap.workspace_id,
                wrap.removal_frontier_id,
                wrap.recipient_key_id,
            )
        })
        .collect();
    let pending_key_unwrap_row_keys = key_wrap_row_keys.clone();
    let event_ids_to_purge: Vec<EventId> = retired
        .iter()
        .flat_map(|key| [key.recipient_key_id, key.local_recipient_key_id])
        .chain(wraps_to_purge.iter().map(|wrap| wrap.key_wrap_id))
        .collect();

    store
        .write_transaction(move |store| {
            store.delete_table_rows_in_tx(
                local_recipient_key::schema::LOCAL_RECIPIENT_KEYS,
                local_recipient_keys,
            )?;
            store.delete_table_rows_in_tx(key_wrap::schema::KEY_WRAPS, key_wrap_row_keys)?;
            store.delete_table_rows_in_tx(
                key_wrap::schema::PENDING_KEY_UNWRAPS,
                pending_key_unwrap_row_keys,
            )?;
            for event_id in &event_ids_to_purge {
                purging::purge_event_storage_in_tx(store, event_id)?;
            }
            Ok(())
        })
        .map_err(|err| format!("purge retired recipient material tx: {err}"))
}

fn next_timestamp(store: &Store) -> Result<u64, String> {
    let max_timestamp =
        event_queries::max_timestamp(store).map_err(|err| format!("load max timestamp: {err}"))?;
    logical_clock::next_timestamp(store, max_timestamp)
}

fn key_wrap_event_from_row(row: &key_wrap::types::KeyWrapRow) -> key_wrap::types::KeyWrapEvent {
    key_wrap::types::KeyWrapEvent {
        workspace_id: row.workspace_id,
        created_at_ms: row.created_at_ms,
        removal_frontier_id: row.removal_frontier_id,
        local_key_secret_id: row.local_key_secret_id,
        recipient_key_id: row.recipient_key_id,
        sender_wrap_public_key: row.sender_wrap_public_key,
        nonce: row.nonce,
        ciphertext: row.ciphertext,
    }
}

#[cfg(test)]
mod tests {
    use crate::core::crypto::{self as core_crypto, Ed25519PrivateKey};
    use crate::protocol::event_modules::encryption::removal_frontier;
    use crate::protocol::event_modules::types::{event_id, EventStatus};
    use crate::protocol::Protocol;
    use crate::workers::pipeline_helpers::event_lifecycle;

    use super::*;

    const WORKSPACE: EventId = [1; 32];
    const KEY_SECRET: [u8; 32] = [7; 32];

    fn build_signed_frontier_record(
        signer_private_key: &Ed25519PrivateKey,
    ) -> crate::protocol::event_modules::types::EventRecord {
        let payload =
            removal_frontier::codec::encode(&removal_frontier::types::RemovalFrontierEvent {
                workspace_id: WORKSPACE,
                created_at_ms: 1,
                authority_admin_id: [9; 32],
                removal_event_ids: Vec::new(),
            })
            .expect("encode frontier");
        let envelope = removal_frontier::codec::sign([8; 32], signer_private_key, payload);
        let bytes = removal_frontier::codec::encode_signed(&envelope);
        removal_frontier::codec::signed_record_from_bytes(bytes).expect("signed record")
    }

    fn seed_local_key_secret(store: &Store) -> (EventId, EventId) {
        let signer_private_key = core_crypto::random_ed25519_private_key();
        seed_local_key_secret_with_signer(store, &signer_private_key)
    }

    /// Deterministic seed for cross-store tests: caller supplies the signer
    /// so the resulting `removal_frontier_id` is identical across stores.
    fn seed_local_key_secret_with_signer(
        store: &Store,
        signer_private_key: &Ed25519PrivateKey,
    ) -> (EventId, EventId) {
        let frontier_record = build_signed_frontier_record(signer_private_key);
        let frontier_id = event_id(&frontier_record.canonical_bytes);

        let output =
            local_key_secret::commands::from_key_secret(WORKSPACE, frontier_id, KEY_SECRET)
                .expect("local key secret");
        let local_key_secret_id = output.value.local_key_secret_id;
        let record = output.events[0].record().clone();
        store
            .write_transaction(|store| {
                event_lifecycle::insert_event(store, &frontier_record, EventStatus::Applied)?;
                event_lifecycle::insert_event(store, &record, EventStatus::Applied)?;
                store.insert_table_rows_in_tx(vec![
                    local_key_secret::schema::local_key_secret_row(
                        local_key_secret_id,
                        &output.value.event,
                    ),
                ])?;
                Ok(())
            })
            .expect("seed local key secret");
        (frontier_id, local_key_secret_id)
    }

    #[test]
    fn derive_key_secrets_drains_projected_pending_unwrap_queue() {
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let signer_private_key: Ed25519PrivateKey = [9; 32];
        let signer_endpoint_shared_id = [8; 32];
        let frontier_record = build_signed_frontier_record(&signer_private_key);
        let frontier_id = event_id(&frontier_record.canonical_bytes);

        let local_recipient_output =
            local_recipient_key::commands::create(WORKSPACE).expect("local recipient");
        let local_recipient_id = local_recipient_output.events[0].event_id();
        let local_recipient_event = local_recipient_output.value.clone();
        let local_recipient_record = local_recipient_output.events[0].record().clone();

        let recipient_output =
            recipient_key::commands::publish(recipient_key::commands::PublishRecipientKey {
                workspace_id: WORKSPACE,
                created_at_ms: 2,
                endpoint_shared_id: signer_endpoint_shared_id,
                signer_private_key,
                recipient_key: local_recipient_event.recipient_key,
            })
            .expect("recipient key");
        let recipient_record = recipient_output.events[0].record().clone();
        let recipient_envelope =
            recipient_key::codec::decode_signed(&recipient_record.canonical_bytes)
                .expect("recipient envelope");
        let recipient_event =
            recipient_key::codec::decode(&recipient_envelope.payload).expect("recipient event");

        let sender_local_secret =
            local_key_secret::commands::from_key_secret(WORKSPACE, frontier_id, KEY_SECRET)
                .expect("sender local key secret")
                .value;
        let key_wrap_output = key_wrap::commands::create(key_wrap::commands::CreateKeyWrap {
            workspace_id: WORKSPACE,
            created_at_ms: 3,
            signer_endpoint_shared_id,
            signer_private_key,
            removal_frontier_id: frontier_id,
            local_key_secret_id: sender_local_secret.local_key_secret_id,
            key_secret: sender_local_secret.event.key_secret,
            recipient_key_id: recipient_output.value.recipient_key_id,
            recipient_key: local_recipient_event.recipient_key,
        })
        .expect("key wrap");
        let key_wrap_record = key_wrap_output.events[0].record().clone();
        let key_wrap_id = key_wrap_output.value.key_wrap_id;
        let key_wrap_envelope = key_wrap::codec::decode_signed(&key_wrap_record.canonical_bytes)
            .expect("key wrap envelope");
        let key_wrap_event =
            key_wrap::codec::decode(&key_wrap_envelope.payload).expect("key wrap event");
        let local_recipient_row = local_recipient_key::schema::local_recipient_key_row(
            local_recipient_id,
            &local_recipient_event,
        );
        let recipient_row = recipient_key::schema::recipient_key_row(
            recipient_output.value.recipient_key_id,
            &recipient_event,
        )
        .expect("recipient row");
        let key_wrap_row = key_wrap::schema::key_wrap_row(
            key_wrap_id,
            key_wrap_envelope.signer_endpoint_shared_id,
            key_wrap_envelope.signer_public_key,
            &key_wrap_event,
        );
        let pending_key_unwrap_row =
            key_wrap::schema::pending_key_unwrap_row(key_wrap_id, &key_wrap_event);

        store
            .write_transaction(|store| {
                event_lifecycle::insert_event(store, &frontier_record, EventStatus::Applied)?;
                event_lifecycle::insert_event(
                    store,
                    &local_recipient_record,
                    EventStatus::Applied,
                )?;
                store.insert_table_rows_in_tx(vec![
                    local_recipient_row,
                    recipient_row,
                    key_wrap_row,
                    pending_key_unwrap_row,
                ])?;
                Ok(())
            })
            .expect("seed projected wrap");

        let pending = key_wrap::queries::list_pending_unwraps(&store, usize::MAX)
            .expect("pending before derive");
        assert_eq!(pending.len(), 1);

        let output = run(&store, &protocol, Work::DeriveKeySecrets { batch_size: 16 })
            .expect("derive key secret");
        let Output::DerivedKeySecrets(report) = output else {
            panic!("unexpected output");
        };
        assert_eq!(report.scanned_key_wraps, 1);
        assert_eq!(report.derived_key_secrets, 1);
        assert_eq!(report.failed_key_wraps, 0);
        assert_eq!(report.admitted_events, 1);

        let local = local_key_secret::queries::get(&store, WORKSPACE, frontier_id)
            .expect("local key secret")
            .expect("local key secret row");
        assert_eq!(
            local.local_key_secret_id,
            sender_local_secret.local_key_secret_id
        );
        assert_eq!(local.key_secret, KEY_SECRET);
        assert!(
            key_wrap::queries::list_pending_unwraps(&store, usize::MAX)
                .expect("pending after derive")
                .is_empty(),
            "successful unwrap must consume its queue row"
        );

        let second = run(&store, &protocol, Work::DeriveKeySecrets { batch_size: 16 })
            .expect("derive is idempotent after queue drain");
        let Output::DerivedKeySecrets(second) = second else {
            panic!("unexpected output");
        };
        assert_eq!(second.scanned_key_wraps, 0);
        assert_eq!(second.derived_key_secrets, 0);
    }

    #[test]
    fn derive_event_leaf_is_idempotent_and_returns_leaf_node_secret() {
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let (frontier_id, _local_key_secret_id) = seed_local_key_secret(&store);
        let event_id_in_minute = [99; 32];

        let first = run(
            &store,
            &protocol,
            Work::DeriveEventLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: 17,
                event_id_in_minute,
            },
        )
        .expect("first derive");
        let Output::DerivedEventLeaf(first) = first else {
            panic!("unexpected output");
        };
        let leaf_id = first
            .local_history_node_secret_id
            .expect("first call must produce leaf id");
        assert!(first.leaf_node_secret.is_some());
        assert!(first.admitted_events >= 1);

        let second = run(
            &store,
            &protocol,
            Work::DeriveEventLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: 17,
                event_id_in_minute,
            },
        )
        .expect("second derive");
        let Output::DerivedEventLeaf(second) = second else {
            panic!("unexpected output");
        };
        assert_eq!(second.local_history_node_secret_id, Some(leaf_id));
        assert_eq!(second.leaf_node_secret, first.leaf_node_secret);
        assert_eq!(second.admitted_events, 0, "second call must be idempotent");
    }

    #[test]
    fn derive_event_leaf_reaches_same_secret_via_root_walk() {
        // Walking from the workspace root through ~63 time-tree splits and
        // one trie split must reproduce the same leaf secret as a direct
        // BLAKE3 keyed-hash derivation. This is the "O(280) hashes" property.
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let (frontier_id, _local_key_secret_id) = seed_local_key_secret(&store);
        let event_id_in_minute = [0xab; 32];
        let created_at_ms: u64 = 7 * 60_000;

        let report = run(
            &store,
            &protocol,
            Work::DeriveEventLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms,
                event_id_in_minute,
            },
        )
        .expect("derive");
        let Output::DerivedEventLeaf(report) = report else {
            panic!("unexpected");
        };
        let leaf_secret = report.leaf_node_secret.expect("leaf secret");

        // Replay the chain directly from the workspace key secret.
        let mut current_secret = KEY_SECRET;
        let mut current_start = 0u64;
        let mut current_width = TIME_TREE_ROOT_WIDTH;
        let target_minute = created_at_ms / 60_000;
        while current_width > 1 {
            let half = current_width / 2;
            let mid = current_start + half;
            let (child_side, child_start) = if target_minute < mid {
                (0u8, current_start)
            } else {
                (1u8, mid)
            };
            let info = time_split_info(current_start, current_width, child_side, child_start, half);
            current_secret = crypto::blake3_keyed_hash(
                &current_secret,
                local_history_node_secret::commands::TIME_SPLIT_DOMAIN,
                &info,
            );
            current_start = child_start;
            current_width = half;
        }
        let leaf_side = bit_at(&event_id_in_minute, 0);
        let info = trie_split_info(
            0,
            [0; 32],
            leaf_side,
            TRIE_LEAF_BIT_DEPTH,
            event_id_in_minute,
        );
        let recomputed = crypto::blake3_keyed_hash(
            &current_secret,
            local_history_node_secret::commands::TRIE_SPLIT_DOMAIN,
            &info,
        );
        assert_eq!(recomputed, leaf_secret);
    }

    #[test]
    fn sparse_delete_materializes_log_n_internals_not_n_leaves() {
        // Author N events in the same minute as fresh leaves (no internals
        // materialized), then retire ONE. The materialized rows after
        // retire must scale with O(log #minutes + log #events_in_minute),
        // not with N. With TIME_TREE_ROOT_WIDTH = 2^63, the time-tree
        // contribution is O(64). The trie contribution should be O(log N).
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let (frontier_id, _) = seed_local_key_secret(&store);
        const N: usize = 16;
        let coords: Vec<EventId> = (0u8..N as u8).map(|byte| [byte ^ 0xa5; 32]).collect();
        for coord in &coords {
            let _ = run(
                &store,
                &protocol,
                Work::DeriveEventLeaf {
                    workspace_id: WORKSPACE,
                    removal_frontier_id: frontier_id,
                    created_at_ms: 60_000,
                    event_id_in_minute: *coord,
                },
            )
            .expect("derive leaf");
        }
        let pre_rows = local_history_node_secret::queries::list_for_workspace(&store, WORKSPACE)
            .expect("pre rows");
        assert_eq!(
            pre_rows.len(),
            N,
            "every fresh send admits exactly one leaf row"
        );
        for row in &pre_rows {
            assert!(
                local_history_node_secret::types::is_leaf_row(row),
                "every pre-delete row must be a leaf",
            );
        }

        // Retire the first leaf.
        let report = run(
            &store,
            &protocol,
            Work::RetireDeletedEventLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: 60_000,
                event_id_in_minute: coords[0],
            },
        )
        .expect("retire");
        let Output::RetiredDeletedEventLeaf(report) = report else {
            panic!("unexpected output");
        };
        // The retire walk admits a chain of ~log(range_width) + log(N)
        // descend-side AND sibling-side events, then wipes the descend
        // chain (rows + canonical bytes). `purged_event_bytes` therefore
        // counts the leaf bytes + every descend-side event's bytes + the
        // F root event's bytes. We just bound it loosely.
        assert!(
            report.purged_event_bytes >= 1,
            "at minimum the leaf canonical bytes must be purged"
        );
        assert!(
            report.tombstones_written >= 1,
            "at minimum a leaf tombstone must be written"
        );

        let post_rows = local_history_node_secret::queries::list_for_workspace(&store, WORKSPACE)
            .expect("post rows");
        let leaf_count = post_rows
            .iter()
            .filter(|row| local_history_node_secret::types::is_leaf_row(row))
            .count();
        assert_eq!(
            leaf_count,
            N - 1,
            "exactly one leaf retired; surviving leaf rows persist",
        );
        // After retire, only SIBLING internals remain — the descend-side
        // chain is wiped. Sibling count is bounded by O(log range_width +
        // log N): one sibling per time-tree split level plus one per trie
        // divergence depth.
        let internal_row_count = post_rows.len() - leaf_count;
        let time_tree_sibling_bound = 64 + 4; // 64 levels * 1 sibling + slack
        let trie_sibling_bound = (N as f64).log2().ceil() as usize + 4;
        assert!(
            internal_row_count <= time_tree_sibling_bound + trie_sibling_bound,
            "internal sibling row count {internal_row_count} must be O(log range + log N), bound {}",
            time_tree_sibling_bound + trie_sibling_bound,
        );

        // Assert the deleted leaf cannot be looked up.
        assert!(
            local_history_node_secret::queries::get_leaf(
                &store,
                WORKSPACE,
                frontier_id,
                60_000 / 60_000,
                coords[0],
            )
            .expect("lookup")
            .is_none(),
            "deleted leaf row must be gone",
        );

        // Assert F root row is also wiped.
        assert!(
            local_key_secret::queries::get(&store, WORKSPACE, frontier_id)
                .expect("look up local_key_secret")
                .is_none(),
            "local_key_secret(F) row must be wiped after retire",
        );
    }

    #[test]
    fn delete_wipes_minute_node_along_descend_path() {
        // Forward-secrecy invariant under the new retire walk: the
        // minute_node at the deleted leaf's `target_minute` is on the
        // descending path from F root to the leaf. The retire walk
        // therefore exact-deletes that minute_node row (and purges its
        // canonical bytes). It also leaves adjacent minute_nodes at M-1
        // or M+1 unmaterialized (those are sibling-side at the final
        // time-tree split, which we deliberately skip).
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let (frontier_id, _) = seed_local_key_secret(&store);
        let coord_a = [0xaa; 32];
        let coord_b = [0xbb; 32];
        // Two events in minute 100 so retire has a surviving sibling to
        // cover.
        for coord in [coord_a, coord_b] {
            let _ = run(
                &store,
                &protocol,
                Work::DeriveEventLeaf {
                    workspace_id: WORKSPACE,
                    removal_frontier_id: frontier_id,
                    created_at_ms: 100 * 60_000,
                    event_id_in_minute: coord,
                },
            )
            .expect("derive leaf");
        }
        let _ = run(
            &store,
            &protocol,
            Work::RetireDeletedEventLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: 100 * 60_000,
                event_id_in_minute: coord_a,
            },
        )
        .expect("retire");

        // Adjacent minute_nodes (range_width=1, bit_depth=0) at minute 99 or 101
        // must not exist (sibling-at-width-1 skip).
        for adjacent in [99u64, 101u64] {
            assert!(
                local_history_node_secret::queries::get_minute_node(
                    &store,
                    WORKSPACE,
                    frontier_id,
                    adjacent,
                )
                .expect("lookup")
                .is_none(),
                "minute_node at adjacent minute {adjacent} must NOT be materialized",
            );
        }
        // The deleted leaf's minute_node is on the descend path and so is
        // wiped — its row no longer exists post-retire (forward secrecy
        // requires this; otherwise minute_node + target_coord re-derives
        // the deleted leaf's secret via a single trie split).
        assert!(
            local_history_node_secret::queries::get_minute_node(
                &store,
                WORKSPACE,
                frontier_id,
                100,
            )
            .expect("lookup")
            .is_none(),
            "minute_node at M=100 must be wiped after retire (descend-path FS)",
        );
        // The surviving sibling leaf at coord_b stays materialized.
        assert!(
            local_history_node_secret::queries::get_leaf(
                &store,
                WORKSPACE,
                frontier_id,
                100,
                coord_b,
            )
            .expect("lookup")
            .is_some(),
            "sibling leaf at coord_b must survive retire",
        );
    }

    #[test]
    fn cover_summary_after_sparse_delete_is_logarithmic() {
        // The cover_summary length is O(materialized_rows + tombstones) by
        // construction. After deleting 1 of N events in a minute, the
        // materialized row count is bounded by O(log range_width + log N)
        // (siblings only) and the tombstone count is also O(log range +
        // log N + 1) (one tombstone per wiped descend-path row + leaf),
        // so cover_summary length stays bounded too.
        use local_history_node_secret::queries::cover_summary;
        use local_history_node_secret::schema::{COVER_SUMMARY_ROW_LEN, COVER_SUMMARY_TOMBSTONE_LEN};
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let (frontier_id, _) = seed_local_key_secret(&store);
        const N: usize = 32;
        let coords: Vec<EventId> = (0u8..N as u8).map(|byte| [byte ^ 0x77; 32]).collect();
        for coord in &coords {
            let _ = run(
                &store,
                &protocol,
                Work::DeriveEventLeaf {
                    workspace_id: WORKSPACE,
                    removal_frontier_id: frontier_id,
                    created_at_ms: 60_000,
                    event_id_in_minute: *coord,
                },
            )
            .expect("derive leaf");
        }
        let _ = run(
            &store,
            &protocol,
            Work::RetireDeletedEventLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: 60_000,
                event_id_in_minute: coords[0],
            },
        )
        .expect("retire");

        let summary = cover_summary(&store, WORKSPACE).expect("cover_summary");
        let header_len = b"topo cover summary v4".len() + 4;
        // Layout: header(21) || u32(rows) || rows... || u32(tombstones) || tombstones...
        // We can't trivially recover the boundary here, but the total is
        // bounded by the row+tombstone budgets.
        let log_n = (N as f64).log2().ceil() as usize;
        // Surviving leaves + sibling internals + tombstone budget.
        let row_budget = (N - 1) + 2 * 64 + 4 + 2 * log_n + 4;
        let tombstone_budget = 64 + 4 + log_n + 4 + 1; // F root + path + leaf + slack
        let total_budget = header_len
            + 4
            + row_budget * COVER_SUMMARY_ROW_LEN
            + 4
            + tombstone_budget * COVER_SUMMARY_TOMBSTONE_LEN;
        assert!(
            summary.len() <= total_budget,
            "cover_summary length {} exceeds bound {}",
            summary.len(),
            total_budget,
        );

        // Determinism: a second compute returns the same bytes.
        let again = cover_summary(&store, WORKSPACE).expect("cover_summary again");
        assert_eq!(summary, again);
    }

    /// Adversary model: an attacker has saved a copy of the deleted leaf's
    /// `(unix_minute, event_id_in_minute, created_at_ms)` and the canonical
    /// bytes of the deleted message before the retire. After retire, we ask:
    /// can any retained workspace material reach the deleted leaf's secret?
    ///
    /// Under the new puncturing retire walk:
    ///   * No `local_history_node_secret` row covers the deleted leaf's
    ///     coord. Sibling rows have prefixes that diverge from the deleted
    ///     leaf's coord at the sibling's depth, so they cannot re-derive
    ///     the leaf. This is asserted via the per-row walk below.
    ///   * The `local_key_secret(F)` row is also wiped (separately
    ///     asserted in `strict_adversary_no_retained_row_derives_deleted_leaf`),
    ///     so the workspace root cannot re-derive the leaf either.
    ///
    /// This test exercises the per-row walk: every retained row in
    /// `local_history_node_secrets` whose coordinate could plausibly cover
    /// the deleted leaf is checked, and none must derive it.
    #[test]
    fn adversary_cannot_re_derive_deleted_leaf_from_unrelated_retained_rows() {
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let (frontier_id, _local_key_secret_id) = seed_local_key_secret(&store);

        // Author N events in the same minute. Distinct event_id_in_minute
        // bits so the trie has real branching.
        const N: usize = 8;
        let coords: Vec<EventId> = (0u8..N as u8).map(|byte| [byte ^ 0xa5; 32]).collect();
        let target_idx = 0usize;
        let target_coord = coords[target_idx];
        let target_created_at_ms: u64 = 60_000;
        let target_minute = target_created_at_ms / 60_000;

        let mut target_secret_snapshot: Option<HistoryNodeSecret> = None;
        for (idx, coord) in coords.iter().enumerate() {
            let report = run(
                &store,
                &protocol,
                Work::DeriveEventLeaf {
                    workspace_id: WORKSPACE,
                    removal_frontier_id: frontier_id,
                    created_at_ms: target_created_at_ms,
                    event_id_in_minute: *coord,
                },
            )
            .expect("derive leaf");
            let Output::DerivedEventLeaf(report) = report else {
                panic!("unexpected output");
            };
            if idx == target_idx {
                target_secret_snapshot =
                    Some(report.leaf_node_secret.expect("target leaf secret"));
            }
        }
        let target_secret = target_secret_snapshot.expect("target snapshot");

        // Retire the target leaf.
        let retire = run(
            &store,
            &protocol,
            Work::RetireDeletedEventLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: target_created_at_ms,
                event_id_in_minute: target_coord,
            },
        )
        .expect("retire");
        let Output::RetiredDeletedEventLeaf(_retire) = retire else {
            panic!("unexpected output");
        };
        assert!(
            local_history_node_secret::queries::get_leaf(
                &store,
                WORKSPACE,
                frontier_id,
                target_minute,
                target_coord,
            )
            .expect("lookup")
            .is_none(),
            "deleted leaf row must be gone",
        );

        // Walk from each retained row that could plausibly cover the target
        // and assert NONE derives the target leaf's secret. After the
        // puncturing retire walk, no covering row exists for the deleted
        // coord — the descend chain is wiped.
        let post_rows = local_history_node_secret::queries::list_for_workspace(&store, WORKSPACE)
            .expect("list rows");
        for row in &post_rows {
            if row.removal_frontier_id != frontier_id {
                continue;
            }
            // Skip leaf rows (they are exact lookups, not ancestors).
            if row.bit_depth == TRIE_LEAF_BIT_DEPTH {
                continue;
            }
            let covers_minute = row.range_start <= target_minute
                && target_minute < row.range_start.saturating_add(row.range_width);
            if !covers_minute {
                continue;
            }
            // Does this row's prefix actually agree with target_coord up to
            // bit_depth? After puncturing retire, no surviving row should
            // satisfy this — they are all siblings (off-path).
            let on_path = if row.bit_depth == 0 {
                true
            } else {
                let masked_target = mask_prefix_to_depth(target_coord, row.bit_depth);
                masked_target == row.event_id_prefix
            };
            let derived = walk_descendant_to_leaf(
                row.node_secret,
                row.range_start,
                row.range_width,
                row.bit_depth,
                row.event_id_prefix,
                target_minute,
                target_coord,
            );
            assert_ne!(
                derived, target_secret,
                "RETAINED ROW LEAKS deleted leaf secret: \
                 row=(start={}, width={}, depth={}, on_path={}); \
                 the puncturing retire walk must wipe every such row.",
                row.range_start, row.range_width, row.bit_depth, on_path,
            );
        }

        // Walking from the workspace root (KEY_SECRET) DOES reproduce the
        // leaf secret deterministically, but the F root row has been wiped
        // by the retire walk, so an on-disk attacker does not actually
        // have access to KEY_SECRET. The forward-secrecy guarantee is
        // grounded in the wipe, not in the KDF's directionality.
        let root_walk = walk_descendant_to_leaf(
            KEY_SECRET,
            0,
            TIME_TREE_ROOT_WIDTH,
            TIME_TREE_BIT_DEPTH,
            [0; 32],
            target_minute,
            target_coord,
        );
        assert_eq!(
            root_walk, target_secret,
            "sanity: the KDF reproduces the leaf if and only if the \
             attacker has the F root secret. The retire walk's wipe of \
             the F root row is what makes this in-memory reconstruction \
             unreachable on a real device.",
        );
        // F root row is wiped — confirm the disk-level state.
        assert!(
            local_key_secret::queries::get(&store, WORKSPACE, frontier_id)
                .expect("look up local_key_secret")
                .is_none(),
            "local_key_secret(F) row must be wiped; the in-memory KEY_SECRET \
             constant in this test is what an adversary CANNOT recover from disk",
        );
    }

    /// Strict adversary assertion: AFTER retire, NO retained row in the
    /// workspace — including the `local_key_secret(F)` root — should be
    /// able to derive the deleted leaf's secret.
    ///
    /// The retire walk admits both descend-side and sibling internals
    /// during the chain (so the projector's source-dependency invariant
    /// holds), then exact-deletes every descend-path row AND the F root
    /// row, purges their canonical bytes, and tombstones them. Only
    /// off-path siblings and unrelated rows survive. Sibling secrets
    /// cannot derive the deleted leaf because their prefix at the
    /// sibling's depth is the OPPOSITE of the deleted leaf's bit, so the
    /// KDF inputs from a sibling produce the SIBLING-SIDE leaf, not the
    /// deleted leaf.
    ///
    /// The F root check is the critical one for the broader threat
    /// model: an adversary who has both the deleted message's ciphertext
    /// (from a backup or non-purging peer) and on-disk access must not
    /// be able to recover the deleted message's AEAD key. The ciphertext
    /// header reveals the canonical fields → `event_id_in_minute`. With
    /// an intact F root the adversary could re-derive the leaf via the
    /// root fast path (`derive_event_leaf_from_root`); wiping F root
    /// closes that path.
    #[test]
    fn strict_adversary_no_retained_row_derives_deleted_leaf() {
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let (frontier_id, _local_key_secret_id) = seed_local_key_secret(&store);

        const N: usize = 8;
        let coords: Vec<EventId> = (0u8..N as u8).map(|byte| [byte ^ 0xa5; 32]).collect();
        let target_idx = 0usize;
        let target_coord = coords[target_idx];
        let target_created_at_ms: u64 = 60_000;
        let target_minute = target_created_at_ms / 60_000;

        let mut target_secret: Option<HistoryNodeSecret> = None;
        for (idx, coord) in coords.iter().enumerate() {
            let report = run(
                &store,
                &protocol,
                Work::DeriveEventLeaf {
                    workspace_id: WORKSPACE,
                    removal_frontier_id: frontier_id,
                    created_at_ms: target_created_at_ms,
                    event_id_in_minute: *coord,
                },
            )
            .expect("derive leaf");
            let Output::DerivedEventLeaf(report) = report else {
                panic!();
            };
            if idx == target_idx {
                target_secret = Some(report.leaf_node_secret.expect("target leaf secret"));
            }
        }
        let target_secret = target_secret.expect("target snapshot");

        let _ = run(
            &store,
            &protocol,
            Work::RetireDeletedEventLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: target_created_at_ms,
                event_id_in_minute: target_coord,
            },
        )
        .expect("retire");

        let post_rows = local_history_node_secret::queries::list_for_workspace(&store, WORKSPACE)
            .expect("list rows");
        for row in &post_rows {
            if row.bit_depth == TRIE_LEAF_BIT_DEPTH {
                continue;
            }
            let covers_minute = row.range_start <= target_minute
                && target_minute < row.range_start.saturating_add(row.range_width);
            if !covers_minute {
                continue;
            }
            if row.bit_depth != 0 {
                let masked = mask_prefix_to_depth(target_coord, row.bit_depth);
                if masked != row.event_id_prefix {
                    continue;
                }
            }
            let derived = walk_descendant_to_leaf(
                row.node_secret,
                row.range_start,
                row.range_width,
                row.bit_depth,
                row.event_id_prefix,
                target_minute,
                target_coord,
            );
            assert_ne!(
                derived, target_secret,
                "STRICT ADVERSARY VIOLATION: retained row at \
                 (start={}, width={}, depth={}) re-derives deleted leaf",
                row.range_start, row.range_width, row.bit_depth,
            );
        }

        // The workspace `local_key_secret(F)` row must also be wiped: if it
        // remained, its secret would reproduce the deleted leaf via the
        // root fast path (deterministic time-tree walk + one trie split).
        // See `derive_event_leaf_from_root`.
        assert!(
            local_key_secret::queries::get(&store, WORKSPACE, frontier_id)
                .expect("look up local_key_secret")
                .is_none(),
            "STRICT ADVERSARY VIOLATION: local_key_secret(F) row survived \
             retire — F root + ciphertext re-derive the deleted leaf",
        );
    }

    /// After retire, the workspace's `local_history_node_tombstones` table
    /// names every wiped node. Two stores running the same admit + retire
    /// history MUST produce byte-equal `cover_summary` outputs because the
    /// summary v4 encoding includes both retained rows AND tombstones, and
    /// every wiped event id is deterministic from the same canonical
    /// inputs.
    #[test]
    fn cover_summary_is_byte_equal_across_two_stores_running_same_retire() {
        use local_history_node_secret::queries::cover_summary;
        let coords: Vec<EventId> = (0u8..6u8).map(|byte| [byte ^ 0xa5; 32]).collect();
        let target_idx = 0usize;
        // Use a deterministic signer so both stores derive the same
        // `removal_frontier_id`. In production, two peers receive the same
        // signed frontier event over the network, so their frontier ids
        // match by construction.
        let signer = [0xab; 32];

        let mk_store = || -> (Store, EventId) {
            let store = Protocol::open_memory_store().expect("store");
            let protocol = Protocol::new();
            let (frontier_id, _) = seed_local_key_secret_with_signer(&store, &signer);
            for coord in &coords {
                let _ = run(
                    &store,
                    &protocol,
                    Work::DeriveEventLeaf {
                        workspace_id: WORKSPACE,
                        removal_frontier_id: frontier_id,
                        created_at_ms: 60_000,
                        event_id_in_minute: *coord,
                    },
                )
                .expect("derive leaf");
            }
            let _ = run(
                &store,
                &protocol,
                Work::RetireDeletedEventLeaf {
                    workspace_id: WORKSPACE,
                    removal_frontier_id: frontier_id,
                    created_at_ms: 60_000,
                    event_id_in_minute: coords[target_idx],
                },
            )
            .expect("retire");
            (store, frontier_id)
        };

        let (alice_store, _alice_frontier) = mk_store();
        let (bob_store, _bob_frontier) = mk_store();
        let alice_summary = cover_summary(&alice_store, WORKSPACE).expect("alice summary");
        let bob_summary = cover_summary(&bob_store, WORKSPACE).expect("bob summary");
        assert_eq!(
            alice_summary, bob_summary,
            "cover_summary must be byte-equal across two stores running the \
             same admit + retire history (forward-secrecy commitment relies \
             on every peer producing the same fingerprint of the retained set)",
        );
        // Sanity: tombstones are present (so summary actually exercises the
        // tombstone-encoding branch).
        let tombstones =
            local_history_node_secret::queries::list_tombstones_for_workspace(&alice_store, WORKSPACE)
                .expect("list tombstones");
        assert!(
            !tombstones.is_empty(),
            "retire must write tombstones so cover_summary's tombstone branch is non-empty",
        );
    }

    /// After retire wipes `local_key_secret(F)`, authoring a new message
    /// under F in a *different minute* must keep working: the retire
    /// walk's time-tree siblings collectively cover every minute except
    /// the wiped one, so `derive_event_leaf` falls back to the deepest
    /// covering time-axis sibling. No explicit `key-frontier` advance is
    /// required — each peer derives the same sibling secrets locally
    /// because the KDF is deterministic.
    #[test]
    fn after_retire_authoring_under_wiped_frontier_uses_sibling_fallback() {
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let (frontier_id, _) = seed_local_key_secret(&store);
        let coord_a = [0xaa; 32];
        let coord_b = [0xbb; 32];
        // Retire-target minute = 1 (created_at_ms = 60_000). Author both
        // coords there so the trie has a real branching.
        for coord in [coord_a, coord_b] {
            let _ = run(
                &store,
                &protocol,
                Work::DeriveEventLeaf {
                    workspace_id: WORKSPACE,
                    removal_frontier_id: frontier_id,
                    created_at_ms: 60_000,
                    event_id_in_minute: coord,
                },
            )
            .expect("derive leaf");
        }
        let _ = run(
            &store,
            &protocol,
            Work::RetireDeletedEventLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: 60_000,
                event_id_in_minute: coord_a,
            },
        )
        .expect("retire");

        // F root row is wiped (the retire walk's wipe phase guarantees this).
        assert!(
            local_key_secret::queries::get(&store, WORKSPACE, frontier_id)
                .expect("look up local_key_secret")
                .is_none(),
            "precondition: retire must have wiped local_key_secret(F)"
        );

        // Authoring under the SAME (wiped) frontier in a different minute
        // (minute 2 = 120_000 ms) must succeed via time-axis sibling
        // fallback: the retire walk admitted time-tree siblings that
        // collectively cover [0, TIME_TREE_ROOT_WIDTH) minus minute 1.
        let new_coord = [0xcc; 32];
        let report = run(
            &store,
            &protocol,
            Work::DeriveEventLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: 120_000,
                event_id_in_minute: new_coord,
            },
        )
        .expect("authoring after retire must succeed via sibling fallback");
        let Output::DerivedEventLeaf(report) = report else {
            panic!();
        };
        assert!(
            report.local_history_node_secret_id.is_some(),
            "sibling fallback must produce a fresh leaf row"
        );
        assert!(
            report.leaf_node_secret.is_some(),
            "sibling fallback must produce a fresh leaf secret"
        );

    }

    /// Same-minute authoring for a brand-new coord whose trie subtree is
    /// not covered by any surviving sibling row legitimately wedges.
    /// `closest_retained_ancestor` returns a clear error rather than
    /// silently using F (which has been wiped). This is the documented
    /// "genuine wedge" branch from the function's docstring — the retire
    /// walk only admits same-minute trie siblings at divergence depths
    /// between the deleted coord and surviving leaves, so a new coord
    /// whose prefix bits sit inside the (now-wiped) descend subtree has
    /// no covering ancestor.
    #[test]
    fn after_retire_same_minute_uncovered_coord_errors_with_clear_message() {
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let (frontier_id, _) = seed_local_key_secret(&store);
        let coord_a = [0xaa; 32];
        let coord_b = [0xbb; 32];
        for coord in [coord_a, coord_b] {
            let _ = run(
                &store,
                &protocol,
                Work::DeriveEventLeaf {
                    workspace_id: WORKSPACE,
                    removal_frontier_id: frontier_id,
                    created_at_ms: 60_000,
                    event_id_in_minute: coord,
                },
            )
            .expect("derive leaf");
        }
        let _ = run(
            &store,
            &protocol,
            Work::RetireDeletedEventLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: 60_000,
                event_id_in_minute: coord_a,
            },
        )
        .expect("retire");

        // A new same-minute coord whose subtree falls inside the wiped
        // descend chain (no surviving sibling covers it) yields a clear
        // wedge error, not a silent fallback to a wiped F.
        let uncovered = [0xcc; 32];
        let err = run(
            &store,
            &protocol,
            Work::DeriveEventLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: 60_000,
                event_id_in_minute: uncovered,
            },
        )
        .expect_err("uncovered same-minute coord must error with a clear wedge message");
        assert!(
            err.contains("no retained ancestor covers"),
            "expected wedge error mentioning no retained ancestor; got: {err}"
        );
    }

    /// Walk from the given covering-row's secret down to the leaf at
    /// `(target_minute, 1, TRIE_LEAF_BIT_DEPTH, target_coord)` using the
    /// same KDF construction as the implementation. Used to ask whether a
    /// retained row's secret derives a target leaf.
    fn walk_descendant_to_leaf(
        start_secret: HistoryNodeSecret,
        start_range_start: u64,
        start_range_width: u64,
        start_bit_depth: u16,
        start_event_id_prefix: EventId,
        target_minute: u64,
        target_coord: EventId,
    ) -> HistoryNodeSecret {
        // Time-tree descent if needed.
        let mut current_secret = start_secret;
        let mut current_start = start_range_start;
        let mut current_width = start_range_width;
        while current_width > 1 {
            let half = current_width / 2;
            let mid = current_start + half;
            let (child_side, child_start) = if target_minute < mid {
                (0u8, current_start)
            } else {
                (1u8, mid)
            };
            let info = time_split_info(current_start, current_width, child_side, child_start, half);
            current_secret = crypto::blake3_keyed_hash(
                &current_secret,
                local_history_node_secret::commands::TIME_SPLIT_DOMAIN,
                &info,
            );
            current_start = child_start;
            current_width = half;
        }
        debug_assert_eq!(current_start, target_minute);
        debug_assert_eq!(current_width, 1);

        // Trie descent: from the starting bit_depth (or 0 if we just
        // arrived at the minute_node from a time-tree walk) down to the
        // leaf via a single trie_split with `child_bit_depth = 256` and
        // `child_event_id_prefix = target_coord`.
        let parent_bit_depth = if start_range_width == 1 {
            start_bit_depth
        } else {
            // We descended through the time tree; the parent at the bottom
            // is the minute_node-equivalent at bit_depth = 0.
            0
        };
        let parent_prefix = if start_range_width == 1 {
            start_event_id_prefix
        } else {
            [0u8; 32]
        };
        let leaf_side = bit_at(&target_coord, parent_bit_depth);
        let info = trie_split_info(
            parent_bit_depth,
            parent_prefix,
            leaf_side,
            TRIE_LEAF_BIT_DEPTH,
            target_coord,
        );
        crypto::blake3_keyed_hash(
            &current_secret,
            local_history_node_secret::commands::TRIE_SPLIT_DOMAIN,
            &info,
        )
    }

    #[test]
    fn chop_with_floor_zero_is_noop() {
        // floor_minute = 0 means [0, 0) is empty; the chop must leave F's
        // row untouched and report zero counts.
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let (frontier_id, local_key_secret_id) = seed_local_key_secret(&store);

        let report = run(
            &store,
            &protocol,
            Work::ChopTimeTreePrefix {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                floor_minute: 0,
            },
        )
        .expect("chop with floor=0");
        let Output::ChoppedTimeTreePrefix(report) = report else {
            panic!("unexpected output");
        };
        assert_eq!(report.subtree_tombstones_written, 0);
        assert_eq!(report.boundary_descend_tombstones_written, 0);
        assert_eq!(report.right_side_siblings_materialized, 0);
        assert_eq!(report.purged_event_bytes, 0);

        // F's row must be untouched.
        let root = local_key_secret::queries::get(&store, WORKSPACE, frontier_id)
            .expect("look up local_key_secret")
            .expect("F row must remain after no-op chop");
        assert_eq!(root.local_key_secret_id, local_key_secret_id);
        // No tombstones should have been written.
        let tombstones = local_history_node_secret::queries::list_tombstones_for_workspace(
            &store, WORKSPACE,
        )
        .expect("list tombstones");
        assert!(
            tombstones.is_empty(),
            "no tombstones must be written for floor=0"
        );
    }

    #[test]
    fn chop_full_minute_writes_subtree_and_descend_tombstones() {
        // Chop with a small non-zero floor. Confirm tombstones land in
        // LOCAL_HISTORY_NODE_TOMBSTONES, with the boundary depth and
        // subtree-tombstone counts each bounded by the time-tree depth.
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let (frontier_id, _) = seed_local_key_secret(&store);

        let floor_minute: u64 = 100;
        let report = run(
            &store,
            &protocol,
            Work::ChopTimeTreePrefix {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                floor_minute,
            },
        )
        .expect("chop");
        let Output::ChoppedTimeTreePrefix(report) = report else {
            panic!();
        };

        // Time-tree depth from width = 2^63 down to width = 1 is 63 levels.
        // Each level admits at most one descend row and at most one
        // fully-left subtree tombstone, so each count is bounded by 63.
        let depth_bound = TIME_TREE_BIT_DEPTH as usize + 63; // = 63 (since TIME_TREE_BIT_DEPTH=0); use 63 directly
        let _ = depth_bound;
        let max_levels = 63usize;
        assert!(
            report.subtree_tombstones_written <= max_levels,
            "subtree tombstones {} must be <= {} (one per boundary bit=1 level)",
            report.subtree_tombstones_written,
            max_levels,
        );
        assert!(
            report.boundary_descend_tombstones_written <= max_levels,
            "boundary descend tombstones {} must be <= {} (one per descend level)",
            report.boundary_descend_tombstones_written,
            max_levels,
        );
        // For floor_minute = 100 (= 0b1100100), floor sits in the LEFT half
        // of all top levels (bit=0), then the RIGHT half (bit=1) at the
        // levels where 100 has set bits. Count the set bits of 100 = 3, so
        // exactly 3 fully-left subtrees are tombstoned.
        assert_eq!(
            report.subtree_tombstones_written, 3,
            "floor_minute=100 has 3 set bits → 3 fully-left subtrees tombstoned"
        );

        // Tombstones are persisted in LOCAL_HISTORY_NODE_TOMBSTONES.
        let tombstones = local_history_node_secret::queries::list_tombstones_for_workspace(
            &store, WORKSPACE,
        )
        .expect("list tombstones");
        // One tombstone per descend-path row + one per fully-left subtree.
        // Bound: depth + depth + 1 (F root).
        assert!(
            !tombstones.is_empty(),
            "non-zero floor must produce at least one tombstone"
        );
        assert!(
            tombstones.len() <= 2 * max_levels + 1,
            "tombstone count {} must be <= 2*{} + 1",
            tombstones.len(),
            max_levels,
        );

        // F's row must be wiped (chop wipes F just like RetireDeletedEventLeaf).
        assert!(
            local_key_secret::queries::get(&store, WORKSPACE, frontier_id)
                .expect("look up local_key_secret")
                .is_none(),
            "F's row must be wiped after a non-zero chop"
        );
    }

    #[test]
    fn chop_then_author_above_floor_succeeds_via_sibling() {
        // After a chop to floor=100, deriving an event leaf at minute 200
        // (above the floor) must succeed via the right-side sibling cover
        // materialized by the chop walk.
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let (frontier_id, _) = seed_local_key_secret(&store);

        let _ = run(
            &store,
            &protocol,
            Work::ChopTimeTreePrefix {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                floor_minute: 100,
            },
        )
        .expect("chop to floor=100");

        let report = run(
            &store,
            &protocol,
            Work::DeriveEventLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: 200 * 60_000,
                event_id_in_minute: [0x77; 32],
            },
        )
        .expect("derive above-floor must succeed via sibling cover");
        let Output::DerivedEventLeaf(report) = report else {
            panic!();
        };
        assert!(
            report.local_history_node_secret_id.is_some(),
            "leaf row must materialize from a sibling cover"
        );
        assert!(
            report.leaf_node_secret.is_some(),
            "leaf secret must derive successfully"
        );
    }

    #[test]
    fn chop_then_author_below_floor_errors_with_clear_message() {
        // Authoring at minute 50 after a chop to floor=100 must wedge with
        // the documented "no retained ancestor covers" message — the
        // chopped subtree has been wiped and no sibling covers it.
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let (frontier_id, _) = seed_local_key_secret(&store);

        let _ = run(
            &store,
            &protocol,
            Work::ChopTimeTreePrefix {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                floor_minute: 100,
            },
        )
        .expect("chop");

        let err = run(
            &store,
            &protocol,
            Work::DeriveEventLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: 50 * 60_000,
                event_id_in_minute: [0x42; 32],
            },
        )
        .expect_err("below-floor authoring must wedge with a clear error");
        assert!(
            err.contains("no retained ancestor covers"),
            "expected wedge error mentioning no retained ancestor; got: {err}"
        );
    }

    #[test]
    fn chop_is_deterministic() {
        // Two fresh stores chopped to the same floor must produce
        // byte-identical tombstone rows. cover_summary is the canonical
        // fingerprint of the retained set + tombstones, so we compare it.
        use local_history_node_secret::queries::cover_summary;
        let signer = [0xcd; 32];

        let mk_store = || -> (Store, EventId) {
            let store = Protocol::open_memory_store().expect("store");
            let protocol = Protocol::new();
            let (frontier_id, _) = seed_local_key_secret_with_signer(&store, &signer);
            let _ = run(
                &store,
                &protocol,
                Work::ChopTimeTreePrefix {
                    workspace_id: WORKSPACE,
                    removal_frontier_id: frontier_id,
                    floor_minute: 12345,
                },
            )
            .expect("chop");
            (store, frontier_id)
        };

        let (alice_store, _) = mk_store();
        let (bob_store, _) = mk_store();
        let alice_summary = cover_summary(&alice_store, WORKSPACE).expect("alice summary");
        let bob_summary = cover_summary(&bob_store, WORKSPACE).expect("bob summary");
        assert_eq!(
            alice_summary, bob_summary,
            "cover_summary must be byte-equal across two stores running the \
             same chop (forward-secrecy commitment relies on every peer \
             producing the same fingerprint)"
        );
        // Also sanity-check that tombstone rows are byte-equal directly.
        let mut alice_tombs =
            local_history_node_secret::queries::list_tombstones_for_workspace(
                &alice_store,
                WORKSPACE,
            )
            .expect("alice tombs");
        let mut bob_tombs = local_history_node_secret::queries::list_tombstones_for_workspace(
            &bob_store, WORKSPACE,
        )
        .expect("bob tombs");
        alice_tombs.sort_by(|a, b| a.tombstone_node_id.cmp(&b.tombstone_node_id));
        bob_tombs.sort_by(|a, b| a.tombstone_node_id.cmp(&b.tombstone_node_id));
        assert_eq!(
            alice_tombs, bob_tombs,
            "tombstone rows must be byte-identical across peers"
        );
        assert!(
            !alice_tombs.is_empty(),
            "non-zero floor must produce tombstones"
        );
    }

    #[test]
    fn chop_after_prior_retire_does_not_resurrect_f() {
        // Start with an F-wipe state from a per-leaf RetireDeletedEventLeaf,
        // then chop. F must stay wiped and the chop must complete without
        // errors (sibling fallback for the boundary descent).
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let (frontier_id, _) = seed_local_key_secret(&store);

        // Author two leaves in minute 1 so retire has a sibling structure.
        let coord_a = [0xaa; 32];
        let coord_b = [0xbb; 32];
        for coord in [coord_a, coord_b] {
            let _ = run(
                &store,
                &protocol,
                Work::DeriveEventLeaf {
                    workspace_id: WORKSPACE,
                    removal_frontier_id: frontier_id,
                    created_at_ms: 60_000,
                    event_id_in_minute: coord,
                },
            )
            .expect("derive leaf");
        }
        // Retire one leaf — this wipes F.
        let _ = run(
            &store,
            &protocol,
            Work::RetireDeletedEventLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: 60_000,
                event_id_in_minute: coord_a,
            },
        )
        .expect("retire");
        assert!(
            local_key_secret::queries::get(&store, WORKSPACE, frontier_id)
                .expect("look up F")
                .is_none(),
            "precondition: F must be wiped by the retire"
        );

        // Now chop with a floor above minute 1 so the chop has work to do
        // via the sibling-fallback descent. Use floor_minute = 50.
        let report = run(
            &store,
            &protocol,
            Work::ChopTimeTreePrefix {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                floor_minute: 50,
            },
        )
        .expect("chop after retire must succeed");
        let Output::ChoppedTimeTreePrefix(_report) = report else {
            panic!();
        };

        // F must still be wiped — chop must not resurrect F.
        assert!(
            local_key_secret::queries::get(&store, WORKSPACE, frontier_id)
                .expect("look up F")
                .is_none(),
            "F must remain wiped after chop (chop must not resurrect F)"
        );
    }

    #[test]
    fn chop_subsumes_and_gcs_pre_existing_leaf_tombstones() {
        // Author two leaves in minute 50 (so retire has a sibling structure
        // and writes a non-trivial set of per-leaf tombstones), retire one
        // of them. Then chop with floor_minute = 100. The pre-existing
        // per-leaf tombstones written by the retire all live under
        // minute 50 (range_start + range_width <= 51 <= 100), so the chop
        // must GC them in the same transaction as its wipe and report
        // `subsumed_leaf_tombstones_gcd >= 1`.
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let (frontier_id, _) = seed_local_key_secret(&store);

        let coord_a = [0xaa; 32];
        let coord_b = [0xbb; 32];
        for coord in [coord_a, coord_b] {
            let _ = run(
                &store,
                &protocol,
                Work::DeriveEventLeaf {
                    workspace_id: WORKSPACE,
                    removal_frontier_id: frontier_id,
                    created_at_ms: 50 * 60_000,
                    event_id_in_minute: coord,
                },
            )
            .expect("derive leaf");
        }
        let _ = run(
            &store,
            &protocol,
            Work::RetireDeletedEventLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: 50 * 60_000,
                event_id_in_minute: coord_a,
            },
        )
        .expect("retire leaf at minute 50");

        // Snapshot the pre-chop tombstone set so we can assert the GC
        // strictly removes the subsumed ones.
        let pre_tombs = local_history_node_secret::queries::list_tombstones_for_workspace(
            &store, WORKSPACE,
        )
        .expect("pre-chop tombs");
        let subsumed_pre: Vec<_> = pre_tombs
            .iter()
            .filter(|t| t.removal_frontier_id == frontier_id)
            .filter(|t| t.range_start.saturating_add(t.range_width) <= 100)
            .cloned()
            .collect();
        assert!(
            !subsumed_pre.is_empty(),
            "precondition: retire at minute 50 must produce at least one \
             tombstone whose range fits under floor_minute=100; got {pre_tombs:?}"
        );

        // Now chop to floor=100.
        let report = run(
            &store,
            &protocol,
            Work::ChopTimeTreePrefix {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                floor_minute: 100,
            },
        )
        .expect("chop");
        let Output::ChoppedTimeTreePrefix(report) = report else {
            panic!();
        };
        assert!(
            report.subsumed_leaf_tombstones_gcd >= 1,
            "chop must report at least one subsumed leaf tombstone \
             (subsumed_pre.len() = {}, report = {report:?})",
            subsumed_pre.len(),
        );
        assert!(
            report.subsumed_leaf_tombstones_gcd >= subsumed_pre.len(),
            "chop must GC every subsumed pre-existing tombstone (had {}, \
             report claims {})",
            subsumed_pre.len(),
            report.subsumed_leaf_tombstones_gcd,
        );

        // Verify each pre-existing subsumed tombstone is truly gone from
        // the table.
        let post_tombs = local_history_node_secret::queries::list_tombstones_for_workspace(
            &store, WORKSPACE,
        )
        .expect("post-chop tombs");
        for old in &subsumed_pre {
            assert!(
                !post_tombs.iter().any(|t| {
                    t.removal_frontier_id == old.removal_frontier_id
                        && t.tombstone_node_id == old.tombstone_node_id
                }),
                "subsumed tombstone {:?} must be exact-deleted by the chop GC",
                old.tombstone_node_id,
            );
        }
    }

    #[test]
    fn chop_does_not_gc_tombstones_above_floor() {
        // Retire a leaf at minute 50 AND a leaf at minute 150 (so each
        // produces per-leaf tombstones rooted at their respective minute).
        // Chop with floor_minute = 100. The minute-50 tombstones must be
        // GC'd; the minute-150 tombstones must survive.
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let (frontier_id, _) = seed_local_key_secret(&store);

        let coord_at_50_a = [0xa1; 32];
        let coord_at_50_b = [0xa2; 32];
        let coord_at_150_a = [0xb1; 32];
        let coord_at_150_b = [0xb2; 32];
        for coord in [coord_at_50_a, coord_at_50_b] {
            let _ = run(
                &store,
                &protocol,
                Work::DeriveEventLeaf {
                    workspace_id: WORKSPACE,
                    removal_frontier_id: frontier_id,
                    created_at_ms: 50 * 60_000,
                    event_id_in_minute: coord,
                },
            )
            .expect("derive leaf at 50");
        }
        for coord in [coord_at_150_a, coord_at_150_b] {
            let _ = run(
                &store,
                &protocol,
                Work::DeriveEventLeaf {
                    workspace_id: WORKSPACE,
                    removal_frontier_id: frontier_id,
                    created_at_ms: 150 * 60_000,
                    event_id_in_minute: coord,
                },
            )
            .expect("derive leaf at 150");
        }
        let _ = run(
            &store,
            &protocol,
            Work::RetireDeletedEventLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: 50 * 60_000,
                event_id_in_minute: coord_at_50_a,
            },
        )
        .expect("retire leaf at minute 50");
        let _ = run(
            &store,
            &protocol,
            Work::RetireDeletedEventLeaf {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                created_at_ms: 150 * 60_000,
                event_id_in_minute: coord_at_150_a,
            },
        )
        .expect("retire leaf at minute 150");

        // Snapshot tombstones that should NOT be GC'd: those whose range
        // contains a minute >= 100. The minute-150 leaf tombstone has
        // range_start=150, range_width=1, so range_end=151 > 100 and it
        // must survive the chop.
        let pre_tombs = local_history_node_secret::queries::list_tombstones_for_workspace(
            &store, WORKSPACE,
        )
        .expect("pre-chop tombs");
        let above_floor: Vec<_> = pre_tombs
            .iter()
            .filter(|t| t.removal_frontier_id == frontier_id)
            .filter(|t| t.range_start.saturating_add(t.range_width) > 100)
            .cloned()
            .collect();
        assert!(
            !above_floor.is_empty(),
            "precondition: retire at minute 150 must produce at least one \
             tombstone whose range_end > 100; got {pre_tombs:?}"
        );

        let _ = run(
            &store,
            &protocol,
            Work::ChopTimeTreePrefix {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_id,
                floor_minute: 100,
            },
        )
        .expect("chop");

        // Each above-floor tombstone must still be present after the chop.
        let post_tombs = local_history_node_secret::queries::list_tombstones_for_workspace(
            &store, WORKSPACE,
        )
        .expect("post-chop tombs");
        for survivor in &above_floor {
            assert!(
                post_tombs.iter().any(|t| {
                    t.removal_frontier_id == survivor.removal_frontier_id
                        && t.tombstone_node_id == survivor.tombstone_node_id
                }),
                "tombstone for range [{},{}) must survive a chop to floor=100; \
                 got post={:?}",
                survivor.range_start,
                survivor.range_start + survivor.range_width,
                post_tombs.iter().map(|t| (t.range_start, t.range_width)).collect::<Vec<_>>(),
            );
        }
    }

    #[test]
    fn chop_does_not_gc_tombstones_from_other_frontier() {
        // Seed two distinct removal frontiers under the same workspace.
        // Author + retire a leaf under each to produce per-frontier
        // tombstones. Chop only frontier A. Frontier B's tombstones must
        // be untouched even though they are byte-located under the same
        // workspace prefix.
        let store = Protocol::open_memory_store().expect("store");
        let protocol = Protocol::new();
        let signer_a = core_crypto::random_ed25519_private_key();
        let signer_b = core_crypto::random_ed25519_private_key();
        let (frontier_a, _) = seed_local_key_secret_with_signer(&store, &signer_a);
        let (frontier_b, _) = seed_local_key_secret_with_signer(&store, &signer_b);
        assert_ne!(
            frontier_a, frontier_b,
            "precondition: two distinct frontiers under the same workspace"
        );

        // Author and retire one leaf under each frontier in minute 50.
        for frontier_id in [frontier_a, frontier_b] {
            for coord in [[0xaa; 32], [0xbb; 32]] {
                let _ = run(
                    &store,
                    &protocol,
                    Work::DeriveEventLeaf {
                        workspace_id: WORKSPACE,
                        removal_frontier_id: frontier_id,
                        created_at_ms: 50 * 60_000,
                        event_id_in_minute: coord,
                    },
                )
                .expect("derive leaf");
            }
            let _ = run(
                &store,
                &protocol,
                Work::RetireDeletedEventLeaf {
                    workspace_id: WORKSPACE,
                    removal_frontier_id: frontier_id,
                    created_at_ms: 50 * 60_000,
                    event_id_in_minute: [0xaa; 32],
                },
            )
            .expect("retire leaf");
        }

        let pre_tombs_b: Vec<_> =
            local_history_node_secret::queries::list_tombstones_for_workspace(&store, WORKSPACE)
                .expect("pre-chop tombs")
                .into_iter()
                .filter(|t| t.removal_frontier_id == frontier_b)
                .collect();
        assert!(
            !pre_tombs_b.is_empty(),
            "precondition: frontier B's retire must produce at least one tombstone"
        );

        let _ = run(
            &store,
            &protocol,
            Work::ChopTimeTreePrefix {
                workspace_id: WORKSPACE,
                removal_frontier_id: frontier_a,
                floor_minute: 100,
            },
        )
        .expect("chop frontier A");

        // Every frontier-B tombstone must survive.
        let post_tombs_b: Vec<_> =
            local_history_node_secret::queries::list_tombstones_for_workspace(&store, WORKSPACE)
                .expect("post-chop tombs")
                .into_iter()
                .filter(|t| t.removal_frontier_id == frontier_b)
                .collect();
        assert_eq!(
            pre_tombs_b.len(),
            post_tombs_b.len(),
            "chop on frontier A must not touch any frontier-B tombstone"
        );
        for old in &pre_tombs_b {
            assert!(
                post_tombs_b
                    .iter()
                    .any(|t| t.tombstone_node_id == old.tombstone_node_id),
                "frontier-B tombstone {:?} must survive a chop on frontier A",
                old.tombstone_node_id,
            );
        }
    }
}

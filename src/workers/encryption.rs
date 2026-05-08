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
//! `RetireDeletedEventLeaf` walks the same path, but materializes BOTH children
//! at every split (the descending side becomes the source for the next split,
//! the sibling side covers the rest of the parent's range implicitly). At the
//! bottom the leaf row is purged and exact-deleted, retiring the AEAD key
//! material for the deleted event.

use crate::core::crypto;
use crate::core::logical_clock;
use crate::core::store::Store;
use crate::protocol::event_modules::identity::{endpoint, endpoint_shared};
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    DerivedKeySecrets(DeriveReport),
    RotatedRecipientKey(RotateRecipientKeyReport),
    DerivedEventLeaf(DeriveEventLeafReport),
    RetiredDeletedEventLeaf(RetireDeletedEventLeafReport),
    DrainedPendingMessageLeaves(DrainPendingLeavesReport),
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
    }
}

fn derive_key_secrets<R: EventRegistry>(
    store: &Store,
    registry: &R,
    batch_size: usize,
) -> Result<DeriveReport, String> {
    let mut report = DeriveReport::default();
    for row in key_wrap::schema::list_all(store)? {
        if report.scanned_key_wraps >= batch_size {
            break;
        }
        report.scanned_key_wraps += 1;
        if local_key_secret::schema::get(store, row.workspace_id, row.removal_frontier_id)?
            .is_some()
        {
            continue;
        }
        let Some(recipient) = recipient_key_row(store, row.workspace_id, row.recipient_key_id)?
        else {
            continue;
        };
        let Some(local_recipient) =
            local_recipient_key::schema::list_for_workspace(store, row.workspace_id)?
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

fn root_source(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
) -> Result<DerivationSource, String> {
    let root = local_key_secret::schema::get(store, workspace_id, removal_frontier_id)?
        .ok_or_else(|| "local key secret is missing for removal frontier".to_string())?;
    Ok(DerivationSource {
        secret_id: root.local_key_secret_id,
        secret: root.key_secret,
        range_start: 0,
        range_width: TIME_TREE_ROOT_WIDTH,
        bit_depth: TIME_TREE_BIT_DEPTH,
        event_id_prefix: [0; 32],
    })
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

/// Find the closest materialized ancestor that covers
/// `(unix_minute, 1, TRIE_LEAF_BIT_DEPTH, event_id_in_minute)`. Returns the
/// frontier root's `DerivationSource` if no closer materialized internal
/// exists.
fn closest_retained_ancestor(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    unix_minute: u64,
    event_id_in_minute: EventId,
) -> Result<DerivationSource, String> {
    let mut best = root_source(store, workspace_id, removal_frontier_id)?;
    for row in local_history_node_secret::schema::list_for_frontier(
        store,
        workspace_id,
        removal_frontier_id,
    )? {
        if !covers(&row, unix_minute, event_id_in_minute) {
            continue;
        }
        if more_specific_than(&row, &best) {
            best = DerivationSource {
                secret_id: row.local_history_node_secret_id,
                secret: row.node_secret,
                range_start: row.range_start,
                range_width: row.range_width,
                bit_depth: row.bit_depth,
                event_id_prefix: row.event_id_prefix,
            };
        }
    }
    Ok(best)
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

    if let Some(existing) = local_history_node_secret::schema::get_leaf(
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
        if let Some(existing) = local_history_node_secret::schema::get_minute_node(
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

fn closest_materialized_source_excluding_leaf(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    unix_minute: u64,
    event_id_in_minute: EventId,
) -> Result<MaterializedSource, String> {
    let root = local_key_secret::schema::get(store, workspace_id, removal_frontier_id)?
        .ok_or_else(|| "local key secret is missing for removal frontier".to_string())?;
    let mut best = MaterializedSource {
        secret_id: root.local_key_secret_id,
        secret: root.key_secret,
        range_start: 0,
        range_width: TIME_TREE_ROOT_WIDTH,
        bit_depth: TIME_TREE_BIT_DEPTH,
        event_id_prefix: [0; 32],
        is_root: true,
    };
    for row in local_history_node_secret::schema::list_for_frontier(
        store,
        workspace_id,
        removal_frontier_id,
    )? {
        if !covers(&row, unix_minute, event_id_in_minute) {
            continue;
        }
        // Skip the leaf-being-retired itself (it cannot be its own ancestor).
        if row.bit_depth == TRIE_LEAF_BIT_DEPTH && row.event_id_prefix == event_id_in_minute {
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
        let better = if best.is_root {
            true
        } else if candidate.range_width < best.range_width {
            true
        } else if candidate.range_width > best.range_width {
            false
        } else {
            candidate.bit_depth > best.bit_depth
        };
        if better {
            best = candidate;
        }
    }
    Ok(best)
}

fn closest_materialized_source(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
    unix_minute: u64,
    event_id_in_minute: EventId,
) -> Result<MaterializedSource, String> {
    let root = local_key_secret::schema::get(store, workspace_id, removal_frontier_id)?
        .ok_or_else(|| "local key secret is missing for removal frontier".to_string())?;
    let mut best = MaterializedSource {
        secret_id: root.local_key_secret_id,
        secret: root.key_secret,
        range_start: 0,
        range_width: TIME_TREE_ROOT_WIDTH,
        bit_depth: TIME_TREE_BIT_DEPTH,
        event_id_prefix: [0; 32],
        is_root: true,
    };
    for row in local_history_node_secret::schema::list_for_frontier(
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
        // More specific = smaller range_width OR (equal width and larger bit_depth).
        let better = if best.is_root {
            true
        } else if candidate.range_width < best.range_width {
            true
        } else if candidate.range_width > best.range_width {
            false
        } else {
            candidate.bit_depth > best.bit_depth
        };
        if better {
            best = candidate;
        }
    }
    Ok(best)
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
    let rows = local_history_node_secret::schema::list_for_frontier(
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

/// Retire one event's leaf by walking from the closest retained ancestor
/// down through the time tree to the minute_node and through the trie
/// toward the leaf, materializing both children at every split so siblings
/// retain implicit cover. At the bottom the leaf is purged and exact-deleted.
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
    let leaf_row = local_history_node_secret::schema::get_leaf(
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
        admitted_events: 0,
        purged_event_bytes: 0,
        materialized_internal_rows: 0,
    };

    if leaf_id.is_none() {
        return Ok(report);
    }
    let leaf_id = leaf_id.expect("checked above");

    // Step 1: walk the time tree from the closest retained ancestor down to
    // the minute_node, materializing both children at each split. The
    // leaf-being-retired is NOT a valid ancestor of itself; exclude it from
    // the search so the walk goes back up to a real cover.
    let materialized = collect_materialized_rows(store, workspace_id, removal_frontier_id)?;
    let mut current = closest_materialized_source_excluding_leaf(
        store,
        workspace_id,
        removal_frontier_id,
        unix_minute,
        event_id_in_minute,
    )?;
    while current.range_width > 1 {
        let half = current.range_width / 2;
        let mid = current.range_start + half;
        let (descend_side, descend_start, sibling_side, sibling_start) = if unix_minute < mid {
            (0u8, current.range_start, 1u8, mid)
        } else {
            (1u8, mid, 0u8, current.range_start)
        };
        let parent_start = if current.is_root {
            0
        } else {
            current.range_start
        };
        let parent_width = if current.is_root {
            TIME_TREE_ROOT_WIDTH
        } else {
            current.range_width
        };
        // Descending child first (becomes the new parent).
        let descend = ensure_time_split(
            store,
            registry,
            workspace_id,
            removal_frontier_id,
            current.secret_id,
            current.secret,
            parent_start,
            parent_width,
            descend_side,
            descend_start,
            half,
        )?;
        report.admitted_events += descend.admitted_events;
        if descend.materialized_new_row {
            report.materialized_internal_rows += 1;
        }
        // Sibling child (covers the rest of the parent's range implicitly).
        //
        // At the FINAL time-tree split (parent_width=2, half=1), the
        // sibling-side child is the adjacent minute_node `(M-1, 1)` or
        // `(M+1, 1)` — minutes where no events live. Per the binary-tree
        // FS spec, those adjacent minute_nodes stay implicit under the
        // already-materialized parent at width=2. Skipping the final
        // sibling materialization keeps the row count down and matches
        // the spec's "minute_nodes for adjacent minutes M-1 and M+1 are
        // NOT materialized" assertion.
        if parent_width > 2 {
            let sibling = ensure_time_split(
                store,
                registry,
                workspace_id,
                removal_frontier_id,
                current.secret_id,
                current.secret,
                parent_start,
                parent_width,
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
        current = MaterializedSource {
            secret_id: descend.row_event_id,
            secret: descend.row_secret,
            range_start: descend_start,
            range_width: half,
            bit_depth: TIME_TREE_BIT_DEPTH,
            event_id_prefix: [0; 32],
            is_root: false,
        };
    }
    if current.range_start != unix_minute || current.range_width != 1 {
        return Err("retire walk did not reach the target minute_node".to_string());
    }
    // current is the minute_node row.

    // Step 2: walk the trie from minute_node down to the leaf, materializing
    // both children at every divergence depth implied by surviving leaves.
    let _leaf_node_secret = leaf_row.expect("checked above").node_secret;
    walk_trie_for_retire(
        store,
        registry,
        workspace_id,
        removal_frontier_id,
        unix_minute,
        event_id_in_minute,
        &mut current,
        &mut report,
    )?;
    let _ = materialized;

    // Step 3: purge the leaf canonical bytes and exact-delete the leaf row.
    let purged = store
        .write_transaction(|store| purging::purge_event_storage_in_tx(store, &leaf_id))
        .map_err(|err| format!("purge deleted event leaf bytes: {err}"))?;
    if purged {
        report.purged_event_bytes += 1;
    }
    store
        .delete_table_rows(
            local_history_node_secret::schema::LOCAL_HISTORY_NODE_SECRETS,
            vec![
                local_history_node_secret::schema::local_history_node_secret_key(
                    workspace_id,
                    removal_frontier_id,
                    unix_minute,
                    1,
                    TRIE_LEAF_BIT_DEPTH,
                    event_id_in_minute,
                ),
            ],
        )
        .map_err(|err| format!("delete leaf projection row: {err}"))?;
    Ok(report)
}

fn collect_materialized_rows(
    store: &Store,
    workspace_id: EventId,
    removal_frontier_id: EventId,
) -> Result<Vec<local_history_node_secret::types::LocalHistoryNodeSecretRow>, String> {
    local_history_node_secret::schema::list_for_frontier(store, workspace_id, removal_frontier_id)
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
    if let Some(existing) = local_history_node_secret::schema::get(
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
    if let Some(existing) = local_history_node_secret::schema::get(
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
    minute_node: &mut MaterializedSource,
    report: &mut RetireDeletedEventLeafReport,
) -> Result<(), String> {
    // Compute divergence depths between `leaf_coord` and every other
    // materialized leaf in this minute. Each unique divergence depth
    // requires a sibling internal at that depth (covering the surviving
    // events on the opposite side of the leaf path).
    let trie_rows: Vec<_> = local_history_node_secret::schema::list_leaves(store, workspace_id)?
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
        secret_id: minute_node.secret_id,
        secret: minute_node.secret,
        range_start: unix_minute,
        range_width: 1,
        bit_depth: minute_node.bit_depth,
        event_id_prefix: minute_node.event_id_prefix,
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
        let Some(bytes) = event_schema::event_bytes(store, &blocked_event_id)
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
        if local_key_secret::schema::get(store, workspace_id, removal_frontier_id)?.is_none() {
            continue;
        }
        if event_schema::has_event(store, &leaf_id)
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
        let report = drain_pending_message_leaves(store, app, ctx.options.work_limit)
            .map_err(|err| format!("drain pending message leaves: {err}"))?;
        ctx.report
            .add("derived_message_leaves", report.derived_leaves);
        Ok(())
    }
    Worker {
        name: "encryption_message_leaves",
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
    let local_keys = local_recipient_key::schema::list_for_workspace(store, workspace_id)?;
    let mut active = Vec::new();
    for row in recipient_key::schema::list_for_workspace(store, workspace_id)? {
        if row.endpoint_shared_id != endpoint_shared_id {
            continue;
        }
        let Some(local) = local_keys
            .iter()
            .find(|candidate| candidate.recipient_key == row.recipient_key)
        else {
            continue;
        };
        if recipient_key_tombstone::schema::get(store, workspace_id, row.recipient_key_id)?
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
    let workspace_wraps = key_wrap::schema::list_for_workspace(store, workspace_id)?;
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
            for event_id in &event_ids_to_purge {
                purging::purge_event_storage_in_tx(store, event_id)?;
            }
            Ok(())
        })
        .map_err(|err| format!("purge retired recipient material tx: {err}"))
}

fn next_timestamp(store: &Store) -> Result<u64, String> {
    let max_timestamp =
        event_schema::max_timestamp(store).map_err(|err| format!("load max timestamp: {err}"))?;
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
        let frontier_record = build_signed_frontier_record(&signer_private_key);
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
        let pre_rows = local_history_node_secret::schema::list_for_workspace(&store, WORKSPACE)
            .expect("pre rows");
        assert_eq!(pre_rows.len(), N, "every fresh send admits exactly one leaf row");
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
        assert_eq!(report.purged_event_bytes, 1);

        let post_rows = local_history_node_secret::schema::list_for_workspace(&store, WORKSPACE)
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
        // Time-tree internals + minute_node + sibling time-tree internals
        // are bounded by O(log range_width). With ROOT_WIDTH = 2^63, that
        // is at most ~125 rows even for a maximally-deep walk. Trie
        // internals scale with O(log N) ~ log2(16) = 4 unique divergence
        // depths, each producing 2 internals (descend + sibling) = 8
        // trie rows. Bound the total at 200 to be conservative; what
        // matters is that it does NOT scale with N (so increasing N
        // would not blow this up).
        let internal_row_count = post_rows.len() - leaf_count;
        let time_tree_bound = 2 * 64 + 4; // 64 levels * 2 children + slack
        let trie_bound = 2 * (N as f64).log2().ceil() as usize + 4;
        assert!(
            internal_row_count <= time_tree_bound + trie_bound,
            "internal row count {internal_row_count} must be O(log range + log N), bound {}",
            time_tree_bound + trie_bound,
        );

        // Assert the deleted leaf cannot be looked up.
        assert!(
            local_history_node_secret::schema::get_leaf(
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
    }

    #[test]
    fn delete_does_not_materialize_adjacent_minute_node_rows() {
        // Spec invariant: deleting an event in minute M must NOT materialize
        // the adjacent minute_nodes at (M-1, 1) or (M+1, 1). They stay
        // implicit under the materialized time-tree internal at width=2.
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

        let rows = local_history_node_secret::schema::list_for_workspace(&store, WORKSPACE)
            .expect("rows");
        // Adjacent minute_nodes (range_width=1, bit_depth=0) at minute 99 or 101
        // must not exist.
        for adjacent in [99u64, 101u64] {
            assert!(
                local_history_node_secret::schema::get_minute_node(
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
        // Sanity: minute_node at M=100 IS materialized.
        assert!(
            local_history_node_secret::schema::get_minute_node(
                &store,
                WORKSPACE,
                frontier_id,
                100,
            )
            .expect("lookup")
            .is_some(),
            "minute_node at M=100 must be materialized after delete",
        );
        let _ = rows;
    }

    #[test]
    fn cover_summary_after_sparse_delete_is_logarithmic() {
        // The cover_summary length is O(materialized_rows) by construction
        // (each row contributes COVER_SUMMARY_ROW_LEN bytes). After
        // deleting 1 of N events in a minute, the materialized row count
        // is bounded by O(log range_width + log N), so cover_summary
        // length stays bounded too.
        use local_history_node_secret::schema::{cover_summary, COVER_SUMMARY_ROW_LEN};
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
        let header_len = b"topo cover summary v3".len() + 4;
        let row_count = (summary.len() - header_len) / COVER_SUMMARY_ROW_LEN;
        assert_eq!(
            (summary.len() - header_len) % COVER_SUMMARY_ROW_LEN,
            0,
            "cover_summary row encoding length must be {COVER_SUMMARY_ROW_LEN} bytes",
        );
        // Surviving leaves (N-1) plus log-bounded internals.
        let log_n = (N as f64).log2().ceil() as usize;
        let bound = (N - 1) + 2 * 64 + 4 + 2 * log_n + 4;
        assert!(
            row_count <= bound,
            "cover_summary row count {row_count} must be O(N + log range + log N), bound {bound}",
        );

        // Determinism: a second compute returns the same bytes.
        let again = cover_summary(&store, WORKSPACE).expect("cover_summary again");
        assert_eq!(summary, again);
    }
}

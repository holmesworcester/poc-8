//! Commands for local history range-node secrets.
//!
//! Two domain-separated derivation paths exist:
//!
//! * `derive_time_split` — splits a time-axis range. The parent covers
//!   `(parent_range_start, parent_range_width)`. The child covers
//!   `(child_range_start, child_range_width)` on `child_side` (0 = left,
//!   1 = right). `range_width=1` means the child is a minute_node leaf of
//!   the time tree, sitting at the bridge between time tree and trie tree.
//!   The KDF info encodes
//!   `u64_be(parent_start) || u64_be(parent_width) || u8(child_side)
//!     || u64_be(child_start) || u64_be(child_width)`.
//!
//! * `derive_trie_split` — splits a within-minute hash trie. The parent
//!   trie node sits at `parent_bit_depth` (0 = minute_node) on the same
//!   minute (`range_start`). The child sits at `child_bit_depth` on
//!   `child_side` (0 = bit-0, 1 = bit-1). `child_bit_depth = 256` makes the
//!   child a leaf carrying the full `event_id_in_minute`. Patricia
//!   compression is allowed: a child may sit at any depth past the
//!   parent's depth. The KDF info encodes
//!   `u8(parent_bit_depth) || prefix(parent_bit_depth, 32)
//!     || u8(child_side) || u8(child_bit_depth)
//!     || prefix(child_bit_depth, 32)`.
//!
//! Both paths return one local event whose dependencies are the source
//! secret, the workspace removal frontier, and (optionally) a tombstoned
//! node id. Projection writes the row and exact-deletes the retired row.
//!
//! These are local-only events. Their plaintext `node_secret` is in the
//! canonical bytes; on tombstone, the worker purges the canonical bytes
//! to preserve forward secrecy.

use crate::core::crypto;
use crate::protocol::event_modules::types::{event_id, EventId};
use crate::protocol::event_modules::worker::CommandOutput;
use crate::protocol::wire::Writer;

use super::codec;
use super::types::{
    mask_prefix_to_depth, HistoryNodeSecret, LocalHistoryNodeSecret, TIME_TREE_BIT_DEPTH,
    TRIE_LEAF_BIT_DEPTH,
};

/// Domain-separated tag for time-axis range-tree splits under
/// BLAKE3-keyed-hash. Bumping the tag forces re-derivation.
pub const TIME_SPLIT_DOMAIN: &[u8] = b"topo time split v1";

/// Domain-separated tag for within-minute hash-trie splits under
/// BLAKE3-keyed-hash. Bumping the tag forces re-derivation.
pub const TRIE_SPLIT_DOMAIN: &[u8] = b"topo trie split v1";

/// Implicit time-tree root width used when a leaf is derived directly from
/// the workspace `local_key_secret` (no materialized intermediates). Must
/// match `workers::encryption::TIME_TREE_ROOT_WIDTH`.
pub const ROOT_TIME_TREE_WIDTH: u64 = 1u64 << 63;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeriveTimeSplit {
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    /// Identity of the source-secret event we derive from. May be the
    /// frontier root (`local_key_secret`) or another `local_history_node_secret`.
    pub parent_secret_id: EventId,
    /// Plaintext source-secret material.
    pub parent_secret: HistoryNodeSecret,
    /// Parent's covered range. The frontier root is encoded as
    /// `(parent_range_start=0, parent_range_width=u64::MAX)` to capture the
    /// whole time axis.
    pub parent_range_start: u64,
    pub parent_range_width: u64,
    /// 0 for left half (lower minutes), 1 for right half. Encoded into the
    /// KDF info so left and right children diverge.
    pub child_side: u8,
    pub child_range_start: u64,
    pub child_range_width: u64,
    pub tombstone_node_id: Option<EventId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeriveTrieSplit {
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    /// Identity of the source-secret event we derive from. The parent must
    /// either be a minute_node (`bit_depth=0`) or another trie internal.
    pub parent_secret_id: EventId,
    pub parent_secret: HistoryNodeSecret,
    /// Minute slot the trie lives under. The same value is propagated to the
    /// child since trie depth doesn't change `range_start`.
    pub range_start: u64,
    pub parent_bit_depth: u16,
    pub parent_event_id_prefix: EventId,
    /// 0 for the bit-0 branch, 1 for the bit-1 branch at the parent's depth.
    pub child_side: u8,
    pub child_bit_depth: u16,
    pub child_event_id_prefix: EventId,
    pub tombstone_node_id: Option<EventId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHistoryNodeSecretOutput {
    pub local_history_node_secret_id: EventId,
    pub event: LocalHistoryNodeSecret,
}

pub fn derive_time_split(
    input: DeriveTimeSplit,
) -> Result<CommandOutput<LocalHistoryNodeSecretOutput>, String> {
    validate_id("workspace_id", &input.workspace_id)?;
    validate_id("removal_frontier_id", &input.removal_frontier_id)?;
    validate_id("parent_secret_id", &input.parent_secret_id)?;
    validate_id("parent_secret", &input.parent_secret)?;
    if let Some(tombstone_node_id) = input.tombstone_node_id {
        validate_id("tombstone_node_id", &tombstone_node_id)?;
    }
    if input.child_side > 1 {
        return Err("child_side must be 0 (left) or 1 (right)".to_string());
    }
    codec::validate_range(input.child_range_start, input.child_range_width)?;
    if input.parent_range_width != u64::MAX {
        codec::validate_range(input.parent_range_start, input.parent_range_width)?;
    }

    let info = time_split_info(&input);
    let node_secret = crypto::blake3_keyed_hash(&input.parent_secret, TIME_SPLIT_DOMAIN, &info);
    let event = LocalHistoryNodeSecret {
        workspace_id: input.workspace_id,
        removal_frontier_id: input.removal_frontier_id,
        source_secret_id: input.parent_secret_id,
        range_start: input.child_range_start,
        range_width: input.child_range_width,
        bit_depth: TIME_TREE_BIT_DEPTH,
        event_id_prefix: [0; 32],
        tombstone_node_id: input.tombstone_node_id,
        node_secret,
    };
    let bytes = codec::encode(&event);
    let record = codec::record_from_bytes(bytes)?;
    let value = LocalHistoryNodeSecretOutput {
        local_history_node_secret_id: event_id(&record.canonical_bytes),
        event,
    };
    Ok(CommandOutput::with_events(value, vec![record]))
}

/// Derive a per-event leaf directly from the frontier root
/// (`local_key_secret`). The chain walks the time tree from the implicit
/// root `(0, ROOT_TIME_TREE_WIDTH)` down to `(unix_minute, 1)` then takes
/// one trie split from the minute_node (`bit_depth=0`) to the leaf
/// (`bit_depth=256`). Both walks use the same domain tags as
/// `derive_time_split` and `derive_trie_split`, so a leaf admitted via
/// this fast path is byte-equal to one admitted via materialized
/// intermediates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeriveEventLeafFromRoot {
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    /// Identity of the workspace `local_key_secret` row.
    pub root_secret_id: EventId,
    /// The workspace root key secret material.
    pub root_secret: HistoryNodeSecret,
    pub unix_minute: u64,
    pub event_id_in_minute: EventId,
}

pub fn derive_event_leaf_from_root(
    input: DeriveEventLeafFromRoot,
) -> Result<CommandOutput<LocalHistoryNodeSecretOutput>, String> {
    validate_id("workspace_id", &input.workspace_id)?;
    validate_id("removal_frontier_id", &input.removal_frontier_id)?;
    validate_id("root_secret_id", &input.root_secret_id)?;
    validate_id("root_secret", &input.root_secret)?;

    // Time-tree walk: `ROOT_TIME_TREE_WIDTH → … → 1`.
    let mut current_secret = input.root_secret;
    let mut current_start = 0u64;
    let mut current_width = ROOT_TIME_TREE_WIDTH;
    while current_width > 1 {
        let half = current_width / 2;
        let mid = current_start + half;
        let (child_side, child_start) = if input.unix_minute < mid {
            (0u8, current_start)
        } else {
            (1u8, mid)
        };
        let info =
            time_split_info_bytes(current_start, current_width, child_side, child_start, half);
        current_secret = crypto::blake3_keyed_hash(&current_secret, TIME_SPLIT_DOMAIN, &info);
        current_start = child_start;
        current_width = half;
    }

    // Trie split: from minute_node (`bit_depth=0`) to leaf (`bit_depth=256`).
    let leaf_side = super::types::bit_at(&input.event_id_in_minute, 0);
    let leaf_info = trie_split_info_bytes(
        0,
        [0; 32],
        leaf_side,
        TRIE_LEAF_BIT_DEPTH,
        input.event_id_in_minute,
    );
    let leaf_secret = crypto::blake3_keyed_hash(&current_secret, TRIE_SPLIT_DOMAIN, &leaf_info);

    let event = LocalHistoryNodeSecret {
        workspace_id: input.workspace_id,
        removal_frontier_id: input.removal_frontier_id,
        source_secret_id: input.root_secret_id,
        range_start: input.unix_minute,
        range_width: 1,
        bit_depth: TRIE_LEAF_BIT_DEPTH,
        event_id_prefix: input.event_id_in_minute,
        tombstone_node_id: None,
        node_secret: leaf_secret,
    };
    let bytes = codec::encode(&event);
    let record = codec::record_from_bytes(bytes)?;
    let value = LocalHistoryNodeSecretOutput {
        local_history_node_secret_id: event_id(&record.canonical_bytes),
        event,
    };
    Ok(CommandOutput::with_events(value, vec![record]))
}

fn time_split_info_bytes(
    parent_range_start: u64,
    parent_range_width: u64,
    child_side: u8,
    child_range_start: u64,
    child_range_width: u64,
) -> Vec<u8> {
    let mut out = Writer::with_capacity(8 + 8 + 1 + 8 + 8);
    out.u64(parent_range_start);
    out.u64(parent_range_width);
    out.u8(child_side);
    out.u64(child_range_start);
    out.u64(child_range_width);
    out.finish()
}

fn trie_split_info_bytes(
    parent_bit_depth: u16,
    parent_event_id_prefix: EventId,
    child_side: u8,
    child_bit_depth: u16,
    child_event_id_prefix: EventId,
) -> Vec<u8> {
    let mut out = Writer::with_capacity(2 + 32 + 1 + 2 + 32);
    out.raw(&parent_bit_depth.to_be_bytes());
    let parent_prefix = mask_prefix_to_depth(parent_event_id_prefix, parent_bit_depth);
    out.id(&parent_prefix);
    out.u8(child_side);
    out.raw(&child_bit_depth.to_be_bytes());
    let child_prefix = mask_prefix_to_depth(child_event_id_prefix, child_bit_depth);
    out.id(&child_prefix);
    out.finish()
}

pub fn derive_trie_split(
    input: DeriveTrieSplit,
) -> Result<CommandOutput<LocalHistoryNodeSecretOutput>, String> {
    validate_id("workspace_id", &input.workspace_id)?;
    validate_id("removal_frontier_id", &input.removal_frontier_id)?;
    validate_id("parent_secret_id", &input.parent_secret_id)?;
    validate_id("parent_secret", &input.parent_secret)?;
    if let Some(tombstone_node_id) = input.tombstone_node_id {
        validate_id("tombstone_node_id", &tombstone_node_id)?;
    }
    if input.child_side > 1 {
        return Err("child_side must be 0 (left) or 1 (right)".to_string());
    }
    if input.parent_bit_depth >= TRIE_LEAF_BIT_DEPTH {
        return Err("parent_bit_depth must be less than 256 (parent cannot be a leaf)".to_string());
    }
    if input.child_bit_depth <= input.parent_bit_depth {
        return Err("child_bit_depth must be greater than parent_bit_depth".to_string());
    }
    if input.child_bit_depth > TRIE_LEAF_BIT_DEPTH {
        return Err("child_bit_depth must be at most 256".to_string());
    }
    codec::validate_range(input.range_start, 1)?;

    let info = trie_split_info(&input);
    let node_secret = crypto::blake3_keyed_hash(&input.parent_secret, TRIE_SPLIT_DOMAIN, &info);
    let event = LocalHistoryNodeSecret {
        workspace_id: input.workspace_id,
        removal_frontier_id: input.removal_frontier_id,
        source_secret_id: input.parent_secret_id,
        range_start: input.range_start,
        range_width: 1,
        bit_depth: input.child_bit_depth,
        event_id_prefix: mask_prefix_to_depth(input.child_event_id_prefix, input.child_bit_depth),
        tombstone_node_id: input.tombstone_node_id,
        node_secret,
    };
    let bytes = codec::encode(&event);
    let record = codec::record_from_bytes(bytes)?;
    let value = LocalHistoryNodeSecretOutput {
        local_history_node_secret_id: event_id(&record.canonical_bytes),
        event,
    };
    Ok(CommandOutput::with_events(value, vec![record]))
}

fn time_split_info(input: &DeriveTimeSplit) -> Vec<u8> {
    let mut out = Writer::with_capacity(8 + 8 + 1 + 8 + 8);
    out.u64(input.parent_range_start);
    out.u64(input.parent_range_width);
    out.u8(input.child_side);
    out.u64(input.child_range_start);
    out.u64(input.child_range_width);
    out.finish()
}

fn trie_split_info(input: &DeriveTrieSplit) -> Vec<u8> {
    let mut out = Writer::with_capacity(2 + 32 + 1 + 2 + 32);
    out.raw(&input.parent_bit_depth.to_be_bytes());
    let parent_prefix = mask_prefix_to_depth(input.parent_event_id_prefix, input.parent_bit_depth);
    out.id(&parent_prefix);
    out.u8(input.child_side);
    out.raw(&input.child_bit_depth.to_be_bytes());
    let child_prefix = mask_prefix_to_depth(input.child_event_id_prefix, input.child_bit_depth);
    out.id(&child_prefix);
    out.finish()
}

fn validate_id(name: &str, id: &EventId) -> Result<(), String> {
    if id.iter().all(|byte| *byte == 0) {
        return Err(format!("{name} cannot be empty"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::types::EventScope;

    use super::*;

    fn time_input(child_start: u64, child_width: u64, side: u8) -> DeriveTimeSplit {
        DeriveTimeSplit {
            workspace_id: [1; 32],
            removal_frontier_id: [2; 32],
            parent_secret_id: [3; 32],
            parent_secret: [7; 32],
            parent_range_start: 0,
            parent_range_width: u64::MAX,
            child_side: side,
            child_range_start: child_start,
            child_range_width: child_width,
            tombstone_node_id: None,
        }
    }

    #[test]
    fn time_split_proposes_local_secret_with_source_dependency() {
        let output = derive_time_split(time_input(1_700_000, 1, 0)).expect("derive");
        let record = output.events[0].record();

        assert_eq!(record.scope, EventScope::Local);
        assert_eq!(record.workspace_id, Some([1; 32]));
        assert_eq!(record.dependencies, vec![[2; 32], [3; 32]]);
        assert_eq!(
            output.value.local_history_node_secret_id,
            output.events[0].event_id()
        );
    }

    #[test]
    fn time_split_is_deterministic_and_side_sensitive() {
        let left = derive_time_split(time_input(0, 1, 0)).expect("left").value;
        let right_a = derive_time_split(time_input(1, 1, 1))
            .expect("right_a")
            .value;
        let right_b = derive_time_split(time_input(1, 1, 1))
            .expect("right_b")
            .value;

        assert_eq!(
            right_a.local_history_node_secret_id,
            right_b.local_history_node_secret_id
        );
        assert_eq!(right_a.event.node_secret, right_b.event.node_secret);
        assert_ne!(left.event.node_secret, right_a.event.node_secret);
    }

    #[test]
    fn trie_split_is_deterministic_and_prefix_sensitive() {
        let nonce_a = [0x80; 32];
        let nonce_b = [0xff; 32];
        let mk = |coord: EventId| DeriveTrieSplit {
            workspace_id: [1; 32],
            removal_frontier_id: [2; 32],
            parent_secret_id: [3; 32],
            parent_secret: [7; 32],
            range_start: 100,
            parent_bit_depth: 0,
            parent_event_id_prefix: [0; 32],
            child_side: 1,
            child_bit_depth: TRIE_LEAF_BIT_DEPTH,
            child_event_id_prefix: coord,
            tombstone_node_id: None,
        };
        let left = derive_trie_split(mk(nonce_a)).expect("left").value;
        let same = derive_trie_split(mk(nonce_a)).expect("same").value;
        let other = derive_trie_split(mk(nonce_b)).expect("other").value;

        assert_eq!(
            left.local_history_node_secret_id,
            same.local_history_node_secret_id
        );
        assert_eq!(left.event.node_secret, same.event.node_secret);
        assert_ne!(
            left.local_history_node_secret_id,
            other.local_history_node_secret_id
        );
        assert_ne!(left.event.node_secret, other.event.node_secret);
    }
}

//! Local history range-node key types.
//!
//! These local-only events let filesystem history keys be ordinary events.
//! Their dependency ids make the common event worker sort parent/sibling key
//! material before the node that relies on it.
//!
//! The retained tree is a binary tree on **both** axes:
//!
//!   * Time axis — the outer tree. Internal nodes cover a power-of-two range
//!     of unix-minute slots: `(range_start, range_width)`. The leaf of the
//!     time tree is a `minute_node` at `(unix_minute, 1)` with `bit_depth=0`.
//!     The frontier root (`local_key_secret`) implicitly covers the entire
//!     time axis.
//!   * Within-minute hash trie — the inner tree. Under each minute_node a
//!     Patricia/radix trie keys the surviving events by the bits of their
//!     `event_id_in_minute`. A trie internal at depth `d` carries the first
//!     `d` bits of the prefix and is the divergence point of its two
//!     children. Leaves sit at `bit_depth=256` and store the full
//!     `event_id_in_minute` as `event_id_prefix`.
//!
//! Most nodes are NOT stored — they are derivable from any retained ancestor
//! that covers the desired position. A row is materialized only when:
//!
//!   * It is the frontier root (`local_key_secret`).
//!   * A delete or split made it necessary to durably name the node along a
//!     deletion path or as a retained sibling at a split point.
//!   * It is a leaf (`bit_depth=256`) for an event whose canonical bytes are
//!     still admitted in the local store. Materializing leaves lets the AEAD
//!     path be a single row read instead of a full path walk.

use crate::core::crypto::XChaCha20Poly1305Key;
use crate::protocol::event_modules::types::EventId;

pub type HistoryNodeSecret = XChaCha20Poly1305Key;

/// Trie leaf depth — a leaf row carries the full 256-bit `event_id_in_minute`
/// as `event_id_prefix` and sits at `bit_depth = 256`.
pub const TRIE_LEAF_BIT_DEPTH: u16 = 256;

/// Time-tree node bit depth. Time-tree internals and the minute_node row both
/// sit at `bit_depth = 0`; `event_id_prefix` is zero for them.
pub const TIME_TREE_BIT_DEPTH: u16 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHistoryNodeSecret {
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    pub source_secret_id: EventId,
    /// Time-axis range start (unix minute for `range_width=1`).
    pub range_start: u64,
    /// Time-axis range width (power of two; 1 for minute_node and below).
    pub range_width: u64,
    /// 0 for time-tree internals and minute_nodes; 1..=255 for trie internals;
    /// 256 (`TRIE_LEAF_BIT_DEPTH`) for trie leaves.
    pub bit_depth: u16,
    /// Zero for time-tree nodes; the first `bit_depth` bits of the trie path
    /// for trie internals; the full 256-bit `event_id_in_minute` for leaves.
    pub event_id_prefix: EventId,
    pub tombstone_node_id: Option<EventId>,
    pub node_secret: HistoryNodeSecret,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHistoryNodeSecretRow {
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    pub local_history_node_secret_id: EventId,
    pub source_secret_id: EventId,
    pub range_start: u64,
    pub range_width: u64,
    pub bit_depth: u16,
    pub event_id_prefix: EventId,
    pub tombstone_node_id: Option<EventId>,
    pub node_secret: HistoryNodeSecret,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHistoryNodeTombstoneRow {
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    pub tombstone_node_id: EventId,
    pub replacement_node_id: EventId,
}

/// True if this row's coordinate names a trie leaf (an event's AEAD key
/// material), as opposed to an interior tree node.
pub fn is_leaf_row(row: &LocalHistoryNodeSecretRow) -> bool {
    row.bit_depth == TRIE_LEAF_BIT_DEPTH
}

/// True if this row's coordinate names a minute_node (the bridge between time
/// tree and trie tree), at `(unix_minute, 1)` with `bit_depth=0`.
pub fn is_minute_node_row(row: &LocalHistoryNodeSecretRow) -> bool {
    row.bit_depth == TIME_TREE_BIT_DEPTH && row.range_width == 1
}

/// Mask `event_id_prefix` to its first `bit_depth` bits, zeroing the rest.
/// Trie node prefixes are stored zero-padded so equal coordinates encode
/// equal bytes.
pub fn mask_prefix_to_depth(prefix: EventId, bit_depth: u16) -> EventId {
    if bit_depth == 0 {
        return [0; 32];
    }
    if bit_depth >= TRIE_LEAF_BIT_DEPTH {
        return prefix;
    }
    let mut out = prefix;
    let full_bytes = (bit_depth / 8) as usize;
    let remaining_bits = (bit_depth % 8) as u8;
    if remaining_bits > 0 {
        let keep = 8 - remaining_bits;
        let mask = (0xffu8 << keep) & 0xff;
        out[full_bytes] &= mask;
        for byte in &mut out[full_bytes + 1..] {
            *byte = 0;
        }
    } else {
        for byte in &mut out[full_bytes..] {
            *byte = 0;
        }
    }
    out
}

/// Read the bit at `bit_index` (0 = MSB of byte 0) from a 32-byte event id.
/// Returns 0 or 1.
pub fn bit_at(id: &EventId, bit_index: u16) -> u8 {
    debug_assert!(bit_index < 256, "bit index out of range");
    let byte = (bit_index / 8) as usize;
    let shift = 7 - (bit_index % 8) as u8;
    (id[byte] >> shift) & 0x01
}

/// First bit index where two 256-bit ids diverge, in MSB order. Returns 256
/// if the ids are equal.
pub fn first_diverging_bit(a: &EventId, b: &EventId) -> u16 {
    for byte_idx in 0..32 {
        let xor = a[byte_idx] ^ b[byte_idx];
        if xor != 0 {
            // Find leading-bit position within the byte.
            let leading = xor.leading_zeros() as u16;
            return (byte_idx as u16) * 8 + leading;
        }
    }
    TRIE_LEAF_BIT_DEPTH
}

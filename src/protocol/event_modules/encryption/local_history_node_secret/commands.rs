//! Commands for local history range-node secrets.
//!
//! Derivation is deterministic from the source secret, range, frontier,
//! `event_id_in_minute`, and optional tombstone id. The KDF is BLAKE3 keyed
//! hash with explicit domain separation; HKDF-SHA256 was used in v1 and is no
//! longer compatible.
//!
//! The command returns one local event and does not write tombstone rows
//! directly; projection owns row replacement semantics after the common worker
//! has loaded dependencies.

use crate::core::crypto;
use crate::protocol::event_modules::types::{event_id, EventId};
use crate::protocol::event_modules::worker::CommandOutput;
use crate::protocol::wire::Writer;

use super::codec;
use super::types::{HistoryNodeSecret, LocalHistoryNodeSecret};

/// Domain-separated tag for `local_history_node_secret` derivation under
/// BLAKE3-keyed-hash. `v2` differentiates this output set from the v1
/// HKDF-SHA256 derivation that did not include `event_id_in_minute`.
const HISTORY_NODE_DOMAIN: &[u8] = b"topo local history node secret v2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeriveHistoryNodeSecret {
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    pub source_secret_id: EventId,
    pub source_secret: HistoryNodeSecret,
    pub range_start: u64,
    pub range_width: u64,
    pub event_id_in_minute: Option<EventId>,
    pub tombstone_node_id: Option<EventId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHistoryNodeSecretOutput {
    pub local_history_node_secret_id: EventId,
    pub event: LocalHistoryNodeSecret,
}

pub fn derive(
    input: DeriveHistoryNodeSecret,
) -> Result<CommandOutput<LocalHistoryNodeSecretOutput>, String> {
    validate_id("workspace_id", &input.workspace_id)?;
    validate_id("removal_frontier_id", &input.removal_frontier_id)?;
    validate_id("source_secret_id", &input.source_secret_id)?;
    validate_id("source_secret", &input.source_secret)?;
    if let Some(event_id_in_minute) = input.event_id_in_minute {
        validate_id("event_id_in_minute", &event_id_in_minute)?;
    }
    if let Some(tombstone_node_id) = input.tombstone_node_id {
        validate_id("tombstone_node_id", &tombstone_node_id)?;
    }
    codec::validate_range(input.range_start, input.range_width)?;

    let node_secret = crypto::blake3_keyed_hash(
        &input.source_secret,
        HISTORY_NODE_DOMAIN,
        &associated_data(&input),
    );
    let event = LocalHistoryNodeSecret {
        workspace_id: input.workspace_id,
        removal_frontier_id: input.removal_frontier_id,
        source_secret_id: input.source_secret_id,
        range_start: input.range_start,
        range_width: input.range_width,
        event_id_in_minute: input.event_id_in_minute,
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

fn associated_data(input: &DeriveHistoryNodeSecret) -> Vec<u8> {
    let mut out = Writer::with_capacity(32 + 32 + 32 + 8 + 8 + 32 + 32);
    out.id(&input.workspace_id);
    out.id(&input.removal_frontier_id);
    out.id(&input.source_secret_id);
    out.u64(input.range_start);
    out.u64(input.range_width);
    out.id(&input.event_id_in_minute.unwrap_or([0; 32]));
    out.id(&input.tombstone_node_id.unwrap_or([0; 32]));
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

    fn input(range_start: u64, event_id_in_minute: Option<[u8; 32]>) -> DeriveHistoryNodeSecret {
        DeriveHistoryNodeSecret {
            workspace_id: [1; 32],
            removal_frontier_id: [2; 32],
            source_secret_id: [3; 32],
            source_secret: [7; 32],
            range_start,
            range_width: 1,
            event_id_in_minute,
            tombstone_node_id: None,
        }
    }

    #[test]
    fn derive_proposes_local_secret_with_source_dependency() {
        let output = derive(input(1_700_000, None)).expect("derive");
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
    fn derive_is_deterministic_and_event_id_in_minute_sensitive() {
        let nonce_a = [9; 32];
        let nonce_b = [10; 32];
        let left = derive(input(1_700_000, Some(nonce_a))).expect("left").value;
        let right = derive(input(1_700_000, Some(nonce_a))).expect("right").value;
        let other = derive(input(1_700_000, Some(nonce_b))).expect("other").value;
        let minute = derive(input(1_700_000, None)).expect("minute").value;

        assert_eq!(
            left.local_history_node_secret_id,
            right.local_history_node_secret_id
        );
        assert_eq!(left.event.node_secret, right.event.node_secret);
        assert_ne!(
            left.local_history_node_secret_id,
            other.local_history_node_secret_id
        );
        assert_ne!(left.event.node_secret, other.event.node_secret);
        assert_ne!(left.event.node_secret, minute.event.node_secret);
        assert_ne!(
            left.local_history_node_secret_id,
            minute.local_history_node_secret_id
        );
    }
}

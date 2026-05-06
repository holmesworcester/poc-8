//! Codec for local history range-node secrets.

use crate::core::crypto::XCHACHA20_POLY1305_KEY_BYTES;
use crate::protocol::event_modules::types::{EventId, EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::types::LocalHistoryNodeSecret;

pub const TYPE_LOCAL_HISTORY_NODE_SECRET: u8 = 145;
pub const LOCAL_HISTORY_NODE_SECRET_WIRE_SIZE: usize =
    1 + 32 + 32 + 32 + 8 + 8 + 32 + XCHACHA20_POLY1305_KEY_BYTES;

pub fn encode(event: &LocalHistoryNodeSecret) -> Vec<u8> {
    let mut out = Writer::with_capacity(LOCAL_HISTORY_NODE_SECRET_WIRE_SIZE);
    out.u8(TYPE_LOCAL_HISTORY_NODE_SECRET);
    out.id(&event.workspace_id);
    out.id(&event.removal_frontier_id);
    out.id(&event.source_secret_id);
    out.u64(event.range_start);
    out.u64(event.range_width);
    out.id(&event.tombstone_node_id.unwrap_or([0; 32]));
    out.id(&event.node_secret);
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<LocalHistoryNodeSecret, String> {
    let mut reader = Reader::new(bytes, "local history node secret");
    let tag = reader.u8()?;
    if tag != TYPE_LOCAL_HISTORY_NODE_SECRET {
        return Err("expected local history node secret".to_string());
    }
    let workspace_id = reader.id()?;
    let removal_frontier_id = reader.id()?;
    let source_secret_id = reader.id()?;
    let range_start = reader.u64()?;
    let range_width = reader.u64()?;
    let tombstone_node_id = reader.id()?;
    let event = LocalHistoryNodeSecret {
        workspace_id,
        removal_frontier_id,
        source_secret_id,
        range_start,
        range_width,
        tombstone_node_id: (!is_zero(&tombstone_node_id)).then_some(tombstone_node_id),
        node_secret: reader.id()?,
    };
    reader.finish()?;
    validate(&event)?;
    Ok(event)
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let event = decode(&bytes)?;
    let mut dependencies = Vec::with_capacity(3);
    push_unique(&mut dependencies, event.removal_frontier_id);
    push_unique(&mut dependencies, event.source_secret_id);
    if let Some(tombstone_node_id) = event.tombstone_node_id {
        push_unique(&mut dependencies, tombstone_node_id);
    }
    Ok(EventRecord {
        timestamp: 0,
        body_len: 0,
        canonical_bytes: bytes,
        dependencies,
        workspace_id: Some(event.workspace_id),
        scope: EventScope::Local,
    })
}

pub fn validate_range(range_start: u64, range_width: u64) -> Result<(), String> {
    if range_width == 0 {
        return Err("local history node range width cannot be zero".to_string());
    }
    if !range_width.is_power_of_two() {
        return Err("local history node range width must be a power of two".to_string());
    }
    if !range_start.is_multiple_of(range_width) {
        return Err("local history node range start must align to width".to_string());
    }
    Ok(())
}

fn validate(event: &LocalHistoryNodeSecret) -> Result<(), String> {
    if is_zero(&event.workspace_id) {
        return Err("local history node workspace cannot be empty".to_string());
    }
    if is_zero(&event.removal_frontier_id) {
        return Err("local history node removal_frontier_id cannot be empty".to_string());
    }
    if is_zero(&event.source_secret_id) {
        return Err("local history node source_secret_id cannot be empty".to_string());
    }
    if is_zero(&event.node_secret) {
        return Err("local history node material cannot be empty".to_string());
    }
    validate_range(event.range_start, event.range_width)?;
    Ok(())
}

fn push_unique(out: &mut Vec<EventId>, id: EventId) {
    if !out.iter().any(|candidate| candidate == &id) {
        out.push(id);
    }
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::types::EventScope;

    use super::super::commands;
    use super::*;

    #[test]
    fn roundtrips_local_history_node_secret() {
        let event = commands::derive(commands::DeriveHistoryNodeSecret {
            workspace_id: [1; 32],
            removal_frontier_id: [2; 32],
            source_secret_id: [3; 32],
            source_secret: [7; 32],
            range_start: 8,
            range_width: 8,
            tombstone_node_id: Some([4; 32]),
        })
        .expect("derive")
        .value
        .event;

        assert_eq!(decode(&encode(&event)).expect("decode"), event);
    }

    #[test]
    fn record_is_local_and_depends_on_source_frontier_and_tombstoned_node() {
        let output = commands::derive(commands::DeriveHistoryNodeSecret {
            workspace_id: [1; 32],
            removal_frontier_id: [2; 32],
            source_secret_id: [3; 32],
            source_secret: [7; 32],
            range_start: 8,
            range_width: 8,
            tombstone_node_id: Some([4; 32]),
        })
        .expect("derive");
        let record = output.events[0].record();

        assert_eq!(record.scope, EventScope::Local);
        assert_eq!(record.workspace_id, Some([1; 32]));
        assert_eq!(record.dependencies, vec![[2; 32], [3; 32], [4; 32]]);
    }

    #[test]
    fn rejects_non_canonical_range() {
        let mut event = commands::derive(commands::DeriveHistoryNodeSecret {
            workspace_id: [1; 32],
            removal_frontier_id: [2; 32],
            source_secret_id: [3; 32],
            source_secret: [7; 32],
            range_start: 3,
            range_width: 8,
            tombstone_node_id: None,
        })
        .expect_err("unaligned range must fail");

        assert_eq!(event, "local history node range start must align to width");

        event = validate_range(0, 7).expect_err("non power of two must fail");
        assert_eq!(
            event,
            "local history node range width must be a power of two"
        );
    }
}

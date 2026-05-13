//! Message projection rows.
//!
//! Rows are keyed by `workspace_id || message_id` so list queries can scan all
//! messages in one workspace with a bounded prefix scan. Author and signer ids
//! are stored alongside the text so display queries can join with users without
//! re-decoding canonical bytes.
//!
//! Reads (lookups, scans, tombstone-existence queries) live in
//! `queries.rs`. The receive-side admit gate (`admit_check_received`)
//! stays here for now because the projector boundary rule treats
//! projector.rs as a pure transform that cannot consult storage; routing
//! the gate through projector.rs would also force projector.rs to depend
//! on the queries module, which the boundary rule forbids.

use crate::core::store::{Schema, Store, TableName, TableRow};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::AdmitDecision;
use crate::protocol::wire::{Reader, Writer};

use super::codec;
use super::queries;
use super::types::{
    unix_minute_for, MessageCiphertext, MessageEvent, MessagePlaintext, MessageRow, EXPIRES_NEVER,
    MESSAGE_CIPHERTEXT_BYTES, MESSAGE_TEXT_BYTES, UNIX_MINUTE_MS,
};

pub const MESSAGES: TableName = TableName::new("content.messages");
pub const SEALED_MESSAGES: TableName = TableName::new("content.sealed_messages");
pub const MESSAGE_TOMBSTONES: TableName = TableName::new("content.message_tombstones");

pub const SCHEMAS: &[Schema] = &[
    Schema::durable_row_table("content.messages.v2", MESSAGES),
    Schema::durable_row_table("content.sealed_messages.v4", SEALED_MESSAGES),
    Schema::durable_row_table("content.message_tombstones.v2", MESSAGE_TOMBSTONES),
];

/// Receive-side admission gate for signed message events.
///
/// Runs in the common pipeline's `drain_canonical_in` step before storage,
/// so message bytes whose id is already tombstoned (a previous TTL expiry or
/// author deletion has fired) never re-enter `EVENTS` or the in-memory
/// admitted-event index. If the message's stamped `expires_at_minute` is
/// past the local logical clock, the gate writes a tombstone row directly
/// and drops the bytes; this catches re-deliveries after a previous local
/// expiry, and replaces the projector's old `is_expired_at_receive` branch
/// (which fired too late, after the bytes were already stored).
pub fn admit_check_received(store: &Store, bytes: &[u8]) -> Result<AdmitDecision, String> {
    let envelope = codec::decode_signed(bytes)?;
    let event = codec::decode(&envelope.payload)?;
    let event_id = crate::protocol::event_modules::types::event_id(bytes);
    if queries::message_tombstone_exists(store, event.workspace_id, event_id)? {
        return Ok(AdmitDecision::Drop);
    }
    if event.expires_at_minute == EXPIRES_NEVER {
        return Ok(AdmitDecision::Admit);
    }
    let Some(now_ms) = crate::core::logical_clock::logical_time(store)? else {
        return Ok(AdmitDecision::Admit);
    };
    if event.expires_at_minute >= now_ms / UNIX_MINUTE_MS {
        return Ok(AdmitDecision::Admit);
    }
    let row = message_tombstone_row(
        event.workspace_id,
        event_id,
        event.author_user_id,
        unix_minute_for(event.created_at_ms),
    );
    Ok(AdmitDecision::WriteRowsAndDrop(vec![row]))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedMessageRow {
    pub workspace_id: EventId,
    pub message_id: EventId,
    pub created_at_ms: u64,
    pub author_user_id: EventId,
    pub signer_endpoint_shared_id: EventId,
    pub removal_frontier_id: EventId,
    pub local_history_node_secret_id: EventId,
    /// Authoring-time expiry stamped into canonical bytes; surfaces here so
    /// the disappearing-minute worker can enumerate expired minutes and the
    /// projector can reject expired-at-receive messages.
    pub expires_at_minute: u64,
    /// Reference to the disappearing-messages policy this message was
    /// authored under. Either a signed `disappearing_messages_setting`
    /// event id or the workspace event id (slice-1 fallback).
    pub disappearing_setting_id: EventId,
    pub nonce: crate::core::crypto::XChaCha20Poly1305Nonce,
    pub ciphertext: MessageCiphertext,
}

pub fn message_row(
    message_id: EventId,
    signer_endpoint_shared_id: EventId,
    event: &MessagePlaintext,
) -> Result<TableRow, String> {
    Ok(TableRow {
        table: MESSAGES,
        key: message_key(event.workspace_id, message_id),
        value: encode_value(signer_endpoint_shared_id, event)?,
    })
}

pub fn message_key(workspace_id: EventId, message_id: EventId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&message_id);
    key
}

pub fn sealed_message_row(
    message_id: EventId,
    signer_endpoint_shared_id: EventId,
    event: &MessageEvent,
) -> Result<TableRow, String> {
    Ok(TableRow {
        table: SEALED_MESSAGES,
        key: message_key(event.workspace_id, message_id),
        value: encode_sealed_value(signer_endpoint_shared_id, event),
    })
}

pub fn decode_sealed_message_row(key: &[u8], value: &[u8]) -> Result<SealedMessageRow, String> {
    if key.len() != 64 {
        return Err("sealed message row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut message_id = [0; 32];
    message_id.copy_from_slice(&key[32..64]);

    let mut reader = Reader::new(value, "sealed message row");
    let created_at_ms = reader.u64()?;
    let author_user_id = reader.id()?;
    let signer_endpoint_shared_id = reader.id()?;
    let removal_frontier_id = reader.id()?;
    let local_history_node_secret_id = reader.id()?;
    let expires_at_minute = reader.u64()?;
    let disappearing_setting_id = reader.id()?;
    let nonce = reader
        .bytes(crate::core::crypto::XCHACHA20_POLY1305_NONCE_BYTES)?
        .try_into()
        .map_err(|_| "sealed message row nonce length mismatch".to_string())?;
    let ciphertext = reader
        .bytes(MESSAGE_CIPHERTEXT_BYTES)?
        .try_into()
        .map_err(|_| "sealed message row ciphertext length mismatch".to_string())?;
    reader.finish()?;
    Ok(SealedMessageRow {
        workspace_id,
        message_id,
        created_at_ms,
        author_user_id,
        signer_endpoint_shared_id,
        removal_frontier_id,
        local_history_node_secret_id,
        expires_at_minute,
        disappearing_setting_id,
        nonce,
        ciphertext,
    })
}

pub fn message_tombstone_row(
    workspace_id: EventId,
    message_id: EventId,
    author_user_id: EventId,
    authored_minute: u64,
) -> TableRow {
    let mut value = Vec::with_capacity(32 + 8);
    value.extend_from_slice(&author_user_id);
    value.extend_from_slice(&authored_minute.to_be_bytes());
    TableRow {
        table: MESSAGE_TOMBSTONES,
        key: message_key(workspace_id, message_id),
        value,
    }
}

/// Decoded view of a `MESSAGE_TOMBSTONES` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageTombstoneRow {
    pub workspace_id: EventId,
    pub message_id: EventId,
    pub author_user_id: EventId,
    /// Authoring minute = `created_at_ms / UNIX_MINUTE_MS`. Stored so the
    /// chop GC can decide whether this tombstone is subsumed by a new
    /// chop floor.
    pub authored_minute: u64,
}

pub fn decode_message_tombstone_row(
    key: &[u8],
    value: &[u8],
) -> Result<MessageTombstoneRow, String> {
    if key.len() != 64 {
        return Err("message tombstone row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut message_id = [0; 32];
    message_id.copy_from_slice(&key[32..64]);
    if value.len() != 40 {
        return Err(format!(
            "message tombstone row value length {} expected 40",
            value.len()
        ));
    }
    let mut author_user_id = [0; 32];
    author_user_id.copy_from_slice(&value[..32]);
    let authored_minute = u64::from_be_bytes(
        value[32..40]
            .try_into()
            .map_err(|_| "message tombstone authored minute malformed".to_string())?,
    );
    Ok(MessageTombstoneRow {
        workspace_id,
        message_id,
        author_user_id,
        authored_minute,
    })
}

pub fn decode_message_row(key: &[u8], value: &[u8]) -> Result<MessageRow, String> {
    if key.len() != 64 {
        return Err("message row key is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut message_id = [0; 32];
    message_id.copy_from_slice(&key[32..64]);

    let mut reader = Reader::new(value, "message row");
    let created_at_ms = reader.u64()?;
    let author_user_id = reader.id()?;
    let signer_endpoint_shared_id = reader.id()?;
    let text = codec::decode_text_slot(reader.slice(MESSAGE_TEXT_BYTES)?)?;
    reader.finish()?;

    Ok(MessageRow {
        workspace_id,
        message_id,
        created_at_ms,
        author_user_id,
        signer_endpoint_shared_id,
        text,
    })
}

fn encode_value(
    signer_endpoint_shared_id: EventId,
    event: &MessagePlaintext,
) -> Result<Vec<u8>, String> {
    let text = codec::encode_text_slot(&event.text)?;
    let mut out = Writer::with_capacity(8 + 32 + 32 + MESSAGE_TEXT_BYTES);
    out.u64(event.created_at_ms);
    out.id(&event.author_user_id);
    out.id(&signer_endpoint_shared_id);
    out.raw(&text);
    Ok(out.finish())
}

fn encode_sealed_value(signer_endpoint_shared_id: EventId, event: &MessageEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(
        8 + 32
            + 32
            + 32
            + 32
            + 8
            + 32
            + crate::core::crypto::XCHACHA20_POLY1305_NONCE_BYTES
            + MESSAGE_CIPHERTEXT_BYTES,
    );
    out.u64(event.created_at_ms);
    out.id(&event.author_user_id);
    out.id(&signer_endpoint_shared_id);
    out.id(&event.removal_frontier_id);
    out.id(&event.local_history_node_secret_id);
    out.u64(event.expires_at_minute);
    out.id(&event.disappearing_setting_id);
    out.raw(&event.nonce);
    out.raw(&event.ciphertext);
    out.finish()
}

#[cfg(test)]
mod tests {
    use crate::core::logical_clock;
    use crate::protocol::event_modules::types::event_id;
    use crate::protocol::Protocol;

    use super::*;

    /// Build a signed message canonical record. The bytes are *not* admitted
    /// to EVENTS — the gate runs before storage, so the tests assert the
    /// gate's decision against bytes alone.
    fn signed_message_bytes(
        workspace_id: [u8; 32],
        author_user_id: [u8; 32],
        created_at_ms: u64,
        expires_at_minute: u64,
    ) -> Vec<u8> {
        let inner = MessageEvent {
            workspace_id,
            created_at_ms,
            author_user_id,
            removal_frontier_id: [30; 32],
            local_history_node_secret_id: [40; 32],
            expires_at_minute,
            disappearing_setting_id: workspace_id,
            nonce: [0; 24],
            ciphertext: [0; MESSAGE_CIPHERTEXT_BYTES],
        };
        let payload = codec::encode(&inner);
        let envelope = codec::sign([8; 32], &[7; 32], payload);
        codec::encode_signed(&envelope)
    }

    #[test]
    fn admit_passes_message_with_no_tombstone_and_no_clock() {
        let store = Protocol::open_memory_store().expect("store");
        let bytes = signed_message_bytes([1; 32], [2; 32], 0, EXPIRES_NEVER);
        let decision = admit_check_received(&store, &bytes).expect("admit");
        assert_eq!(decision, AdmitDecision::Admit);
    }

    #[test]
    fn admit_drops_message_with_existing_tombstone_silently() {
        let store = Protocol::open_memory_store().expect("store");
        let workspace_id = [7; 32];
        let author_user_id = [3; 32];
        let bytes = signed_message_bytes(workspace_id, author_user_id, 0, EXPIRES_NEVER);
        let id = event_id(&bytes);

        // Pre-write the tombstone exactly as the disappearing-minute worker
        // or content_purge worker would.
        store
            .insert_table_rows(vec![message_tombstone_row(workspace_id, id, author_user_id, 0)])
            .expect("insert tombstone");

        let decision = admit_check_received(&store, &bytes).expect("admit");
        assert_eq!(decision, AdmitDecision::Drop);

        // EVENTS must remain unchanged: the canonical bytes were not
        // inserted by the gate, and no projector ran.
        assert!(
            crate::protocol::event_modules::schema::event_bytes(&store, &id)
                .expect("event bytes")
                .is_none(),
            "EVENTS must stay empty when the gate drops"
        );
        // The pre-existing tombstone must still be the only one.
        let tombstones =
            queries::list_message_tombstones_for_workspace(&store, workspace_id).expect("list");
        assert_eq!(tombstones.len(), 1);
    }

    #[test]
    fn admit_drops_expired_at_receive_message_at_admission() {
        let store = Protocol::open_memory_store().expect("store");
        let workspace_id = [9; 32];
        let author_user_id = [4; 32];
        let created_at_ms = 100 * UNIX_MINUTE_MS;
        let bytes = signed_message_bytes(workspace_id, author_user_id, created_at_ms, 101);
        let id = event_id(&bytes);

        // Pin the local clock past the message's stamped expiry.
        logical_clock::set_logical_time(&store, 102 * UNIX_MINUTE_MS).expect("set clock");

        let decision = admit_check_received(&store, &bytes).expect("admit");
        let rows = match decision {
            AdmitDecision::WriteRowsAndDrop(rows) => rows,
            other => panic!("expected WriteRowsAndDrop, got {other:?}"),
        };
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].table, MESSAGE_TOMBSTONES);

        // Apply the gate's row writes (drain_canonical_in does this in the
        // same transaction). After the gate's tombstone is in place, the
        // EVENTS row must still be absent.
        store.insert_table_rows(rows).expect("insert tombstone");
        assert!(
            crate::protocol::event_modules::schema::event_bytes(&store, &id)
                .expect("event bytes")
                .is_none(),
            "EVENTS must stay empty when the gate drops"
        );
        // A subsequent admit attempt now hits the existing-tombstone branch.
        let again = admit_check_received(&store, &bytes).expect("admit again");
        assert_eq!(again, AdmitDecision::Drop);
    }

    #[test]
    fn admit_passes_finite_expiry_message_when_clock_is_before_expiry() {
        let store = Protocol::open_memory_store().expect("store");
        let workspace_id = [11; 32];
        let author_user_id = [5; 32];
        let created_at_ms = 100 * UNIX_MINUTE_MS;
        // Stamped expiry = 105; clock = 102 -> not expired yet.
        let bytes = signed_message_bytes(workspace_id, author_user_id, created_at_ms, 105);
        logical_clock::set_logical_time(&store, 102 * UNIX_MINUTE_MS).expect("set clock");
        let decision = admit_check_received(&store, &bytes).expect("admit");
        assert_eq!(decision, AdmitDecision::Admit);
    }

    #[test]
    fn admit_passes_never_expire_message_at_any_clock() {
        let store = Protocol::open_memory_store().expect("store");
        let workspace_id = [13; 32];
        let author_user_id = [6; 32];
        let bytes = signed_message_bytes(workspace_id, author_user_id, 0, EXPIRES_NEVER);
        logical_clock::set_logical_time(&store, u64::MAX - 1).expect("set clock");
        let decision = admit_check_received(&store, &bytes).expect("admit");
        assert_eq!(decision, AdmitDecision::Admit);
    }
}

//! Codec for local invite-accepted events.
//!
//! The format is fixed-width and intentionally contains no raw secret. The
//! secret-bearing event is an immediate dependency, so common admission provides
//! it to the projector and out-of-order replay blocks until the secret arrives.
//! Keeping the event timestamp-free makes re-accepting the same link from the
//! same endpoint produce the same local event id instead of accumulating retry
//! rows that differ only by wall-clock timing.

use crate::protocol::event_modules::types::{EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::types::InviteAcceptedEvent;

pub const TYPE_INVITE_ACCEPTED: u8 = 146;
pub const INVITE_ACCEPTED_WIRE_SIZE: usize = 1 + 32 + 32 + 32 + 32 + 32;

pub fn encode(event: &InviteAcceptedEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(INVITE_ACCEPTED_WIRE_SIZE);
    out.u8(TYPE_INVITE_ACCEPTED);
    out.id(&event.workspace_id);
    out.id(&event.invite_event_id);
    out.id(&event.invite_secret_event_id);
    out.id(&event.bootstrap_hash);
    out.id(&event.accepted_endpoint_id);
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<InviteAcceptedEvent, String> {
    let mut reader = Reader::new(bytes, "invite_accepted");
    let tag = reader.u8()?;
    if tag != TYPE_INVITE_ACCEPTED {
        return Err("expected invite_accepted".to_string());
    }
    let event = InviteAcceptedEvent {
        workspace_id: reader.id()?,
        invite_event_id: reader.id()?,
        invite_secret_event_id: reader.id()?,
        bootstrap_hash: reader.id()?,
        accepted_endpoint_id: reader.id()?,
    };
    reader.finish()?;
    validate(&event)?;
    Ok(event)
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let event = decode(&bytes)?;
    Ok(EventRecord {
        timestamp: 0,
        body_len: bytes.len(),
        canonical_bytes: bytes,
        dependencies: vec![event.invite_secret_event_id],
        workspace_id: Some(event.workspace_id),
        scope: EventScope::Local,
    })
}

fn validate(event: &InviteAcceptedEvent) -> Result<(), String> {
    validate_id("invite_accepted workspace_id", &event.workspace_id)?;
    validate_id("invite_accepted invite_event_id", &event.invite_event_id)?;
    validate_id(
        "invite_accepted invite_secret_event_id",
        &event.invite_secret_event_id,
    )?;
    validate_id("invite_accepted bootstrap_hash", &event.bootstrap_hash)?;
    validate_id(
        "invite_accepted accepted_endpoint_id",
        &event.accepted_endpoint_id,
    )?;
    Ok(())
}

fn validate_id(name: &str, id: &[u8; 32]) -> Result<(), String> {
    if id.iter().all(|byte| *byte == 0) {
        return Err(format!("{name} cannot be empty"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::types::EventScope;

    use super::*;

    fn event() -> InviteAcceptedEvent {
        InviteAcceptedEvent {
            workspace_id: [1; 32],
            invite_event_id: [2; 32],
            invite_secret_event_id: [3; 32],
            bootstrap_hash: [4; 32],
            accepted_endpoint_id: [5; 32],
        }
    }

    /// Invariant: invite_accepted canonical bytes round-trip without deriving
    /// any hidden state outside the fixed event fields.
    #[test]
    fn roundtrips_fixed_width_invite_accepted_event() {
        let encoded = encode(&event());

        assert_eq!(encoded.len(), INVITE_ACCEPTED_WIRE_SIZE);
        assert_eq!(decode(&encoded).expect("decode"), event());
    }

    /// Invariant: malformed local acceptance bytes cannot replay with appended
    /// data that would change the canonical id outside the codec's field layout.
    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut bytes = encode(&event());
        bytes.push(0);

        let err = decode(&bytes).expect_err("trailing byte must fail");

        assert!(err.starts_with("trailing "), "{err}");
    }

    /// Invariant: replay/admission can block invite_accepted on the exact local
    /// invite-secret event that records the scoped invite secret.
    #[test]
    fn record_declares_local_scope_and_invite_secret_dependency() {
        let record = record_from_bytes(encode(&event())).expect("record");

        assert_eq!(record.scope, EventScope::Local);
        assert_eq!(record.workspace_id, Some([1; 32]));
        assert_eq!(record.dependencies, vec![[3; 32]]);
    }

    /// Invariant: local acceptance provenance cannot be projected for an empty
    /// endpoint, workspace, invite, secret-event, or bootstrap-hash id.
    #[test]
    fn decode_rejects_empty_ids() {
        let mut candidate = event();
        candidate.workspace_id = [0; 32];

        let err = decode(&encode(&candidate)).expect_err("empty id must fail");

        assert_eq!(err, "invite_accepted workspace_id cannot be empty");
    }
}

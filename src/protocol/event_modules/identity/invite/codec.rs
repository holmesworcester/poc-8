//! Codec for stored invite-secret events.
//!
//! The shareable invite link carries the secret to the invited peer. Locally we
//! store the hash-to-secret mapping as an event so bootstrap authorization is a
//! projected fact rather than hidden CLI state.

use crate::protocol::event_modules::types::{EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::types::InviteSecretEvent;

pub const TYPE_INVITE_SECRET: u8 = 129;

pub fn encode(event: &InviteSecretEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(1 + 32 + 32);
    out.u8(TYPE_INVITE_SECRET);
    out.id(&event.bootstrap_hash);
    out.id(&event.bootstrap_secret);
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<InviteSecretEvent, String> {
    let mut reader = Reader::new(bytes, "invite secret");
    let tag = reader.u8()?;
    if tag != TYPE_INVITE_SECRET {
        return Err("expected invite secret".to_string());
    }
    let event = InviteSecretEvent {
        bootstrap_hash: reader.id()?,
        bootstrap_secret: reader.id()?,
    };
    reader.finish()?;
    event.validate()
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    decode(&bytes)?;
    Ok(EventRecord {
        timestamp: 0,
        body_len: 0,
        canonical_bytes: bytes,
        dependencies: Vec::new(),
        workspace_id: None,
        scope: EventScope::Local,
    })
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::types::EventScope;

    use super::*;
    use crate::protocol::event_modules::identity::invite::types::InviteSecretEvent;

    // Invariant: decode rejects hash that does not match secret.
    #[test]
    fn decode_rejects_hash_that_does_not_match_secret() {
        let event = InviteSecretEvent {
            bootstrap_hash: [9; 32],
            bootstrap_secret: [7; 32],
        };

        let err = decode(&encode(&event)).expect_err("mismatched hash must fail");

        assert_eq!(err, "invite secret hash does not match secret");
    }

    // Invariant: decode rejects trailing bytes.
    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut bytes = encode(&InviteSecretEvent::new([7; 32]));
        bytes.push(0);

        let err = decode(&bytes).expect_err("trailing byte must fail");

        assert!(err.starts_with("trailing "), "{err}");
    }

    // Invariant: record from bytes marks invite secret local only.
    #[test]
    fn record_from_bytes_marks_invite_secret_local_only() {
        let record = record_from_bytes(encode(&InviteSecretEvent::new([7; 32]))).expect("record");

        assert_eq!(record.scope, EventScope::Local);
        assert!(!record.scope.is_shared());
    }
}

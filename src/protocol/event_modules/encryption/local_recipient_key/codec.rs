//! Codec for local recipient key events.
//!
//! Decoding verifies that the stored private key derives the named public key.
//! That keeps malformed local key events out of projection context before any
//! later worker relies on the projected row.

use crate::core::crypto;
use crate::protocol::event_modules::types::{EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::types::LocalRecipientKey;

pub const TYPE_LOCAL_RECIPIENT_KEY: u8 = 143;

pub fn encode(event: &LocalRecipientKey) -> Vec<u8> {
    let mut out = Writer::with_capacity(1 + 32 + 32 + 32);
    out.u8(TYPE_LOCAL_RECIPIENT_KEY);
    out.id(&event.workspace_id);
    out.id(&event.recipient_key);
    out.id(&event.recipient_secret);
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<LocalRecipientKey, String> {
    let mut reader = Reader::new(bytes, "local recipient key");
    let tag = reader.u8()?;
    if tag != TYPE_LOCAL_RECIPIENT_KEY {
        return Err("expected local recipient key".to_string());
    }
    let event = LocalRecipientKey {
        workspace_id: reader.id()?,
        recipient_key: reader.id()?,
        recipient_secret: reader.id()?,
    };
    reader.finish()?;
    validate(&event)?;
    Ok(event)
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let event = decode(&bytes)?;
    Ok(EventRecord {
        timestamp: 0,
        body_len: 0,
        canonical_bytes: bytes,
        dependencies: Vec::new(),
        workspace_id: Some(event.workspace_id),
        scope: EventScope::Local,
    })
}

fn validate(event: &LocalRecipientKey) -> Result<(), String> {
    if is_zero(&event.workspace_id) {
        return Err("local recipient key workspace cannot be empty".to_string());
    }
    if is_zero(&event.recipient_secret) {
        return Err("local recipient key secret cannot be empty".to_string());
    }
    if crypto::x25519_public_key(&event.recipient_secret) != event.recipient_key {
        return Err("local recipient key secret does not match public key".to_string());
    }
    Ok(())
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
    fn roundtrips_local_recipient_key() {
        let event = commands::create([1; 32]).expect("create").value;
        let bytes = encode(&event);

        assert_eq!(decode(&bytes).expect("decode"), event);
    }

    #[test]
    fn decode_rejects_secret_that_does_not_match_public_key() {
        let good = commands::create([1; 32]).expect("create good").value;
        let bad = commands::create([1; 32]).expect("create bad").value;
        let bytes = encode(&LocalRecipientKey {
            workspace_id: [1; 32],
            recipient_key: good.recipient_key,
            recipient_secret: bad.recipient_secret,
        });

        let err = decode(&bytes).expect_err("mismatched keypair must fail");

        assert_eq!(err, "local recipient key secret does not match public key");
    }

    #[test]
    fn decode_rejects_empty_workspace_and_empty_secret() {
        let good = commands::create([1; 32]).expect("create").value;
        let empty_workspace = LocalRecipientKey {
            workspace_id: [0; 32],
            ..good.clone()
        };
        assert_eq!(
            decode(&encode(&empty_workspace)).expect_err("empty workspace must fail"),
            "local recipient key workspace cannot be empty"
        );

        let empty_secret = LocalRecipientKey {
            recipient_key: crypto::x25519_public_key(&[0; 32]),
            recipient_secret: [0; 32],
            ..good
        };
        assert_eq!(
            decode(&encode(&empty_secret)).expect_err("empty secret must fail"),
            "local recipient key secret cannot be empty"
        );
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut bytes = encode(&commands::create([1; 32]).expect("create").value);
        bytes.push(0);

        let err = decode(&bytes).expect_err("trailing byte must fail");

        assert!(err.starts_with("trailing "), "{err}");
    }

    #[test]
    fn record_from_bytes_marks_recipient_key_local_only_and_workspace_scoped() {
        let bytes = encode(&commands::create([1; 32]).expect("create").value);
        let record = record_from_bytes(bytes).expect("record");

        assert_eq!(record.scope, EventScope::Local);
        assert!(!record.scope.is_shared());
        assert_eq!(record.workspace_id, Some([1; 32]));
        assert!(record.dependencies.is_empty());
    }
}

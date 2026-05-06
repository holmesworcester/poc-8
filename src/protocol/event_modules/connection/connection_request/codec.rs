//! Wire codec for connection request events.
//!
//! A request is local protocol history. It is not shared by sync, but it is
//! durable enough for the matching response to name it as a dependency. The
//! request itself names its invite-secret dependency, so bootstrap authorization
//! goes through the same dependency/context path as every other local fact. The
//! fixed magic prefix keeps connection establishment separate from ordinary
//! tagged events, while `Reader::finish` ensures malformed extra bytes are
//! rejected.

use crate::protocol::event_modules::types::{EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::super::types::EVENT_MAGIC;
use super::types::RequestEvent;

pub const TAG: u8 = 1;

pub fn encode(event: &RequestEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(10 + 1 + 32 * 5);
    out.raw(EVENT_MAGIC);
    out.u8(TAG);
    out.id(&event.from_endpoint);
    out.id(&event.to_endpoint);
    out.id(&event.nonce);
    out.id(&event.bootstrap_hash);
    out.id(&event.invite_secret_event_id);
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<RequestEvent, String> {
    if !bytes.starts_with(EVENT_MAGIC) {
        return Err("not a connection event".to_string());
    }
    let mut reader = Reader::new(&bytes[EVENT_MAGIC.len()..], "connection request");
    let tag = reader.u8()?;
    if tag != TAG {
        return Err("expected connection request".to_string());
    }
    let event = RequestEvent {
        from_endpoint: reader.id()?,
        to_endpoint: reader.id()?,
        nonce: reader.id()?,
        bootstrap_hash: reader.id()?,
        invite_secret_event_id: reader.id()?,
    };
    reader.finish()?;
    Ok(event)
}

pub fn is_request(bytes: &[u8]) -> bool {
    bytes.starts_with(EVENT_MAGIC) && bytes.get(EVENT_MAGIC.len()) == Some(&TAG)
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let event = decode(&bytes)?;
    Ok(EventRecord {
        timestamp: 0,
        body_len: 0,
        canonical_bytes: bytes,
        dependencies: vec![event.invite_secret_event_id],
        workspace_id: None,
        scope: EventScope::Local,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> RequestEvent {
        RequestEvent {
            from_endpoint: [1; 32],
            to_endpoint: [2; 32],
            nonce: [3; 32],
            bootstrap_hash: [4; 32],
            invite_secret_event_id: [5; 32],
        }
    }

    #[test]
    fn record_declares_invite_secret_dependency() {
        let record = record_from_bytes(encode(&request())).expect("record");

        assert_eq!(record.scope, EventScope::Local);
        assert_eq!(record.dependencies, vec![[5; 32]]);
    }
}

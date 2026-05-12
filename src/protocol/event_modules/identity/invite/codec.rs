//! Codec for stored invite-secret events.
//!
//! The shareable invite link carries the secret to the invited peer. Locally we
//! store the hash-to-secret mapping as an event so bootstrap authorization is a
//! projected fact rather than hidden CLI state.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::protocol::event_modules::types::{EventRecord, EventScope};
use crate::protocol::wire_schema::{Field, WireSchema};

use super::types::InviteSecretEvent;

pub const TYPE_INVITE_SECRET: u8 = 129;

const ADDR_FAMILY_NONE: u8 = 0;
const ADDR_FAMILY_V4: u8 = 4;
const ADDR_FAMILY_V6: u8 = 6;
const ADDR_BLOCK_BYTES: usize = 1 + 16 + 2;

pub const SCHEMA: WireSchema = WireSchema::new(
    "identity.invite_secret",
    TYPE_INVITE_SECRET,
    &[
        Field::id("bootstrap_hash"),
        Field::id("bootstrap_secret"),
        Field::bytes("addr_block", ADDR_BLOCK_BYTES),
        Field::id("workspace_id_or_zero"),
        Field::id("invite_event_id_or_zero"),
    ],
);

pub fn encode(event: &InviteSecretEvent) -> Vec<u8> {
    SCHEMA
        .encoder()
        .id(&event.bootstrap_hash)
        .id(&event.bootstrap_secret)
        .bytes(&encode_addr_block(event.addr))
        .id(&event.workspace_id.unwrap_or([0; 32]))
        .id(&event.invite_event_id.unwrap_or([0; 32]))
        .finish()
}

pub fn decode(bytes: &[u8]) -> Result<InviteSecretEvent, String> {
    let v = SCHEMA.parse(bytes)?;
    let event = InviteSecretEvent {
        bootstrap_hash: v.id("bootstrap_hash")?,
        bootstrap_secret: v.id("bootstrap_secret")?,
        addr: decode_addr_block(v.raw("addr_block")?)?,
        workspace_id: optional_id(v.id("workspace_id_or_zero")?),
        invite_event_id: optional_id(v.id("invite_event_id_or_zero")?),
    };
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

fn optional_id(id: [u8; 32]) -> Option<[u8; 32]> {
    if id.iter().all(|byte| *byte == 0) {
        None
    } else {
        Some(id)
    }
}

fn encode_addr_block(addr: Option<SocketAddr>) -> [u8; ADDR_BLOCK_BYTES] {
    let mut out = [0u8; ADDR_BLOCK_BYTES];
    match addr {
        None => out[0] = ADDR_FAMILY_NONE,
        Some(a) => match a.ip() {
            IpAddr::V4(ip) => {
                out[0] = ADDR_FAMILY_V4;
                out[1..5].copy_from_slice(&ip.octets());
                out[17..19].copy_from_slice(&a.port().to_be_bytes());
            }
            IpAddr::V6(ip) => {
                out[0] = ADDR_FAMILY_V6;
                out[1..17].copy_from_slice(&ip.octets());
                out[17..19].copy_from_slice(&a.port().to_be_bytes());
            }
        },
    }
    out
}

fn decode_addr_block(bytes: &[u8]) -> Result<Option<SocketAddr>, String> {
    let family = bytes[0];
    let ip_bytes = &bytes[1..17];
    let port = u16::from_be_bytes(bytes[17..19].try_into().expect("len checked"));
    match family {
        ADDR_FAMILY_NONE => {
            if ip_bytes.iter().any(|byte| *byte != 0) || port != 0 {
                return Err("absent invite addr must zero its address bytes".to_string());
            }
            Ok(None)
        }
        ADDR_FAMILY_V4 => {
            if ip_bytes[4..].iter().any(|byte| *byte != 0) {
                return Err("ipv4 invite addr must zero its trailing bytes".to_string());
            }
            let octets: [u8; 4] = ip_bytes[..4].try_into().expect("len checked");
            Ok(Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(octets)),
                port,
            )))
        }
        ADDR_FAMILY_V6 => {
            let octets: [u8; 16] = ip_bytes.try_into().expect("len checked");
            Ok(Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(octets)),
                port,
            )))
        }
        other => Err(format!("unknown invite addr family {other}")),
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::types::EventScope;

    use super::*;
    use crate::protocol::event_modules::identity::invite::types::InviteSecretEvent;

    #[test]
    fn decode_rejects_hash_that_does_not_match_secret() {
        let event = InviteSecretEvent {
            bootstrap_hash: [9; 32],
            bootstrap_secret: [7; 32],
            addr: None,
            workspace_id: None,
            invite_event_id: None,
        };

        let err = decode(&encode(&event)).expect_err("mismatched hash must fail");

        assert_eq!(err, "invite secret hash does not match secret");
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        let mut bytes = encode(&InviteSecretEvent::new([7; 32]));
        bytes.push(0);

        let err = decode(&bytes).expect_err("trailing byte must fail");

        assert!(err.contains("expected"), "{err}");
    }

    #[test]
    fn roundtrips_invite_dial_addr() {
        let addr = "127.0.0.1:41000".parse().expect("addr");
        let event = InviteSecretEvent::new_with_addr([7; 32], addr);

        let decoded = decode(&encode(&event)).expect("decode");

        assert_eq!(decoded.addr, Some(addr));
        assert_eq!(decoded, event);
    }

    #[test]
    fn decode_rejects_incomplete_scope() {
        let event = InviteSecretEvent {
            workspace_id: Some([1; 32]),
            ..InviteSecretEvent::new([7; 32])
        };

        let err = decode(&encode(&event)).expect_err("incomplete scope must fail");

        assert_eq!(err, "invite secret scope is incomplete");
    }

    #[test]
    fn record_from_bytes_marks_invite_secret_local_only() {
        let record = record_from_bytes(encode(&InviteSecretEvent::new([7; 32]))).expect("record");

        assert_eq!(record.scope, EventScope::Local);
        assert!(!record.scope.is_shared());
    }
}

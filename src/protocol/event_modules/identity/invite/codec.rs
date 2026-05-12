//! Codec for stored invite-secret events.
//!
//! The shareable invite link carries the secret to the invited peer. Locally we
//! store the hash-to-secret mapping as an event so bootstrap authorization is a
//! projected fact rather than hidden CLI state.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::protocol::event_modules::types::{EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::types::InviteSecretEvent;

pub const TYPE_INVITE_SECRET: u8 = 129;

const ADDR_FAMILY_NONE: u8 = 0;
const ADDR_FAMILY_V4: u8 = 4;
const ADDR_FAMILY_V6: u8 = 6;
const ADDR_BLOCK_BYTES: usize = 1 + 16 + 2;

pub fn encode(event: &InviteSecretEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(1 + 32 + 32 + ADDR_BLOCK_BYTES + 32 + 32);
    out.u8(TYPE_INVITE_SECRET);
    out.id(&event.bootstrap_hash);
    out.id(&event.bootstrap_secret);
    encode_optional_addr(&mut out, event.addr);
    out.id(&event.workspace_id.unwrap_or([0; 32]));
    out.id(&event.invite_event_id.unwrap_or([0; 32]));
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
        addr: decode_optional_addr(&mut reader)?,
        workspace_id: optional_id(reader.id()?),
        invite_event_id: optional_id(reader.id()?),
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

fn optional_id(id: [u8; 32]) -> Option<[u8; 32]> {
    if id.iter().all(|byte| *byte == 0) {
        None
    } else {
        Some(id)
    }
}

fn encode_optional_addr(out: &mut Writer, addr: Option<SocketAddr>) {
    match addr {
        None => {
            out.u8(ADDR_FAMILY_NONE);
            out.raw(&[0u8; 16]);
            out.u16(0);
        }
        Some(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                out.u8(ADDR_FAMILY_V4);
                let mut padded = [0u8; 16];
                padded[..4].copy_from_slice(&ip.octets());
                out.raw(&padded);
                out.u16(addr.port());
            }
            IpAddr::V6(ip) => {
                out.u8(ADDR_FAMILY_V6);
                out.raw(&ip.octets());
                out.u16(addr.port());
            }
        },
    }
}

fn decode_optional_addr(reader: &mut Reader<'_>) -> Result<Option<SocketAddr>, String> {
    let family = reader.u8()?;
    let raw = reader.bytes(16)?;
    let port = reader.u16()?;
    match family {
        ADDR_FAMILY_NONE => {
            if raw.iter().any(|byte| *byte != 0) || port != 0 {
                return Err("absent invite addr must zero its address bytes".to_string());
            }
            Ok(None)
        }
        ADDR_FAMILY_V4 => {
            if raw[4..].iter().any(|byte| *byte != 0) {
                return Err("ipv4 invite addr must zero its trailing bytes".to_string());
            }
            let octets = [raw[0], raw[1], raw[2], raw[3]];
            Ok(Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(octets)),
                port,
            )))
        }
        ADDR_FAMILY_V6 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&raw);
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

        assert!(err.starts_with("trailing "), "{err}");
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

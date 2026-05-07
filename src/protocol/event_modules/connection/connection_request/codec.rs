//! Wire codec for connection request events.
//!
//! A request is local protocol history. It is not shared by sync, but it is
//! durable enough for the matching response to name it as a dependency. The
//! request itself names its invite-secret dependency, so bootstrap authorization
//! goes through the same dependency/context path as every other local fact. The
//! fixed magic prefix keeps connection establishment separate from ordinary
//! tagged events, while `Reader::finish` ensures malformed extra bytes are
//! rejected.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::protocol::event_modules::types::{EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::super::types::EVENT_MAGIC;
use super::types::RequestEvent;

pub const TAG: u8 = 1;

const ADDR_FAMILY_NONE: u8 = 0;
const ADDR_FAMILY_V4: u8 = 4;
const ADDR_FAMILY_V6: u8 = 6;
const ADDR_BLOCK_BYTES: usize = 1 + 16 + 2;

pub fn encode(event: &RequestEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(10 + 1 + 32 * 5 + ADDR_BLOCK_BYTES);
    out.raw(EVENT_MAGIC);
    out.u8(TAG);
    out.id(&event.from_endpoint);
    out.id(&event.to_endpoint);
    out.id(&event.nonce);
    out.id(&event.bootstrap_hash);
    out.id(&event.invite_secret_event_id);
    encode_optional_addr(&mut out, event.from_listen_addr);
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
        from_listen_addr: decode_optional_addr(&mut reader)?,
    };
    reader.finish()?;
    Ok(event)
}

fn encode_optional_addr(out: &mut Writer, addr: Option<SocketAddr>) {
    // Always reserve the same byte count so the request stays fixed-width.
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
                return Err("absent listen addr must zero its address bytes".to_string());
            }
            Ok(None)
        }
        ADDR_FAMILY_V4 => {
            if raw[4..].iter().any(|byte| *byte != 0) {
                return Err("ipv4 listen addr must zero its trailing bytes".to_string());
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
        other => Err(format!("unknown listen addr family {other}")),
    }
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
            from_listen_addr: None,
        }
    }

    #[test]
    fn record_declares_invite_secret_dependency() {
        let record = record_from_bytes(encode(&request())).expect("record");

        assert_eq!(record.scope, EventScope::Local);
        assert_eq!(record.dependencies, vec![[5; 32]]);
    }

    #[test]
    fn round_trips_optional_listen_addr() {
        let mut request = request();
        let bytes_none = encode(&request);
        assert_eq!(decode(&bytes_none).expect("decode"), request);

        request.from_listen_addr =
            Some("127.0.0.1:55555".parse().expect("ipv4 socket addr"));
        let bytes_v4 = encode(&request);
        assert_eq!(decode(&bytes_v4).expect("decode"), request);
        assert_eq!(bytes_none.len(), bytes_v4.len());

        request.from_listen_addr = Some("[::1]:8080".parse().expect("ipv6 socket addr"));
        let bytes_v6 = encode(&request);
        assert_eq!(decode(&bytes_v6).expect("decode"), request);
        assert_eq!(bytes_none.len(), bytes_v6.len());
    }
}

//! Wire codec for connection request events.
//!
//! A request is local protocol history. It is not shared by sync, but it is
//! durable enough for the matching response to name it as a dependency. The
//! request itself names its invite-secret dependency and carries an invite-key
//! signature over the request transcript, so bootstrap authorization goes
//! through the same dependency/context path as every other local fact.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::core::crypto::ED25519_SIGNATURE_BYTES;
use crate::protocol::event_modules::types::{EventRecord, EventScope};
use crate::protocol::wire_schema::{Field, WireSchema};

use super::types::RequestEvent;

pub const TYPE_CONNECTION_REQUEST: u8 = 132;
pub const TAG: u8 = TYPE_CONNECTION_REQUEST;

const ADDR_FAMILY_NONE: u8 = 0;
const ADDR_FAMILY_V4: u8 = 4;
const ADDR_FAMILY_V6: u8 = 6;
const ADDR_BLOCK_BYTES: usize = 1 + 16 + 2;

pub const SCHEMA: WireSchema = WireSchema::new(
    "connection.request",
    TYPE_CONNECTION_REQUEST,
    &[
        Field::id("from_endpoint"),
        Field::id("to_endpoint"),
        Field::id("nonce"),
        Field::id("invite_event_id"),
        Field::id("bootstrap_hash"),
        Field::bytes("invite_signature", ED25519_SIGNATURE_BYTES),
        Field::id("invite_secret_event_id"),
        Field::id("initiator_ephemeral_secret_event_id"),
        Field::id("initiator_ephemeral_public_key"),
        Field::bytes("from_listen_addr", ADDR_BLOCK_BYTES),
    ],
);

pub fn encode(event: &RequestEvent) -> Vec<u8> {
    SCHEMA
        .encoder()
        .id(&event.from_endpoint)
        .id(&event.to_endpoint)
        .id(&event.nonce)
        .id(&event.invite_event_id)
        .id(&event.bootstrap_hash)
        .bytes(&event.invite_signature)
        .id(&event.invite_secret_event_id)
        .id(&event.initiator_ephemeral_secret_event_id)
        .id(&event.initiator_ephemeral_public_key)
        .bytes(&encode_addr_block(event.from_listen_addr))
        .finish()
}

pub fn decode(bytes: &[u8]) -> Result<RequestEvent, String> {
    let v = SCHEMA.parse(bytes)?;
    Ok(RequestEvent {
        from_endpoint: v.id("from_endpoint")?,
        to_endpoint: v.id("to_endpoint")?,
        nonce: v.id("nonce")?,
        invite_event_id: v.id("invite_event_id")?,
        bootstrap_hash: v.id("bootstrap_hash")?,
        invite_signature: v
            .raw("invite_signature")?
            .try_into()
            .map_err(|_| "invite signature length".to_string())?,
        invite_secret_event_id: v.id("invite_secret_event_id")?,
        initiator_ephemeral_secret_event_id: v.id("initiator_ephemeral_secret_event_id")?,
        initiator_ephemeral_public_key: v.id("initiator_ephemeral_public_key")?,
        from_listen_addr: decode_addr_block(v.raw("from_listen_addr")?)?,
    })
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
                return Err("absent listen addr must zero its address bytes".to_string());
            }
            Ok(None)
        }
        ADDR_FAMILY_V4 => {
            if ip_bytes[4..].iter().any(|byte| *byte != 0) {
                return Err("ipv4 listen addr must zero its trailing bytes".to_string());
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
        other => Err(format!("unknown listen addr family {other}")),
    }
}

pub fn is_request(bytes: &[u8]) -> bool {
    bytes.first() == Some(&TYPE_CONNECTION_REQUEST)
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let event = decode(&bytes)?;
    Ok(EventRecord {
        timestamp: 0,
        body_len: 0,
        canonical_bytes: bytes,
        dependencies: vec![
            event.invite_secret_event_id,
            event.initiator_ephemeral_secret_event_id,
        ],
        workspace_id: None,
        scope: EventScope::Local,
    })
}

pub fn received_record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
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
            invite_event_id: [4; 32],
            bootstrap_hash: [5; 32],
            invite_signature: [6; ED25519_SIGNATURE_BYTES],
            invite_secret_event_id: [6; 32],
            initiator_ephemeral_secret_event_id: [7; 32],
            initiator_ephemeral_public_key: [8; 32],
            from_listen_addr: None,
        }
    }

    #[test]
    fn record_declares_invite_secret_dependency() {
        let record = record_from_bytes(encode(&request())).expect("record");

        assert_eq!(record.scope, EventScope::Local);
        assert_eq!(record.dependencies, vec![[6; 32], [7; 32]]);
    }

    #[test]
    fn received_record_declares_only_invite_secret_dependency() {
        let record = received_record_from_bytes(encode(&request())).expect("record");

        assert_eq!(record.scope, EventScope::Local);
        assert_eq!(record.dependencies, vec![[6; 32]]);
    }

    #[test]
    fn round_trips_optional_listen_addr() {
        let mut request = request();
        let bytes_none = encode(&request);
        assert_eq!(decode(&bytes_none).expect("decode"), request);

        request.from_listen_addr = Some("127.0.0.1:55555".parse().expect("ipv4 socket addr"));
        let bytes_v4 = encode(&request);
        assert_eq!(decode(&bytes_v4).expect("decode"), request);
        assert_eq!(bytes_none.len(), bytes_v4.len());

        request.from_listen_addr = Some("[::1]:8080".parse().expect("ipv6 socket addr"));
        let bytes_v6 = encode(&request);
        assert_eq!(decode(&bytes_v6).expect("decode"), request);
        assert_eq!(bytes_none.len(), bytes_v6.len());
    }
}

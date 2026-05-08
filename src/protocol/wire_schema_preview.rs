//! Schema-driven wire format preview, applied to every event in poc-8.
//!
//! Each event has:
//!   - the data struct,
//!   - a `pub const SCHEMA: WireSchema` declaring tag + ordered fixed-size fields,
//!   - `encode`/`decode` driven by that schema,
//!   - `record_from_bytes` that builds the `EventRecord`.
//!
//! The schema only knows about layout. Record metadata (scope, deps,
//! timestamp, workspace) lives in each event's `record_from_bytes` —
//! short, explicit, kept close to the codec it belongs to. AEAD events
//! use empty AAD: the signature already binds canonical bytes (which
//! include the ciphertext) to the signer.
//!
//! Variable-size fields declare an ordinary `u32` length next to a
//! `bytes(MAX)` slot; the per-event decode validates the length and that
//! the slot's trailer is zero. Used for the BAO proof in `file_slice`
//! and the up-to-4 removal id list in `removal_frontier`.
//!
//! Signed events declare signer/sig as ordinary fields in their wire
//! positions. There is no separate envelope type — a signed event is just
//! an event whose layout includes those fields.
//!
//! Connection events (`connection_request`, `connection_response`) drop
//! the historical 10-byte `EVENT_MAGIC` prefix and use ordinary tag bytes.
//!
//! The wire format produced is the simplified target: no `sized_bytes`
//! around payloads, every event body length is implied by its tag.

#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::core::crypto::{
    ED25519_SIGNATURE_BYTES, XCHACHA20_POLY1305_NONCE_BYTES,
};
use crate::protocol::event_modules::content::file::types::FILE_DESCRIPTOR_CIPHERTEXT_BYTES;
use crate::protocol::event_modules::content::file_slice::types::FILE_SLICE_PROOF_BYTES;
use crate::protocol::event_modules::content::message::types::MESSAGE_CIPHERTEXT_BYTES;
use crate::protocol::event_modules::content::reaction::types::REACTION_CIPHERTEXT_BYTES;
use crate::protocol::event_modules::encryption::key_wrap::types::KEY_WRAP_CIPHERTEXT_BYTES;
use crate::protocol::event_modules::identity::endpoint_shared::types::ENDPOINT_DEVICE_NAME_BYTES;
use crate::protocol::event_modules::identity::user::types::USERNAME_BYTES;
use crate::protocol::event_modules::identity::workspace::types::WORKSPACE_NAME_BYTES;
use crate::protocol::event_modules::types::{
    ConnectionScope, EventId, EventRecord, EventScope,
};
use crate::protocol::wire_schema::{Field, WireSchema};

const REMOVAL_FRONTIER_MAX_REMOVALS: usize = 4;
const REMOVAL_FRONTIER_REMOVALS_BYTES: usize = 32 * REMOVAL_FRONTIER_MAX_REMOVALS;
const ADDR_BLOCK_BYTES: usize = 1 + 16 + 2;
const ADDR_FAMILY_NONE: u8 = 0;
const ADDR_FAMILY_V4: u8 = 4;
const ADDR_FAMILY_V6: u8 = 6;

fn push_unique(out: &mut Vec<EventId>, id: EventId) {
    if !out.iter().any(|candidate| candidate == &id) {
        out.push(id);
    }
}

fn id_array(bytes: &[u8]) -> Result<[u8; 32], String> {
    bytes.try_into().map_err(|_| "id length".to_string())
}

fn sig_array(bytes: &[u8]) -> Result<[u8; ED25519_SIGNATURE_BYTES], String> {
    bytes.try_into().map_err(|_| "sig length".to_string())
}

fn nonce_array(bytes: &[u8]) -> Result<[u8; XCHACHA20_POLY1305_NONCE_BYTES], String> {
    bytes.try_into().map_err(|_| "nonce length".to_string())
}

fn fixed_name<const N: usize>(bytes: &[u8]) -> Result<[u8; N], String> {
    bytes.try_into().map_err(|_| "name length".to_string())
}

fn encode_addr_block(addr: Option<SocketAddr>) -> [u8; ADDR_BLOCK_BYTES] {
    let mut out = [0u8; ADDR_BLOCK_BYTES];
    match addr {
        None => out[0] = ADDR_FAMILY_NONE,
        Some(a) => {
            let port = a.port();
            match a.ip() {
                IpAddr::V4(ip) => {
                    out[0] = ADDR_FAMILY_V4;
                    out[1..5].copy_from_slice(&ip.octets());
                    out[17..19].copy_from_slice(&port.to_be_bytes());
                }
                IpAddr::V6(ip) => {
                    out[0] = ADDR_FAMILY_V6;
                    out[1..17].copy_from_slice(&ip.octets());
                    out[17..19].copy_from_slice(&port.to_be_bytes());
                }
            }
        }
    }
    out
}

fn decode_addr_block(bytes: &[u8]) -> Result<Option<SocketAddr>, String> {
    if bytes.len() != ADDR_BLOCK_BYTES {
        return Err("addr block length".to_string());
    }
    let family = bytes[0];
    let ip_bytes = &bytes[1..17];
    let port = u16::from_be_bytes(bytes[17..19].try_into().expect("len checked"));
    match family {
        ADDR_FAMILY_NONE => {
            if ip_bytes.iter().any(|b| *b != 0) || port != 0 {
                return Err("addr none has non-zero payload".to_string());
            }
            Ok(None)
        }
        ADDR_FAMILY_V4 => {
            if ip_bytes[4..].iter().any(|b| *b != 0) {
                return Err("addr v4 has non-zero padding".to_string());
            }
            let octets: [u8; 4] = ip_bytes[..4].try_into().expect("len checked");
            Ok(Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port)))
        }
        ADDR_FAMILY_V6 => {
            let octets: [u8; 16] = ip_bytes.try_into().expect("len checked");
            Ok(Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)))
        }
        other => Err(format!("addr unknown family {other}")),
    }
}

// ===========================================================================
// sync events — connection-scoped, unsigned.
// ===========================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HaveIdEvent {
    pub connection_id: EventId,
    pub timestamp: u64,
    pub id: EventId,
}

pub const HAVE_ID: WireSchema = WireSchema::new(
    "sync.have_id",
    141,
    &[Field::id("connection_id"), Field::u64("timestamp"), Field::id("id")],
);

pub fn encode_have_id(e: &HaveIdEvent) -> Vec<u8> {
    HAVE_ID.encoder().id(&e.connection_id).u64(e.timestamp).id(&e.id).finish()
}

pub fn decode_have_id(bytes: &[u8]) -> Result<HaveIdEvent, String> {
    let v = HAVE_ID.parse(bytes)?;
    Ok(HaveIdEvent {
        connection_id: v.id("connection_id")?,
        timestamp: v.u64("timestamp")?,
        id: v.id("id")?,
    })
}

pub fn record_from_have_id(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let v = HAVE_ID.parse(&bytes)?;
    Ok(EventRecord {
        timestamp: 0,
        body_len: 0,
        scope: EventScope::Connection(ConnectionScope::Outgoing {
            connection_id: v.id("connection_id")?,
        }),
        workspace_id: None,
        dependencies: vec![],
        canonical_bytes: bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeedIdEvent {
    pub connection_id: EventId,
    pub id: EventId,
}

pub const NEED_ID: WireSchema = WireSchema::new(
    "sync.need_id",
    142,
    &[Field::id("connection_id"), Field::id("id")],
);

pub fn encode_need_id(e: &NeedIdEvent) -> Vec<u8> {
    NEED_ID.encoder().id(&e.connection_id).id(&e.id).finish()
}

pub fn decode_need_id(bytes: &[u8]) -> Result<NeedIdEvent, String> {
    let v = NEED_ID.parse(bytes)?;
    Ok(NeedIdEvent {
        connection_id: v.id("connection_id")?,
        id: v.id("id")?,
    })
}

pub fn record_from_need_id(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let v = NEED_ID.parse(&bytes)?;
    Ok(EventRecord {
        timestamp: 0,
        body_len: 0,
        scope: EventScope::Connection(ConnectionScope::Outgoing {
            connection_id: v.id("connection_id")?,
        }),
        workspace_id: None,
        dependencies: vec![],
        canonical_bytes: bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareEvent {
    pub connection_id: EventId,
    pub range_start: u64,
    pub range_end: u64,
    pub summary_count: u64,
    pub summary_fingerprint: EventId,
    pub response_requested: bool,
}

pub const COMPARE: WireSchema = WireSchema::new(
    "sync.compare",
    140,
    &[
        Field::id("connection_id"),
        Field::u64("range_start"),
        Field::u64("range_end"),
        Field::u64("summary_count"),
        Field::id("summary_fingerprint"),
        Field::u8("response_requested"),
    ],
);

pub fn encode_compare(e: &CompareEvent) -> Vec<u8> {
    COMPARE
        .encoder()
        .id(&e.connection_id)
        .u64(e.range_start)
        .u64(e.range_end)
        .u64(e.summary_count)
        .id(&e.summary_fingerprint)
        .u8(u8::from(e.response_requested))
        .finish()
}

pub fn decode_compare(bytes: &[u8]) -> Result<CompareEvent, String> {
    let v = COMPARE.parse(bytes)?;
    let response = v.u8("response_requested")?;
    if response > 1 {
        return Err("compare response_requested must be 0 or 1".to_string());
    }
    Ok(CompareEvent {
        connection_id: v.id("connection_id")?,
        range_start: v.u64("range_start")?,
        range_end: v.u64("range_end")?,
        summary_count: v.u64("summary_count")?,
        summary_fingerprint: v.id("summary_fingerprint")?,
        response_requested: response == 1,
    })
}

pub fn record_from_compare(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let v = COMPARE.parse(&bytes)?;
    Ok(EventRecord {
        timestamp: 0,
        body_len: 0,
        scope: EventScope::Connection(ConnectionScope::Outgoing {
            connection_id: v.id("connection_id")?,
        }),
        workspace_id: None,
        dependencies: vec![],
        canonical_bytes: bytes,
    })
}

// ===========================================================================
// identity events — unsigned local + signed shared.
// ===========================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointKeypair {
    pub endpoint: EventId,
    pub secret: EventId,
    pub signing_public_key: EventId,
    pub signing_secret: EventId,
}

pub const LOCAL_ENDPOINT: WireSchema = WireSchema::new(
    "identity.local_endpoint",
    128,
    &[
        Field::id("endpoint"),
        Field::id("secret"),
        Field::id("signing_public_key"),
        Field::id("signing_secret"),
    ],
);

pub fn encode_local_endpoint(e: &EndpointKeypair) -> Vec<u8> {
    LOCAL_ENDPOINT
        .encoder()
        .id(&e.endpoint)
        .id(&e.secret)
        .id(&e.signing_public_key)
        .id(&e.signing_secret)
        .finish()
}

pub fn record_from_local_endpoint(bytes: Vec<u8>) -> Result<EventRecord, String> {
    LOCAL_ENDPOINT.parse(&bytes)?;
    Ok(EventRecord {
        timestamp: 0,
        body_len: LOCAL_ENDPOINT.wire_size() - 1,
        scope: EventScope::Local,
        workspace_id: None,
        dependencies: vec![],
        canonical_bytes: bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteSecretEvent {
    pub bootstrap_hash: EventId,
    pub bootstrap_secret: EventId,
    pub workspace_id: Option<EventId>,
    pub invite_event_id: Option<EventId>,
}

pub const INVITE_SECRET: WireSchema = WireSchema::new(
    "identity.invite_secret",
    129,
    &[
        Field::id("bootstrap_hash"),
        Field::id("bootstrap_secret"),
        Field::id("workspace_id_or_zero"),
        Field::id("invite_event_id_or_zero"),
    ],
);

pub fn encode_invite_secret(e: &InviteSecretEvent) -> Vec<u8> {
    INVITE_SECRET
        .encoder()
        .id(&e.bootstrap_hash)
        .id(&e.bootstrap_secret)
        .id(&e.workspace_id.unwrap_or([0; 32]))
        .id(&e.invite_event_id.unwrap_or([0; 32]))
        .finish()
}

fn optional_id(id: EventId) -> Option<EventId> {
    if id.iter().all(|byte| *byte == 0) { None } else { Some(id) }
}

pub fn record_from_invite_secret(bytes: Vec<u8>) -> Result<EventRecord, String> {
    INVITE_SECRET.parse(&bytes)?;
    Ok(EventRecord {
        timestamp: 0,
        body_len: 0,
        scope: EventScope::Local,
        workspace_id: None,
        dependencies: vec![],
        canonical_bytes: bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteAcceptedEvent {
    pub workspace_id: EventId,
    pub invite_event_id: EventId,
    pub invite_secret_event_id: EventId,
    pub bootstrap_hash: EventId,
    pub accepted_endpoint_id: EventId,
}

pub const INVITE_ACCEPTED: WireSchema = WireSchema::new(
    "identity.invite_accepted",
    146,
    &[
        Field::id("workspace_id"),
        Field::id("invite_event_id"),
        Field::id("invite_secret_event_id"),
        Field::id("bootstrap_hash"),
        Field::id("accepted_endpoint_id"),
    ],
);

pub fn encode_invite_accepted(e: &InviteAcceptedEvent) -> Vec<u8> {
    INVITE_ACCEPTED
        .encoder()
        .id(&e.workspace_id)
        .id(&e.invite_event_id)
        .id(&e.invite_secret_event_id)
        .id(&e.bootstrap_hash)
        .id(&e.accepted_endpoint_id)
        .finish()
}

pub fn record_from_invite_accepted(bytes: Vec<u8>) -> Result<EventRecord, String> {
    INVITE_ACCEPTED.parse(&bytes)?;
    Ok(EventRecord {
        timestamp: 0,
        body_len: 0,
        scope: EventScope::Local,
        workspace_id: None,
        dependencies: vec![],
        canonical_bytes: bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceEvent {
    pub created_at_ms: u64,
    pub public_key: EventId,
    pub name: [u8; WORKSPACE_NAME_BYTES],
}

pub const WORKSPACE: WireSchema = WireSchema::new(
    "identity.workspace",
    131,
    &[
        Field::u64("created_at_ms"),
        Field::id("public_key"),
        Field::bytes("name", WORKSPACE_NAME_BYTES),
    ],
);

pub fn encode_workspace(e: &WorkspaceEvent) -> Vec<u8> {
    WORKSPACE
        .encoder()
        .u64(e.created_at_ms)
        .id(&e.public_key)
        .bytes(&e.name)
        .finish()
}

pub fn record_from_workspace(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let v = WORKSPACE.parse(&bytes)?;
    Ok(EventRecord {
        timestamp: v.u64("created_at_ms")?,
        body_len: WORKSPACE.wire_size() - 1,
        scope: EventScope::Shared,
        workspace_id: Some(v.id("public_key")?),
        dependencies: vec![],
        canonical_bytes: bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminEvent {
    pub signer_event_id: EventId,
    pub signer_public_key: EventId,
    pub created_at_ms: u64,
    pub workspace_id: EventId,
    pub public_key: EventId,
    pub authority_event_id: EventId,
    pub user_event_id: EventId,
    pub signature: [u8; ED25519_SIGNATURE_BYTES],
}

pub const ADMIN: WireSchema = WireSchema::new(
    "identity.admin",
    139,
    &[
        Field::id("signer_event_id"),
        Field::id("signer_public_key"),
        Field::u64("created_at_ms"),
        Field::id("workspace_id"),
        Field::id("public_key"),
        Field::id("authority_event_id"),
        Field::id("user_event_id"),
        Field::bytes("signature", ED25519_SIGNATURE_BYTES),
    ],
);

pub fn encode_admin(e: &AdminEvent) -> Vec<u8> {
    ADMIN
        .encoder()
        .id(&e.signer_event_id)
        .id(&e.signer_public_key)
        .u64(e.created_at_ms)
        .id(&e.workspace_id)
        .id(&e.public_key)
        .id(&e.authority_event_id)
        .id(&e.user_event_id)
        .bytes(&e.signature)
        .finish()
}

pub fn record_from_admin(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let v = ADMIN.parse(&bytes)?;
    let signer = v.id("signer_event_id")?;
    let workspace = v.id("workspace_id")?;
    let authority = v.id("authority_event_id")?;
    let user = v.id("user_event_id")?;
    let mut deps = Vec::with_capacity(4);
    for id in [signer, workspace, authority, user] {
        push_unique(&mut deps, id);
    }
    Ok(EventRecord {
        timestamp: v.u64("created_at_ms")?,
        body_len: ADMIN.wire_size() - 1,
        scope: EventScope::Shared,
        workspace_id: Some(workspace),
        dependencies: deps,
        canonical_bytes: bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInviteEvent {
    pub signer_event_id: EventId,
    pub signer_public_key: EventId,
    pub created_at_ms: u64,
    pub public_key: EventId,
    pub workspace_id: EventId,
    pub authority_event_id: EventId,
    pub signature: [u8; ED25519_SIGNATURE_BYTES],
}

pub const USER_INVITE: WireSchema = WireSchema::new(
    "identity.user_invite",
    10,
    &[
        Field::id("signer_event_id"),
        Field::id("signer_public_key"),
        Field::u64("created_at_ms"),
        Field::id("public_key"),
        Field::id("workspace_id"),
        Field::id("authority_event_id"),
        Field::bytes("signature", ED25519_SIGNATURE_BYTES),
    ],
);

pub fn encode_user_invite(e: &UserInviteEvent) -> Vec<u8> {
    USER_INVITE
        .encoder()
        .id(&e.signer_event_id)
        .id(&e.signer_public_key)
        .u64(e.created_at_ms)
        .id(&e.public_key)
        .id(&e.workspace_id)
        .id(&e.authority_event_id)
        .bytes(&e.signature)
        .finish()
}

pub fn record_from_user_invite(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let v = USER_INVITE.parse(&bytes)?;
    let signer = v.id("signer_event_id")?;
    let workspace = v.id("workspace_id")?;
    let authority = v.id("authority_event_id")?;
    let mut deps = Vec::with_capacity(3);
    for id in [signer, workspace, authority] {
        push_unique(&mut deps, id);
    }
    Ok(EventRecord {
        timestamp: v.u64("created_at_ms")?,
        body_len: USER_INVITE.wire_size() - 1,
        scope: EventScope::Shared,
        workspace_id: Some(workspace),
        dependencies: deps,
        canonical_bytes: bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteServerEvent {
    pub signer_event_id: EventId,
    pub signer_public_key: EventId,
    pub created_at_ms: u64,
    pub public_key: EventId,
    pub workspace_id: EventId,
    pub authority_event_id: EventId,
    pub signature: [u8; ED25519_SIGNATURE_BYTES],
}

pub const INVITE_SERVER: WireSchema = WireSchema::new(
    "identity.invite_server",
    136,
    &[
        Field::id("signer_event_id"),
        Field::id("signer_public_key"),
        Field::u64("created_at_ms"),
        Field::id("public_key"),
        Field::id("workspace_id"),
        Field::id("authority_event_id"),
        Field::bytes("signature", ED25519_SIGNATURE_BYTES),
    ],
);

pub fn encode_invite_server(e: &InviteServerEvent) -> Vec<u8> {
    INVITE_SERVER
        .encoder()
        .id(&e.signer_event_id)
        .id(&e.signer_public_key)
        .u64(e.created_at_ms)
        .id(&e.public_key)
        .id(&e.workspace_id)
        .id(&e.authority_event_id)
        .bytes(&e.signature)
        .finish()
}

pub fn record_from_invite_server(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let v = INVITE_SERVER.parse(&bytes)?;
    let signer = v.id("signer_event_id")?;
    let workspace = v.id("workspace_id")?;
    let authority = v.id("authority_event_id")?;
    let mut deps = Vec::with_capacity(3);
    for id in [signer, workspace, authority] {
        push_unique(&mut deps, id);
    }
    Ok(EventRecord {
        timestamp: v.u64("created_at_ms")?,
        body_len: INVITE_SERVER.wire_size() - 1,
        scope: EventScope::Shared,
        workspace_id: Some(workspace),
        dependencies: deps,
        canonical_bytes: bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserEvent {
    pub signer_event_id: EventId,
    pub signer_public_key: EventId,
    pub created_at_ms: u64,
    pub workspace_id: EventId,
    pub public_key: EventId,
    pub username: [u8; USERNAME_BYTES],
    pub signature: [u8; ED25519_SIGNATURE_BYTES],
}

pub const USER: WireSchema = WireSchema::new(
    "identity.user",
    14,
    &[
        Field::id("signer_event_id"),
        Field::id("signer_public_key"),
        Field::u64("created_at_ms"),
        Field::id("workspace_id"),
        Field::id("public_key"),
        Field::bytes("username", USERNAME_BYTES),
        Field::bytes("signature", ED25519_SIGNATURE_BYTES),
    ],
);

pub fn encode_user(e: &UserEvent) -> Vec<u8> {
    USER.encoder()
        .id(&e.signer_event_id)
        .id(&e.signer_public_key)
        .u64(e.created_at_ms)
        .id(&e.workspace_id)
        .id(&e.public_key)
        .bytes(&e.username)
        .bytes(&e.signature)
        .finish()
}

pub fn record_from_user(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let v = USER.parse(&bytes)?;
    let signer = v.id("signer_event_id")?;
    let workspace = v.id("workspace_id")?;
    let mut deps = Vec::with_capacity(2);
    push_unique(&mut deps, signer);
    push_unique(&mut deps, workspace);
    Ok(EventRecord {
        timestamp: v.u64("created_at_ms")?,
        body_len: USER.wire_size() - 1,
        scope: EventScope::Shared,
        workspace_id: Some(workspace),
        dependencies: deps,
        canonical_bytes: bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInviteEvent {
    pub signer_event_id: EventId,
    pub signer_public_key: EventId,
    pub created_at_ms: u64,
    pub workspace_id: EventId,
    pub user_authority_event_id: EventId,
    pub user_invite_event_id: Option<EventId>,
    pub public_key: EventId,
    pub signature: [u8; ED25519_SIGNATURE_BYTES],
}

pub const DEVICE_INVITE: WireSchema = WireSchema::new(
    "identity.device_invite",
    134,
    &[
        Field::id("signer_event_id"),
        Field::id("signer_public_key"),
        Field::u64("created_at_ms"),
        Field::id("workspace_id"),
        Field::id("user_authority_event_id"),
        Field::id("user_invite_event_id_or_zero"),
        Field::id("public_key"),
        Field::bytes("signature", ED25519_SIGNATURE_BYTES),
    ],
);

pub fn encode_device_invite(e: &DeviceInviteEvent) -> Vec<u8> {
    DEVICE_INVITE
        .encoder()
        .id(&e.signer_event_id)
        .id(&e.signer_public_key)
        .u64(e.created_at_ms)
        .id(&e.workspace_id)
        .id(&e.user_authority_event_id)
        .id(&e.user_invite_event_id.unwrap_or([0; 32]))
        .id(&e.public_key)
        .bytes(&e.signature)
        .finish()
}

pub fn record_from_device_invite(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let v = DEVICE_INVITE.parse(&bytes)?;
    let signer = v.id("signer_event_id")?;
    let workspace = v.id("workspace_id")?;
    let authority = v.id("user_authority_event_id")?;
    let invite = optional_id(v.id("user_invite_event_id_or_zero")?);
    let mut deps = Vec::with_capacity(4);
    push_unique(&mut deps, signer);
    push_unique(&mut deps, workspace);
    push_unique(&mut deps, authority);
    if let Some(id) = invite {
        push_unique(&mut deps, id);
    }
    Ok(EventRecord {
        timestamp: v.u64("created_at_ms")?,
        body_len: DEVICE_INVITE.wire_size() - 1,
        scope: EventScope::Shared,
        workspace_id: Some(workspace),
        dependencies: deps,
        canonical_bytes: bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointSharedEvent {
    pub signer_event_id: EventId,
    pub signer_public_key: EventId,
    pub created_at_ms: u64,
    pub workspace_id: EventId,
    pub user_authority_event_id: EventId,
    pub endpoint_id: EventId,
    pub signing_public_key: EventId,
    pub endpoint_role: u8,
    pub device_name: [u8; ENDPOINT_DEVICE_NAME_BYTES],
    pub signature: [u8; ED25519_SIGNATURE_BYTES],
}

pub const ENDPOINT_SHARED: WireSchema = WireSchema::new(
    "identity.endpoint_shared",
    135,
    &[
        Field::id("signer_event_id"),
        Field::id("signer_public_key"),
        Field::u64("created_at_ms"),
        Field::id("workspace_id"),
        Field::id("user_authority_event_id"),
        Field::id("endpoint_id"),
        Field::id("signing_public_key"),
        Field::u8("endpoint_role"),
        Field::bytes("device_name", ENDPOINT_DEVICE_NAME_BYTES),
        Field::bytes("signature", ED25519_SIGNATURE_BYTES),
    ],
);

pub fn encode_endpoint_shared(e: &EndpointSharedEvent) -> Vec<u8> {
    ENDPOINT_SHARED
        .encoder()
        .id(&e.signer_event_id)
        .id(&e.signer_public_key)
        .u64(e.created_at_ms)
        .id(&e.workspace_id)
        .id(&e.user_authority_event_id)
        .id(&e.endpoint_id)
        .id(&e.signing_public_key)
        .u8(e.endpoint_role)
        .bytes(&e.device_name)
        .bytes(&e.signature)
        .finish()
}

pub fn record_from_endpoint_shared(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let v = ENDPOINT_SHARED.parse(&bytes)?;
    let workspace = v.id("workspace_id")?;
    let authority = v.id("user_authority_event_id")?;
    Ok(EventRecord {
        timestamp: v.u64("created_at_ms")?,
        body_len: ENDPOINT_SHARED.wire_size() - 1,
        scope: EventScope::Shared,
        workspace_id: Some(workspace),
        dependencies: vec![workspace, authority],
        canonical_bytes: bytes,
    })
}

// ===========================================================================
// content events.
// ===========================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageDeletionEvent {
    pub signer_endpoint_shared_id: EventId,
    pub signer_public_key: EventId,
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub target_message_id: EventId,
    pub author_user_id: EventId,
    pub signature: [u8; ED25519_SIGNATURE_BYTES],
}

pub const MESSAGE_DELETION: WireSchema = WireSchema::new(
    "content.message_deletion",
    12,
    &[
        Field::id("signer_endpoint_shared_id"),
        Field::id("signer_public_key"),
        Field::id("workspace_id"),
        Field::u64("created_at_ms"),
        Field::id("target_message_id"),
        Field::id("author_user_id"),
        Field::bytes("signature", ED25519_SIGNATURE_BYTES),
    ],
);

pub fn encode_message_deletion(e: &MessageDeletionEvent) -> Vec<u8> {
    MESSAGE_DELETION
        .encoder()
        .id(&e.signer_endpoint_shared_id)
        .id(&e.signer_public_key)
        .id(&e.workspace_id)
        .u64(e.created_at_ms)
        .id(&e.target_message_id)
        .id(&e.author_user_id)
        .bytes(&e.signature)
        .finish()
}

pub fn record_from_message_deletion(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let v = MESSAGE_DELETION.parse(&bytes)?;
    let signer = v.id("signer_endpoint_shared_id")?;
    let workspace = v.id("workspace_id")?;
    let author = v.id("author_user_id")?;
    let target = v.id("target_message_id")?;
    let mut deps = Vec::with_capacity(4);
    for id in [signer, workspace, author, target] {
        push_unique(&mut deps, id);
    }
    Ok(EventRecord {
        timestamp: v.u64("created_at_ms")?,
        body_len: MESSAGE_DELETION.wire_size() - 1,
        scope: EventScope::Shared,
        workspace_id: Some(workspace),
        dependencies: deps,
        canonical_bytes: bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDeletionEvent {
    pub signer_endpoint_shared_id: EventId,
    pub signer_public_key: EventId,
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub target_file_event_id: EventId,
    pub author_user_id: EventId,
    pub signature: [u8; ED25519_SIGNATURE_BYTES],
}

pub const FILE_DELETION: WireSchema = WireSchema::new(
    "content.file_deletion",
    27,
    &[
        Field::id("signer_endpoint_shared_id"),
        Field::id("signer_public_key"),
        Field::id("workspace_id"),
        Field::u64("created_at_ms"),
        Field::id("target_file_event_id"),
        Field::id("author_user_id"),
        Field::bytes("signature", ED25519_SIGNATURE_BYTES),
    ],
);

pub fn encode_file_deletion(e: &FileDeletionEvent) -> Vec<u8> {
    FILE_DELETION
        .encoder()
        .id(&e.signer_endpoint_shared_id)
        .id(&e.signer_public_key)
        .id(&e.workspace_id)
        .u64(e.created_at_ms)
        .id(&e.target_file_event_id)
        .id(&e.author_user_id)
        .bytes(&e.signature)
        .finish()
}

pub fn record_from_file_deletion(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let v = FILE_DELETION.parse(&bytes)?;
    let signer = v.id("signer_endpoint_shared_id")?;
    let workspace = v.id("workspace_id")?;
    let author = v.id("author_user_id")?;
    let target = v.id("target_file_event_id")?;
    let mut deps = Vec::with_capacity(4);
    for id in [signer, workspace, author, target] {
        push_unique(&mut deps, id);
    }
    Ok(EventRecord {
        timestamp: v.u64("created_at_ms")?,
        body_len: FILE_DELETION.wire_size() - 1,
        scope: EventScope::Shared,
        workspace_id: Some(workspace),
        dependencies: deps,
        canonical_bytes: bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEvent {
    pub signer_endpoint_shared_id: EventId,
    pub signer_public_key: EventId,
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub author_user_id: EventId,
    pub removal_frontier_id: EventId,
    pub local_history_node_secret_id: EventId,
    pub nonce: [u8; XCHACHA20_POLY1305_NONCE_BYTES],
    pub ciphertext: [u8; MESSAGE_CIPHERTEXT_BYTES],
    pub signature: [u8; ED25519_SIGNATURE_BYTES],
}

pub const MESSAGE: WireSchema = WireSchema::new(
    "content.message",
    6,
    &[
        Field::id("signer_endpoint_shared_id"),
        Field::id("signer_public_key"),
        Field::id("workspace_id"),
        Field::u64("created_at_ms"),
        Field::id("author_user_id"),
        Field::id("removal_frontier_id"),
        Field::id("local_history_node_secret_id"),
        Field::bytes("nonce", XCHACHA20_POLY1305_NONCE_BYTES),
        Field::bytes("ciphertext", MESSAGE_CIPHERTEXT_BYTES),
        Field::bytes("signature", ED25519_SIGNATURE_BYTES),
    ],
);

pub fn encode_message(e: &MessageEvent) -> Vec<u8> {
    MESSAGE
        .encoder()
        .id(&e.signer_endpoint_shared_id)
        .id(&e.signer_public_key)
        .id(&e.workspace_id)
        .u64(e.created_at_ms)
        .id(&e.author_user_id)
        .id(&e.removal_frontier_id)
        .id(&e.local_history_node_secret_id)
        .bytes(&e.nonce)
        .bytes(&e.ciphertext)
        .bytes(&e.signature)
        .finish()
}

pub fn record_from_message(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let v = MESSAGE.parse(&bytes)?;
    let signer = v.id("signer_endpoint_shared_id")?;
    let workspace = v.id("workspace_id")?;
    let author = v.id("author_user_id")?;
    let frontier = v.id("removal_frontier_id")?;
    let history = v.id("local_history_node_secret_id")?;
    let mut deps = Vec::with_capacity(5);
    for id in [signer, workspace, author, frontier, history] {
        push_unique(&mut deps, id);
    }
    Ok(EventRecord {
        timestamp: v.u64("created_at_ms")?,
        body_len: MESSAGE.wire_size() - 1,
        scope: EventScope::Shared,
        workspace_id: Some(workspace),
        dependencies: deps,
        canonical_bytes: bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactionEvent {
    pub signer_endpoint_shared_id: EventId,
    pub signer_public_key: EventId,
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub target_message_id: EventId,
    pub author_user_id: EventId,
    pub removal_frontier_id: EventId,
    pub local_history_node_secret_id: EventId,
    pub nonce: [u8; XCHACHA20_POLY1305_NONCE_BYTES],
    pub ciphertext: [u8; REACTION_CIPHERTEXT_BYTES],
    pub signature: [u8; ED25519_SIGNATURE_BYTES],
}

pub const REACTION: WireSchema = WireSchema::new(
    "content.reaction",
    8,
    &[
        Field::id("signer_endpoint_shared_id"),
        Field::id("signer_public_key"),
        Field::id("workspace_id"),
        Field::u64("created_at_ms"),
        Field::id("target_message_id"),
        Field::id("author_user_id"),
        Field::id("removal_frontier_id"),
        Field::id("local_history_node_secret_id"),
        Field::bytes("nonce", XCHACHA20_POLY1305_NONCE_BYTES),
        Field::bytes("ciphertext", REACTION_CIPHERTEXT_BYTES),
        Field::bytes("signature", ED25519_SIGNATURE_BYTES),
    ],
);

pub fn encode_reaction(e: &ReactionEvent) -> Vec<u8> {
    REACTION
        .encoder()
        .id(&e.signer_endpoint_shared_id)
        .id(&e.signer_public_key)
        .id(&e.workspace_id)
        .u64(e.created_at_ms)
        .id(&e.target_message_id)
        .id(&e.author_user_id)
        .id(&e.removal_frontier_id)
        .id(&e.local_history_node_secret_id)
        .bytes(&e.nonce)
        .bytes(&e.ciphertext)
        .bytes(&e.signature)
        .finish()
}

pub fn record_from_reaction(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let v = REACTION.parse(&bytes)?;
    let signer = v.id("signer_endpoint_shared_id")?;
    let workspace = v.id("workspace_id")?;
    let target = v.id("target_message_id")?;
    let author = v.id("author_user_id")?;
    let frontier = v.id("removal_frontier_id")?;
    let history = v.id("local_history_node_secret_id")?;
    let mut deps = Vec::with_capacity(6);
    for id in [signer, workspace, author, target, frontier, history] {
        push_unique(&mut deps, id);
    }
    Ok(EventRecord {
        timestamp: v.u64("created_at_ms")?,
        body_len: REACTION.wire_size() - 1,
        scope: EventScope::Shared,
        workspace_id: Some(workspace),
        dependencies: deps,
        canonical_bytes: bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEvent {
    pub signer_endpoint_shared_id: EventId,
    pub signer_public_key: EventId,
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub message_id: EventId,
    pub author_user_id: EventId,
    pub file_id: EventId,
    pub blob_bytes: u64,
    pub total_slices: u32,
    pub slice_bytes: u32,
    pub root_hash: EventId,
    pub removal_frontier_id: EventId,
    pub local_history_node_secret_id: EventId,
    pub nonce: [u8; XCHACHA20_POLY1305_NONCE_BYTES],
    pub ciphertext: [u8; FILE_DESCRIPTOR_CIPHERTEXT_BYTES],
    pub signature: [u8; ED25519_SIGNATURE_BYTES],
}

pub const FILE: WireSchema = WireSchema::new(
    "content.file",
    15,
    &[
        Field::id("signer_endpoint_shared_id"),
        Field::id("signer_public_key"),
        Field::id("workspace_id"),
        Field::u64("created_at_ms"),
        Field::id("message_id"),
        Field::id("author_user_id"),
        Field::id("file_id"),
        Field::u64("blob_bytes"),
        Field::u32("total_slices"),
        Field::u32("slice_bytes"),
        Field::id("root_hash"),
        Field::id("removal_frontier_id"),
        Field::id("local_history_node_secret_id"),
        Field::bytes("nonce", XCHACHA20_POLY1305_NONCE_BYTES),
        Field::bytes("ciphertext", FILE_DESCRIPTOR_CIPHERTEXT_BYTES),
        Field::bytes("signature", ED25519_SIGNATURE_BYTES),
    ],
);

pub fn encode_file(e: &FileEvent) -> Vec<u8> {
    FILE.encoder()
        .id(&e.signer_endpoint_shared_id)
        .id(&e.signer_public_key)
        .id(&e.workspace_id)
        .u64(e.created_at_ms)
        .id(&e.message_id)
        .id(&e.author_user_id)
        .id(&e.file_id)
        .u64(e.blob_bytes)
        .u32(e.total_slices)
        .u32(e.slice_bytes)
        .id(&e.root_hash)
        .id(&e.removal_frontier_id)
        .id(&e.local_history_node_secret_id)
        .bytes(&e.nonce)
        .bytes(&e.ciphertext)
        .bytes(&e.signature)
        .finish()
}

pub fn record_from_file(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let v = FILE.parse(&bytes)?;
    let signer = v.id("signer_endpoint_shared_id")?;
    let workspace = v.id("workspace_id")?;
    let author = v.id("author_user_id")?;
    let message = v.id("message_id")?;
    let history = v.id("local_history_node_secret_id")?;
    let mut deps = Vec::with_capacity(5);
    for id in [signer, workspace, author, message, history] {
        push_unique(&mut deps, id);
    }
    Ok(EventRecord {
        timestamp: v.u64("created_at_ms")?,
        body_len: FILE.wire_size() - 1,
        scope: EventScope::Shared,
        workspace_id: Some(workspace),
        dependencies: deps,
        canonical_bytes: bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSliceEvent {
    pub signer_endpoint_shared_id: EventId,
    pub signer_public_key: EventId,
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub file_id: EventId,
    pub file_event_id: EventId,
    pub slice_number: u32,
    pub local_key_secret_id: EventId,
    pub plaintext_len: u32,
    pub proof: Vec<u8>,
    pub signature: [u8; ED25519_SIGNATURE_BYTES],
}

pub const FILE_SLICE: WireSchema = WireSchema::new(
    "content.file_slice",
    17,
    &[
        Field::id("signer_endpoint_shared_id"),
        Field::id("signer_public_key"),
        Field::id("workspace_id"),
        Field::u64("created_at_ms"),
        Field::id("file_id"),
        Field::id("file_event_id"),
        Field::u32("slice_number"),
        Field::id("local_key_secret_id"),
        Field::u32("plaintext_len"),
        Field::u32("proof_len"),
        Field::bytes("proof_slot", FILE_SLICE_PROOF_BYTES),
        Field::bytes("signature", ED25519_SIGNATURE_BYTES),
    ],
);

pub fn encode_file_slice(e: &FileSliceEvent) -> Result<Vec<u8>, String> {
    if e.proof.len() > FILE_SLICE_PROOF_BYTES {
        return Err("file slice proof exceeds slot capacity".to_string());
    }
    let proof_len = u32::try_from(e.proof.len())
        .map_err(|_| "file slice proof_len overflow".to_string())?;
    let mut slot = vec![0u8; FILE_SLICE_PROOF_BYTES];
    slot[..e.proof.len()].copy_from_slice(&e.proof);
    Ok(FILE_SLICE
        .encoder()
        .id(&e.signer_endpoint_shared_id)
        .id(&e.signer_public_key)
        .id(&e.workspace_id)
        .u64(e.created_at_ms)
        .id(&e.file_id)
        .id(&e.file_event_id)
        .u32(e.slice_number)
        .id(&e.local_key_secret_id)
        .u32(e.plaintext_len)
        .u32(proof_len)
        .bytes(&slot)
        .bytes(&e.signature)
        .finish())
}

pub fn decode_file_slice(bytes: &[u8]) -> Result<FileSliceEvent, String> {
    let v = FILE_SLICE.parse(bytes)?;
    let proof_len = v.u32("proof_len")? as usize;
    if proof_len > FILE_SLICE_PROOF_BYTES {
        return Err("file slice proof_len exceeds slot capacity".to_string());
    }
    let slot = v.raw("proof_slot")?;
    if slot[proof_len..].iter().any(|b| *b != 0) {
        return Err("file slice proof slot has non-zero padding".to_string());
    }
    Ok(FileSliceEvent {
        signer_endpoint_shared_id: v.id("signer_endpoint_shared_id")?,
        signer_public_key: v.id("signer_public_key")?,
        workspace_id: v.id("workspace_id")?,
        created_at_ms: v.u64("created_at_ms")?,
        file_id: v.id("file_id")?,
        file_event_id: v.id("file_event_id")?,
        slice_number: v.u32("slice_number")?,
        local_key_secret_id: v.id("local_key_secret_id")?,
        plaintext_len: v.u32("plaintext_len")?,
        proof: slot[..proof_len].to_vec(),
        signature: sig_array(v.raw("signature")?)?,
    })
}

pub fn record_from_file_slice(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let v = FILE_SLICE.parse(&bytes)?;
    let signer = v.id("signer_endpoint_shared_id")?;
    let workspace = v.id("workspace_id")?;
    let file_event = v.id("file_event_id")?;
    let key_secret = v.id("local_key_secret_id")?;
    let mut deps = Vec::with_capacity(4);
    for id in [signer, workspace, file_event, key_secret] {
        push_unique(&mut deps, id);
    }
    Ok(EventRecord {
        timestamp: v.u64("created_at_ms")?,
        body_len: FILE_SLICE.wire_size() - 1,
        scope: EventScope::Shared,
        workspace_id: Some(workspace),
        dependencies: deps,
        canonical_bytes: bytes,
    })
}

// ===========================================================================
// encryption events.
// ===========================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRecipientKey {
    pub workspace_id: EventId,
    pub recipient_key: EventId,
    pub recipient_secret: EventId,
}

pub const LOCAL_RECIPIENT_KEY: WireSchema = WireSchema::new(
    "encryption.local_recipient_key",
    143,
    &[
        Field::id("workspace_id"),
        Field::id("recipient_key"),
        Field::id("recipient_secret"),
    ],
);

pub fn encode_local_recipient_key(e: &LocalRecipientKey) -> Vec<u8> {
    LOCAL_RECIPIENT_KEY
        .encoder()
        .id(&e.workspace_id)
        .id(&e.recipient_key)
        .id(&e.recipient_secret)
        .finish()
}

pub fn record_from_local_recipient_key(bytes: Vec<u8>) -> Result<EventRecord, String> {
    LOCAL_RECIPIENT_KEY.parse(&bytes)?;
    Ok(EventRecord {
        timestamp: 0,
        body_len: 0,
        scope: EventScope::Local,
        workspace_id: None,
        dependencies: vec![],
        canonical_bytes: bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalKeySecret {
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    pub key_secret: EventId,
}

pub const LOCAL_KEY_SECRET: WireSchema = WireSchema::new(
    "encryption.local_key_secret",
    144,
    &[
        Field::id("workspace_id"),
        Field::id("removal_frontier_id"),
        Field::id("key_secret"),
    ],
);

pub fn encode_local_key_secret(e: &LocalKeySecret) -> Vec<u8> {
    LOCAL_KEY_SECRET
        .encoder()
        .id(&e.workspace_id)
        .id(&e.removal_frontier_id)
        .id(&e.key_secret)
        .finish()
}

pub fn record_from_local_key_secret(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let v = LOCAL_KEY_SECRET.parse(&bytes)?;
    let frontier = v.id("removal_frontier_id")?;
    Ok(EventRecord {
        timestamp: 0,
        body_len: 0,
        scope: EventScope::Local,
        workspace_id: None,
        dependencies: vec![frontier],
        canonical_bytes: bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHistoryNodeSecret {
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    pub source_secret_id: EventId,
    pub range_start: u64,
    pub range_width: u64,
    pub bit_depth: u16,
    pub event_id_prefix: EventId,
    pub tombstone_node_id: Option<EventId>,
    pub node_secret: EventId,
}

pub const LOCAL_HISTORY_NODE_SECRET: WireSchema = WireSchema::new(
    "encryption.local_history_node_secret",
    145,
    &[
        Field::id("workspace_id"),
        Field::id("removal_frontier_id"),
        Field::id("source_secret_id"),
        Field::u64("range_start"),
        Field::u64("range_width"),
        Field::u16("bit_depth"),
        Field::id("event_id_prefix"),
        Field::id("tombstone_node_id_or_zero"),
        Field::id("node_secret"),
    ],
);

pub fn encode_local_history_node_secret(e: &LocalHistoryNodeSecret) -> Vec<u8> {
    LOCAL_HISTORY_NODE_SECRET
        .encoder()
        .id(&e.workspace_id)
        .id(&e.removal_frontier_id)
        .id(&e.source_secret_id)
        .u64(e.range_start)
        .u64(e.range_width)
        .u16(e.bit_depth)
        .id(&e.event_id_prefix)
        .id(&e.tombstone_node_id.unwrap_or([0; 32]))
        .id(&e.node_secret)
        .finish()
}

pub fn record_from_local_history_node_secret(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let v = LOCAL_HISTORY_NODE_SECRET.parse(&bytes)?;
    let frontier = v.id("removal_frontier_id")?;
    let source = v.id("source_secret_id")?;
    let tombstone = optional_id(v.id("tombstone_node_id_or_zero")?);
    let mut deps = Vec::with_capacity(3);
    push_unique(&mut deps, frontier);
    push_unique(&mut deps, source);
    if let Some(id) = tombstone {
        push_unique(&mut deps, id);
    }
    Ok(EventRecord {
        timestamp: 0,
        body_len: 0,
        scope: EventScope::Local,
        workspace_id: None,
        dependencies: deps,
        canonical_bytes: bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientKeyEvent {
    pub signer_endpoint_shared_id: EventId,
    pub signer_public_key: EventId,
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub endpoint_shared_id: EventId,
    pub recipient_key: EventId,
    pub signature: [u8; ED25519_SIGNATURE_BYTES],
}

pub const RECIPIENT_KEY: WireSchema = WireSchema::new(
    "encryption.recipient_key",
    19,
    &[
        Field::id("signer_endpoint_shared_id"),
        Field::id("signer_public_key"),
        Field::id("workspace_id"),
        Field::u64("created_at_ms"),
        Field::id("endpoint_shared_id"),
        Field::id("recipient_key"),
        Field::bytes("signature", ED25519_SIGNATURE_BYTES),
    ],
);

pub fn encode_recipient_key(e: &RecipientKeyEvent) -> Vec<u8> {
    RECIPIENT_KEY
        .encoder()
        .id(&e.signer_endpoint_shared_id)
        .id(&e.signer_public_key)
        .id(&e.workspace_id)
        .u64(e.created_at_ms)
        .id(&e.endpoint_shared_id)
        .id(&e.recipient_key)
        .bytes(&e.signature)
        .finish()
}

pub fn record_from_recipient_key(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let v = RECIPIENT_KEY.parse(&bytes)?;
    let signer = v.id("signer_endpoint_shared_id")?;
    let endpoint = v.id("endpoint_shared_id")?;
    if signer != endpoint {
        return Err("recipient key signer must equal endpoint_shared_id".to_string());
    }
    let workspace = v.id("workspace_id")?;
    let mut deps = Vec::with_capacity(2);
    push_unique(&mut deps, endpoint);
    push_unique(&mut deps, workspace);
    Ok(EventRecord {
        timestamp: v.u64("created_at_ms")?,
        body_len: RECIPIENT_KEY.wire_size() - 1,
        scope: EventScope::Shared,
        workspace_id: Some(workspace),
        dependencies: deps,
        canonical_bytes: bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientKeyTombstoneEvent {
    pub signer_endpoint_shared_id: EventId,
    pub signer_public_key: EventId,
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub endpoint_shared_id: EventId,
    pub old_recipient_key_id: EventId,
    pub new_recipient_key_id: EventId,
    pub signature: [u8; ED25519_SIGNATURE_BYTES],
}

pub const RECIPIENT_KEY_TOMBSTONE: WireSchema = WireSchema::new(
    "encryption.recipient_key_tombstone",
    25,
    &[
        Field::id("signer_endpoint_shared_id"),
        Field::id("signer_public_key"),
        Field::id("workspace_id"),
        Field::u64("created_at_ms"),
        Field::id("endpoint_shared_id"),
        Field::id("old_recipient_key_id"),
        Field::id("new_recipient_key_id"),
        Field::bytes("signature", ED25519_SIGNATURE_BYTES),
    ],
);

pub fn encode_recipient_key_tombstone(e: &RecipientKeyTombstoneEvent) -> Vec<u8> {
    RECIPIENT_KEY_TOMBSTONE
        .encoder()
        .id(&e.signer_endpoint_shared_id)
        .id(&e.signer_public_key)
        .id(&e.workspace_id)
        .u64(e.created_at_ms)
        .id(&e.endpoint_shared_id)
        .id(&e.old_recipient_key_id)
        .id(&e.new_recipient_key_id)
        .bytes(&e.signature)
        .finish()
}

pub fn record_from_recipient_key_tombstone(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let v = RECIPIENT_KEY_TOMBSTONE.parse(&bytes)?;
    let endpoint = v.id("endpoint_shared_id")?;
    let workspace = v.id("workspace_id")?;
    let old = v.id("old_recipient_key_id")?;
    let new = v.id("new_recipient_key_id")?;
    let mut deps = Vec::with_capacity(4);
    for id in [endpoint, workspace, old, new] {
        push_unique(&mut deps, id);
    }
    Ok(EventRecord {
        timestamp: v.u64("created_at_ms")?,
        body_len: RECIPIENT_KEY_TOMBSTONE.wire_size() - 1,
        scope: EventScope::Shared,
        workspace_id: Some(workspace),
        dependencies: deps,
        canonical_bytes: bytes,
    })
}

/// Removal frontier carries an up-to-4 list of removal event ids: declared as
/// a `u8 removal_count` plus a fixed-size 4-id slot. Slots beyond `count` are
/// strict zero-pad; the decode validates that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalFrontierEvent {
    pub signer_endpoint_shared_id: EventId,
    pub signer_public_key: EventId,
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub authority_admin_id: EventId,
    pub removal_event_ids: Vec<EventId>,
    pub signature: [u8; ED25519_SIGNATURE_BYTES],
}

pub const REMOVAL_FRONTIER: WireSchema = WireSchema::new(
    "encryption.removal_frontier",
    21,
    &[
        Field::id("signer_endpoint_shared_id"),
        Field::id("signer_public_key"),
        Field::id("workspace_id"),
        Field::u64("created_at_ms"),
        Field::id("authority_admin_id"),
        Field::u8("removal_count"),
        Field::bytes("removal_slot", REMOVAL_FRONTIER_REMOVALS_BYTES),
        Field::bytes("signature", ED25519_SIGNATURE_BYTES),
    ],
);

pub fn encode_removal_frontier(e: &RemovalFrontierEvent) -> Result<Vec<u8>, String> {
    if e.removal_event_ids.len() > REMOVAL_FRONTIER_MAX_REMOVALS {
        return Err("removal frontier list exceeds slot capacity".to_string());
    }
    let mut slot = [0u8; REMOVAL_FRONTIER_REMOVALS_BYTES];
    for (i, id) in e.removal_event_ids.iter().enumerate() {
        slot[i * 32..(i + 1) * 32].copy_from_slice(id);
    }
    Ok(REMOVAL_FRONTIER
        .encoder()
        .id(&e.signer_endpoint_shared_id)
        .id(&e.signer_public_key)
        .id(&e.workspace_id)
        .u64(e.created_at_ms)
        .id(&e.authority_admin_id)
        .u8(e.removal_event_ids.len() as u8)
        .bytes(&slot)
        .bytes(&e.signature)
        .finish())
}

pub fn decode_removal_frontier(bytes: &[u8]) -> Result<RemovalFrontierEvent, String> {
    let v = REMOVAL_FRONTIER.parse(bytes)?;
    let count = v.u8("removal_count")? as usize;
    if count > REMOVAL_FRONTIER_MAX_REMOVALS {
        return Err("removal frontier count exceeds slot capacity".to_string());
    }
    let slot = v.raw("removal_slot")?;
    let used = count * 32;
    if slot[used..].iter().any(|b| *b != 0) {
        return Err("removal frontier slot has non-zero padding".to_string());
    }
    let mut removal_event_ids = Vec::with_capacity(count);
    for i in 0..count {
        removal_event_ids.push(id_array(&slot[i * 32..(i + 1) * 32])?);
    }
    Ok(RemovalFrontierEvent {
        signer_endpoint_shared_id: v.id("signer_endpoint_shared_id")?,
        signer_public_key: v.id("signer_public_key")?,
        workspace_id: v.id("workspace_id")?,
        created_at_ms: v.u64("created_at_ms")?,
        authority_admin_id: v.id("authority_admin_id")?,
        removal_event_ids,
        signature: sig_array(v.raw("signature")?)?,
    })
}

pub fn record_from_removal_frontier(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let event = decode_removal_frontier(&bytes)?;
    let mut deps =
        Vec::with_capacity(3 + event.removal_event_ids.len());
    push_unique(&mut deps, event.signer_endpoint_shared_id);
    push_unique(&mut deps, event.workspace_id);
    push_unique(&mut deps, event.authority_admin_id);
    for id in &event.removal_event_ids {
        push_unique(&mut deps, *id);
    }
    Ok(EventRecord {
        timestamp: event.created_at_ms,
        body_len: REMOVAL_FRONTIER.wire_size() - 1,
        scope: EventScope::Shared,
        workspace_id: Some(event.workspace_id),
        dependencies: deps,
        canonical_bytes: bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyWrapEvent {
    pub signer_endpoint_shared_id: EventId,
    pub signer_public_key: EventId,
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub removal_frontier_id: EventId,
    pub local_key_secret_id: EventId,
    pub recipient_key_id: EventId,
    pub sender_wrap_public_key: EventId,
    pub nonce: [u8; XCHACHA20_POLY1305_NONCE_BYTES],
    pub ciphertext: [u8; KEY_WRAP_CIPHERTEXT_BYTES],
    pub signature: [u8; ED25519_SIGNATURE_BYTES],
}

pub const KEY_WRAP: WireSchema = WireSchema::new(
    "encryption.key_wrap",
    23,
    &[
        Field::id("signer_endpoint_shared_id"),
        Field::id("signer_public_key"),
        Field::id("workspace_id"),
        Field::u64("created_at_ms"),
        Field::id("removal_frontier_id"),
        Field::id("local_key_secret_id"),
        Field::id("recipient_key_id"),
        Field::id("sender_wrap_public_key"),
        Field::bytes("nonce", XCHACHA20_POLY1305_NONCE_BYTES),
        Field::bytes("ciphertext", KEY_WRAP_CIPHERTEXT_BYTES),
        Field::bytes("signature", ED25519_SIGNATURE_BYTES),
    ],
);

pub fn encode_key_wrap(e: &KeyWrapEvent) -> Vec<u8> {
    KEY_WRAP
        .encoder()
        .id(&e.signer_endpoint_shared_id)
        .id(&e.signer_public_key)
        .id(&e.workspace_id)
        .u64(e.created_at_ms)
        .id(&e.removal_frontier_id)
        .id(&e.local_key_secret_id)
        .id(&e.recipient_key_id)
        .id(&e.sender_wrap_public_key)
        .bytes(&e.nonce)
        .bytes(&e.ciphertext)
        .bytes(&e.signature)
        .finish()
}

pub fn record_from_key_wrap(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let v = KEY_WRAP.parse(&bytes)?;
    let signer = v.id("signer_endpoint_shared_id")?;
    let workspace = v.id("workspace_id")?;
    let frontier = v.id("removal_frontier_id")?;
    let recipient = v.id("recipient_key_id")?;
    let mut deps = Vec::with_capacity(4);
    for id in [signer, workspace, frontier, recipient] {
        push_unique(&mut deps, id);
    }
    Ok(EventRecord {
        timestamp: v.u64("created_at_ms")?,
        body_len: KEY_WRAP.wire_size() - 1,
        scope: EventScope::Shared,
        workspace_id: Some(workspace),
        dependencies: deps,
        canonical_bytes: bytes,
    })
}

// ===========================================================================
// connection events — local, formerly magic-prefixed, now ordinary tags.
// ===========================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRequestEvent {
    pub from_endpoint: EventId,
    pub to_endpoint: EventId,
    pub nonce: EventId,
    pub bootstrap_hash: EventId,
    pub invite_secret_event_id: EventId,
    pub from_listen_addr: Option<SocketAddr>,
}

pub const CONNECTION_REQUEST: WireSchema = WireSchema::new(
    "connection.request",
    1,
    &[
        Field::id("from_endpoint"),
        Field::id("to_endpoint"),
        Field::id("nonce"),
        Field::id("bootstrap_hash"),
        Field::id("invite_secret_event_id"),
        Field::bytes("from_listen_addr", ADDR_BLOCK_BYTES),
    ],
);

pub fn encode_connection_request(e: &ConnectionRequestEvent) -> Vec<u8> {
    let addr_block = encode_addr_block(e.from_listen_addr);
    CONNECTION_REQUEST
        .encoder()
        .id(&e.from_endpoint)
        .id(&e.to_endpoint)
        .id(&e.nonce)
        .id(&e.bootstrap_hash)
        .id(&e.invite_secret_event_id)
        .bytes(&addr_block)
        .finish()
}

pub fn decode_connection_request(bytes: &[u8]) -> Result<ConnectionRequestEvent, String> {
    let v = CONNECTION_REQUEST.parse(bytes)?;
    Ok(ConnectionRequestEvent {
        from_endpoint: v.id("from_endpoint")?,
        to_endpoint: v.id("to_endpoint")?,
        nonce: v.id("nonce")?,
        bootstrap_hash: v.id("bootstrap_hash")?,
        invite_secret_event_id: v.id("invite_secret_event_id")?,
        from_listen_addr: decode_addr_block(v.raw("from_listen_addr")?)?,
    })
}

pub fn record_from_connection_request(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let v = CONNECTION_REQUEST.parse(&bytes)?;
    let invite = v.id("invite_secret_event_id")?;
    Ok(EventRecord {
        timestamp: 0,
        body_len: CONNECTION_REQUEST.wire_size() - 1,
        scope: EventScope::Local,
        workspace_id: None,
        dependencies: vec![invite],
        canonical_bytes: bytes,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionResponseEvent {
    pub from_endpoint: EventId,
    pub to_endpoint: EventId,
    pub request_id: EventId,
    pub connection_id: EventId,
}

pub const CONNECTION_RESPONSE: WireSchema = WireSchema::new(
    "connection.response",
    2,
    &[
        Field::id("from_endpoint"),
        Field::id("to_endpoint"),
        Field::id("request_id"),
        Field::id("connection_id"),
    ],
);

pub fn encode_connection_response(e: &ConnectionResponseEvent) -> Vec<u8> {
    CONNECTION_RESPONSE
        .encoder()
        .id(&e.from_endpoint)
        .id(&e.to_endpoint)
        .id(&e.request_id)
        .id(&e.connection_id)
        .finish()
}

pub fn record_from_connection_response(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let v = CONNECTION_RESPONSE.parse(&bytes)?;
    let request = v.id("request_id")?;
    Ok(EventRecord {
        timestamp: 0,
        body_len: 0,
        scope: EventScope::Local,
        workspace_id: None,
        dependencies: vec![request],
        canonical_bytes: bytes,
    })
}

// ===========================================================================
// Round-trip tests.
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn ed25519_sig() -> [u8; ED25519_SIGNATURE_BYTES] {
        [0xab; ED25519_SIGNATURE_BYTES]
    }

    fn xnonce() -> [u8; XCHACHA20_POLY1305_NONCE_BYTES] {
        [0x42; XCHACHA20_POLY1305_NONCE_BYTES]
    }

    #[test]
    fn have_id_roundtrips() {
        let e = HaveIdEvent { connection_id: [1; 32], timestamp: 42, id: [2; 32] };
        let bytes = encode_have_id(&e);
        assert_eq!(bytes.len(), 73);
        assert_eq!(decode_have_id(&bytes).unwrap(), e);
    }

    #[test]
    fn need_id_roundtrips() {
        let e = NeedIdEvent { connection_id: [1; 32], id: [2; 32] };
        let bytes = encode_need_id(&e);
        assert_eq!(bytes.len(), 65);
        assert_eq!(decode_need_id(&bytes).unwrap(), e);
    }

    #[test]
    fn compare_roundtrips() {
        let e = CompareEvent {
            connection_id: [1; 32],
            range_start: 0,
            range_end: 10,
            summary_count: 3,
            summary_fingerprint: [9; 32],
            response_requested: true,
        };
        let bytes = encode_compare(&e);
        assert_eq!(bytes.len(), 90);
        assert_eq!(decode_compare(&bytes).unwrap(), e);
    }

    #[test]
    fn workspace_record_extracts_timestamp_and_workspace_id() {
        let mut name = [0u8; WORKSPACE_NAME_BYTES];
        name[..5].copy_from_slice(b"hello");
        let e = WorkspaceEvent { created_at_ms: 1700, public_key: [7; 32], name };
        let bytes = encode_workspace(&e);
        let record = record_from_workspace(bytes.clone()).unwrap();
        assert_eq!(record.timestamp, 1700);
        assert_eq!(record.workspace_id, Some([7; 32]));
        assert_eq!(record.scope, EventScope::Shared);
    }

    #[test]
    fn admin_record_carries_signer_workspace_authority_user_deps() {
        let e = AdminEvent {
            signer_event_id: [9; 32],
            signer_public_key: [8; 32],
            created_at_ms: 1234,
            workspace_id: [1; 32],
            public_key: [2; 32],
            authority_event_id: [3; 32],
            user_event_id: [4; 32],
            signature: ed25519_sig(),
        };
        let record = record_from_admin(encode_admin(&e)).unwrap();
        assert_eq!(record.timestamp, 1234);
        assert_eq!(record.workspace_id, Some([1; 32]));
        assert_eq!(record.dependencies, vec![[9; 32], [1; 32], [3; 32], [4; 32]]);
    }

    #[test]
    fn message_record_extracts_signer_and_inner_deps() {
        let e = MessageEvent {
            signer_endpoint_shared_id: [9; 32],
            signer_public_key: [8; 32],
            workspace_id: [1; 32],
            created_at_ms: 1234,
            author_user_id: [2; 32],
            removal_frontier_id: [3; 32],
            local_history_node_secret_id: [4; 32],
            nonce: xnonce(),
            ciphertext: [6; MESSAGE_CIPHERTEXT_BYTES],
            signature: ed25519_sig(),
        };
        let record = record_from_message(encode_message(&e)).unwrap();
        assert_eq!(record.timestamp, 1234);
        assert_eq!(record.workspace_id, Some([1; 32]));
        assert_eq!(record.dependencies, vec![[9; 32], [1; 32], [2; 32], [3; 32], [4; 32]]);
    }

    #[test]
    fn message_deletion_record_dedupes() {
        let e = MessageDeletionEvent {
            signer_endpoint_shared_id: [9; 32],
            signer_public_key: [8; 32],
            workspace_id: [1; 32],
            created_at_ms: 999,
            target_message_id: [2; 32],
            author_user_id: [3; 32],
            signature: ed25519_sig(),
        };
        let record = record_from_message_deletion(encode_message_deletion(&e)).unwrap();
        assert_eq!(record.dependencies, vec![[9; 32], [1; 32], [3; 32], [2; 32]]);
    }

    #[test]
    fn file_slice_padded_proof_canonicalizes_and_rejects_dirty_padding() {
        let proof = vec![0x42; 1024];
        let e = FileSliceEvent {
            signer_endpoint_shared_id: [9; 32],
            signer_public_key: [8; 32],
            workspace_id: [1; 32],
            created_at_ms: 7,
            file_id: [2; 32],
            file_event_id: [3; 32],
            slice_number: 5,
            local_key_secret_id: [4; 32],
            plaintext_len: 1024,
            proof: proof.clone(),
            signature: [0; ED25519_SIGNATURE_BYTES],
        };
        let bytes = encode_file_slice(&e).unwrap();
        assert_eq!(decode_file_slice(&bytes).unwrap(), e);

        let mut tampered = bytes.clone();
        // proof_slot starts after: tag(1) + signer(32) + signer_pk(32) + workspace(32)
        // + created_at(8) + file_id(32) + file_event_id(32) + slice_number(4)
        // + local_key_secret_id(32) + plaintext_len(4) + proof_len(4) = 213
        let pad_index = 213 + proof.len();
        tampered[pad_index] = 1;
        assert!(decode_file_slice(&tampered).is_err());
    }

    #[test]
    fn removal_frontier_slot_canonicalizes() {
        let removals = vec![[1; 32], [2; 32], [3; 32]];
        let e = RemovalFrontierEvent {
            signer_endpoint_shared_id: [9; 32],
            signer_public_key: [8; 32],
            workspace_id: [7; 32],
            created_at_ms: 1,
            authority_admin_id: [4; 32],
            removal_event_ids: removals.clone(),
            signature: ed25519_sig(),
        };
        let bytes = encode_removal_frontier(&e).unwrap();
        let decoded = decode_removal_frontier(&bytes).unwrap();
        assert_eq!(decoded, e);

        let record = record_from_removal_frontier(bytes).unwrap();
        // dedup order: signer, workspace, authority_admin, removals
        assert_eq!(
            record.dependencies,
            vec![[9; 32], [7; 32], [4; 32], [1; 32], [2; 32], [3; 32]]
        );
    }

    #[test]
    fn connection_request_roundtrips_with_v4_addr() {
        let addr: SocketAddr = "10.0.0.1:8080".parse().unwrap();
        let e = ConnectionRequestEvent {
            from_endpoint: [1; 32],
            to_endpoint: [2; 32],
            nonce: [3; 32],
            bootstrap_hash: [4; 32],
            invite_secret_event_id: [5; 32],
            from_listen_addr: Some(addr),
        };
        let bytes = encode_connection_request(&e);
        assert_eq!(decode_connection_request(&bytes).unwrap(), e);
    }

    #[test]
    fn connection_response_record_carries_request_dep() {
        let e = ConnectionResponseEvent {
            from_endpoint: [1; 32],
            to_endpoint: [2; 32],
            request_id: [3; 32],
            connection_id: [4; 32],
        };
        let record = record_from_connection_response(encode_connection_response(&e)).unwrap();
        assert_eq!(record.dependencies, vec![[3; 32]]);
        assert_eq!(record.scope, EventScope::Local);
    }

    #[test]
    fn schema_arity_matches_encoder_calls_for_every_event() {
        // Compile-time sanity: building each encoder and immediately calling
        // finish() on a complete event proves the schema declarations match
        // their encoder usage.
        let _ = encode_have_id(&HaveIdEvent { connection_id: [0; 32], timestamp: 0, id: [0; 32] });
        let _ = encode_need_id(&NeedIdEvent { connection_id: [0; 32], id: [0; 32] });
        let _ = encode_compare(&CompareEvent {
            connection_id: [0; 32], range_start: 0, range_end: 0,
            summary_count: 0, summary_fingerprint: [0; 32], response_requested: false,
        });
        let _ = encode_local_endpoint(&EndpointKeypair {
            endpoint: [0; 32], secret: [0; 32],
            signing_public_key: [0; 32], signing_secret: [0; 32],
        });
        let _ = encode_invite_secret(&InviteSecretEvent {
            bootstrap_hash: [0; 32], bootstrap_secret: [0; 32],
            workspace_id: None, invite_event_id: None,
        });
        let _ = encode_invite_accepted(&InviteAcceptedEvent {
            workspace_id: [0; 32], invite_event_id: [0; 32],
            invite_secret_event_id: [0; 32], bootstrap_hash: [0; 32],
            accepted_endpoint_id: [0; 32],
        });
        let _ = encode_workspace(&WorkspaceEvent {
            created_at_ms: 0, public_key: [0; 32], name: [0; WORKSPACE_NAME_BYTES],
        });
        let _ = encode_admin(&AdminEvent {
            signer_event_id: [0; 32], signer_public_key: [0; 32],
            created_at_ms: 0, workspace_id: [0; 32], public_key: [0; 32],
            authority_event_id: [0; 32], user_event_id: [0; 32], signature: ed25519_sig(),
        });
        let _ = encode_user_invite(&UserInviteEvent {
            signer_event_id: [0; 32], signer_public_key: [0; 32],
            created_at_ms: 0, public_key: [0; 32], workspace_id: [0; 32],
            authority_event_id: [0; 32], signature: ed25519_sig(),
        });
        let _ = encode_invite_server(&InviteServerEvent {
            signer_event_id: [0; 32], signer_public_key: [0; 32],
            created_at_ms: 0, public_key: [0; 32], workspace_id: [0; 32],
            authority_event_id: [0; 32], signature: ed25519_sig(),
        });
        let _ = encode_user(&UserEvent {
            signer_event_id: [0; 32], signer_public_key: [0; 32],
            created_at_ms: 0, workspace_id: [0; 32], public_key: [0; 32],
            username: [0; USERNAME_BYTES], signature: ed25519_sig(),
        });
        let _ = encode_device_invite(&DeviceInviteEvent {
            signer_event_id: [0; 32], signer_public_key: [0; 32],
            created_at_ms: 0, workspace_id: [0; 32],
            user_authority_event_id: [0; 32], user_invite_event_id: None,
            public_key: [0; 32], signature: ed25519_sig(),
        });
        let _ = encode_endpoint_shared(&EndpointSharedEvent {
            signer_event_id: [0; 32], signer_public_key: [0; 32],
            created_at_ms: 0, workspace_id: [0; 32],
            user_authority_event_id: [0; 32], endpoint_id: [0; 32],
            signing_public_key: [0; 32], endpoint_role: 0,
            device_name: [0; ENDPOINT_DEVICE_NAME_BYTES], signature: ed25519_sig(),
        });
        let _ = encode_message_deletion(&MessageDeletionEvent {
            signer_endpoint_shared_id: [0; 32], signer_public_key: [0; 32],
            workspace_id: [0; 32], created_at_ms: 0,
            target_message_id: [0; 32], author_user_id: [0; 32], signature: ed25519_sig(),
        });
        let _ = encode_file_deletion(&FileDeletionEvent {
            signer_endpoint_shared_id: [0; 32], signer_public_key: [0; 32],
            workspace_id: [0; 32], created_at_ms: 0,
            target_file_event_id: [0; 32], author_user_id: [0; 32], signature: ed25519_sig(),
        });
        let _ = encode_message(&MessageEvent {
            signer_endpoint_shared_id: [0; 32], signer_public_key: [0; 32],
            workspace_id: [0; 32], created_at_ms: 0, author_user_id: [0; 32],
            removal_frontier_id: [0; 32], local_history_node_secret_id: [0; 32],
            nonce: xnonce(), ciphertext: [0; MESSAGE_CIPHERTEXT_BYTES], signature: ed25519_sig(),
        });
        let _ = encode_reaction(&ReactionEvent {
            signer_endpoint_shared_id: [0; 32], signer_public_key: [0; 32],
            workspace_id: [0; 32], created_at_ms: 0, target_message_id: [0; 32],
            author_user_id: [0; 32], removal_frontier_id: [0; 32],
            local_history_node_secret_id: [0; 32], nonce: xnonce(),
            ciphertext: [0; REACTION_CIPHERTEXT_BYTES], signature: ed25519_sig(),
        });
        let _ = encode_file(&FileEvent {
            signer_endpoint_shared_id: [0; 32], signer_public_key: [0; 32],
            workspace_id: [0; 32], created_at_ms: 0, message_id: [0; 32],
            author_user_id: [0; 32], file_id: [0; 32], blob_bytes: 0,
            total_slices: 0, slice_bytes: 0, root_hash: [0; 32],
            removal_frontier_id: [0; 32], local_history_node_secret_id: [0; 32],
            nonce: xnonce(), ciphertext: [0; FILE_DESCRIPTOR_CIPHERTEXT_BYTES],
            signature: ed25519_sig(),
        });
        let _ = encode_local_recipient_key(&LocalRecipientKey {
            workspace_id: [0; 32], recipient_key: [0; 32], recipient_secret: [0; 32],
        });
        let _ = encode_local_key_secret(&LocalKeySecret {
            workspace_id: [0; 32], removal_frontier_id: [0; 32], key_secret: [0; 32],
        });
        let _ = encode_local_history_node_secret(&LocalHistoryNodeSecret {
            workspace_id: [0; 32], removal_frontier_id: [0; 32],
            source_secret_id: [0; 32], range_start: 0, range_width: 0,
            bit_depth: 0, event_id_prefix: [0; 32], tombstone_node_id: None,
            node_secret: [0; 32],
        });
        let _ = encode_recipient_key(&RecipientKeyEvent {
            signer_endpoint_shared_id: [0; 32], signer_public_key: [0; 32],
            workspace_id: [0; 32], created_at_ms: 0, endpoint_shared_id: [0; 32],
            recipient_key: [0; 32], signature: ed25519_sig(),
        });
        let _ = encode_recipient_key_tombstone(&RecipientKeyTombstoneEvent {
            signer_endpoint_shared_id: [0; 32], signer_public_key: [0; 32],
            workspace_id: [0; 32], created_at_ms: 0, endpoint_shared_id: [0; 32],
            old_recipient_key_id: [0; 32], new_recipient_key_id: [0; 32],
            signature: ed25519_sig(),
        });
        let _ = encode_key_wrap(&KeyWrapEvent {
            signer_endpoint_shared_id: [0; 32], signer_public_key: [0; 32],
            workspace_id: [0; 32], created_at_ms: 0, removal_frontier_id: [0; 32],
            local_key_secret_id: [0; 32], recipient_key_id: [0; 32],
            sender_wrap_public_key: [0; 32], nonce: xnonce(),
            ciphertext: [0; KEY_WRAP_CIPHERTEXT_BYTES], signature: ed25519_sig(),
        });
        let _ = encode_connection_response(&ConnectionResponseEvent {
            from_endpoint: [0; 32], to_endpoint: [0; 32],
            request_id: [0; 32], connection_id: [0; 32],
        });
    }
}

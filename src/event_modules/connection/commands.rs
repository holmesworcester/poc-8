use std::{net::SocketAddr, str::FromStr};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::store::{EventId, Store};

use super::codec::{
    self, ConnectionEvent, ConnectionId, EndpointId, TransitEnvelope, TransitNonce,
};
use super::projector;
use super::tables;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    pub endpoint: EndpointId,
    pub bootstrap_secret: [u8; 32],
    pub addr: SocketAddr,
    pub invite_event_id: EventId,
    pub workspace_id: EventId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundRequest {
    pub bytes: Vec<u8>,
    pub request_id: EventId,
    pub local_endpoint: EndpointId,
    pub addr: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundResult {
    pub response: Option<Vec<u8>>,
    pub connection_id: Option<ConnectionId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwrappedTransit {
    pub inner: Vec<u8>,
    pub connection_id: Option<ConnectionId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportRoute {
    pub connection_id: ConnectionId,
    pub addr: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EndpointKeypair {
    endpoint: EndpointId,
    secret: [u8; 32],
}

const INVITE_PREFIX: &str = "topo://invite/";
const INVITE_VERSION: &str = "v6";
const INVITE_KIND: &str = "user";
const LABEL_INVITE_ID: &str = "INVITE_ID";
const LABEL_INVITE_PRIVKEY: &str = "INVITE_PRIVKEY";
const LABEL_WORKSPACE: &str = "WORKSPACE";
const LABEL_ENDPOINT_ID: &str = "ENDPOINT_ID";
const LABEL_ADDRESS: &str = "ADDRESS";

pub fn create_invite(store: &Store, public_addr: SocketAddr) -> Result<String, String> {
    let local = ensure_local_keypair(store)?;
    let invite_event_id = nonce32();
    let bootstrap_secret = nonce32();
    let workspace_id = nonce32();
    apply(
        store,
        projector::project_invite_secret(invite_secret_hash(&bootstrap_secret), bootstrap_secret),
    )?;
    Ok(format!(
        "{INVITE_PREFIX}{INVITE_VERSION}/{INVITE_KIND}/{LABEL_INVITE_ID}.{invite_id}/{LABEL_INVITE_PRIVKEY}.{invite_secret}/{LABEL_WORKSPACE}.{workspace}/{LABEL_ENDPOINT_ID}.{endpoint}/{LABEL_ADDRESS}.{address}",
        invite_id = encode_hex(&invite_event_id),
        invite_secret = encode_hex(&bootstrap_secret),
        workspace = encode_hex(&workspace_id),
        endpoint = encode_hex(&local.endpoint),
        address = encode_address(public_addr),
    ))
}

pub fn invite_addr(invite: &str) -> Result<SocketAddr, String> {
    Ok(parse_invite(invite)?.addr)
}

pub fn create_request(store: &Store, invite: &str) -> Result<OutboundRequest, String> {
    let invite = parse_invite(invite)?;
    let local = ensure_local_keypair(store)?;
    let request = ConnectionEvent::Request {
        from_endpoint: local.endpoint,
        nonce: nonce32(),
        bootstrap_hash: invite_secret_hash(&invite.bootstrap_secret),
    };
    let inner = codec::encode(&request);
    let request_id = codec::event_id(&inner);
    apply(store, projector::project_outbound_request(inner.clone())?)?;
    Ok(OutboundRequest {
        bytes: encrypt_bootstrap(&local, invite.endpoint, &inner)?,
        request_id,
        local_endpoint: local.endpoint,
        addr: invite.addr,
    })
}

pub fn ingest_inner(store: &Store, bytes: Vec<u8>) -> Result<InboundResult, String> {
    match codec::decode(&bytes)? {
        ConnectionEvent::Request { .. } => accept_request(store, bytes),
        ConnectionEvent::Ack { .. } => accept_ack(store, bytes),
    }
}

pub fn accept_request(store: &Store, bytes: Vec<u8>) -> Result<InboundResult, String> {
    let local = ensure_local_keypair(store)?;
    let request = codec::decode(&bytes)?;
    let ConnectionEvent::Request {
        from_endpoint,
        bootstrap_hash,
        ..
    } = request
    else {
        return Err("expected connection request".to_string());
    };
    if !bootstrap_hash_is_authorized(store, &bootstrap_hash)? {
        return Err("invite private key rejected".to_string());
    }
    let projection = projector::project_inbound_request(bytes, local.endpoint, bootstrap_hash)?;
    let response = projection
        .response
        .as_ref()
        .map(|bytes| encrypt_bootstrap(&local, from_endpoint, bytes))
        .transpose()?;
    let connection_id = projection.connection_id;
    apply(store, projection)?;
    Ok(InboundResult {
        response,
        connection_id,
    })
}

pub fn accept_ack(store: &Store, bytes: Vec<u8>) -> Result<InboundResult, String> {
    let local = ensure_local_keypair(store)?;
    let event = codec::decode(&bytes)?;
    let ConnectionEvent::Ack { request_id, .. } = event else {
        return Err("expected connection ack".to_string());
    };
    let request_bytes = store
        .module_row(tables::CONNECTION_EVENTS, &request_id)
        .map_err(|err| format!("load connection request: {err}"))?
        .ok_or_else(|| "connection ack references an unknown request".to_string())?;
    let request = codec::decode(&request_bytes)?;
    let ConnectionEvent::Request { from_endpoint, .. } = request else {
        return Err("connection ack references a non-request event".to_string());
    };
    if from_endpoint != local.endpoint {
        return Err("connection ack references another endpoint's request".to_string());
    }

    let projection = projector::project_inbound_ack(bytes, local.endpoint, request_id)?;
    let connection_id = projection.connection_id;
    apply(store, projection)?;
    Ok(InboundResult {
        response: None,
        connection_id,
    })
}

pub fn is_connection_event(bytes: &[u8]) -> bool {
    codec::is_connection_event(bytes)
}

pub fn wrap_connection(
    store: &Store,
    connection_id: ConnectionId,
    inner: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let local = ensure_local_keypair(store)?;
    let remote = remote_endpoint(store, &connection_id)?;
    encrypt_connection(&local, connection_id, remote, &inner)
}

pub fn unwrap_transit(store: &Store, bytes: &[u8]) -> Result<UnwrappedTransit, String> {
    let local = ensure_local_keypair(store)?;
    match codec::decode_transit(bytes)? {
        TransitEnvelope::Bootstrap {
            sender_endpoint,
            recipient_endpoint,
            nonce,
            ciphertext,
        } => {
            if recipient_endpoint != local.endpoint {
                return Err("bootstrap transit addressed to a different endpoint".to_string());
            }
            let envelope = TransitEnvelope::Bootstrap {
                sender_endpoint,
                recipient_endpoint,
                nonce,
                ciphertext: Vec::new(),
            };
            let inner = decrypt(
                &local.secret,
                &sender_endpoint,
                b"topo-bootstrap-transit-v1",
                &codec::transit_associated_data(&envelope),
                &nonce,
                &ciphertext,
            )?;
            Ok(UnwrappedTransit {
                inner,
                connection_id: None,
            })
        }
        TransitEnvelope::Connection {
            connection_id,
            sender_endpoint,
            recipient_endpoint,
            nonce,
            ciphertext,
        } => {
            if recipient_endpoint != local.endpoint {
                return Err("connection transit addressed to a different endpoint".to_string());
            }
            let remote = remote_endpoint(store, &connection_id)?;
            if sender_endpoint != remote {
                return Err("connection transit sender does not match connection".to_string());
            }
            let envelope = TransitEnvelope::Connection {
                connection_id,
                sender_endpoint,
                recipient_endpoint,
                nonce,
                ciphertext: Vec::new(),
            };
            let inner = decrypt(
                &local.secret,
                &sender_endpoint,
                b"topo-connection-transit-v1",
                &codec::transit_associated_data(&envelope),
                &nonce,
                &ciphertext,
            )?;
            Ok(UnwrappedTransit {
                inner,
                connection_id: Some(connection_id),
            })
        }
    }
}

pub fn connection_count(store: &Store) -> Result<usize, String> {
    store
        .module_row_count(tables::CONNECTIONS)
        .map_err(|err| format!("count connections: {err}"))
}

pub fn connection_event_count(store: &Store) -> Result<usize, String> {
    store
        .module_row_count(tables::CONNECTION_EVENTS)
        .map_err(|err| format!("count connection events: {err}"))
}

pub fn record_transport_target(
    store: &Store,
    connection_id: ConnectionId,
    addr: SocketAddr,
) -> Result<(), String> {
    apply(
        store,
        projector::project_transport_target(connection_id, addr),
    )
}

pub fn transport_routes(store: &Store) -> Result<Vec<TransportRoute>, String> {
    let rows = store
        .module_rows(tables::TRANSPORT_TARGETS)
        .map_err(|err| format!("load transport targets: {err}"))?;
    rows.into_iter()
        .map(|(key, value)| {
            let connection_id = bytes_to_id(&key)?;
            let text = String::from_utf8(value)
                .map_err(|err| format!("transport target is not utf8: {err}"))?;
            let addr = SocketAddr::from_str(&text)
                .map_err(|err| format!("transport target is invalid: {err}"))?;
            Ok(TransportRoute {
                connection_id,
                addr,
            })
        })
        .collect()
}

fn encrypt_bootstrap(
    local: &EndpointKeypair,
    recipient_endpoint: EndpointId,
    inner: &[u8],
) -> Result<Vec<u8>, String> {
    let nonce = nonce24();
    let envelope = TransitEnvelope::Bootstrap {
        sender_endpoint: local.endpoint,
        recipient_endpoint,
        nonce,
        ciphertext: Vec::new(),
    };
    let ciphertext = encrypt(
        &local.secret,
        &recipient_endpoint,
        b"topo-bootstrap-transit-v1",
        &codec::transit_associated_data(&envelope),
        &nonce,
        inner,
    )?;
    Ok(codec::encode_transit(&TransitEnvelope::Bootstrap {
        sender_endpoint: local.endpoint,
        recipient_endpoint,
        nonce,
        ciphertext,
    }))
}

fn encrypt_connection(
    local: &EndpointKeypair,
    connection_id: ConnectionId,
    recipient_endpoint: EndpointId,
    inner: &[u8],
) -> Result<Vec<u8>, String> {
    let nonce = nonce24();
    let envelope = TransitEnvelope::Connection {
        connection_id,
        sender_endpoint: local.endpoint,
        recipient_endpoint,
        nonce,
        ciphertext: Vec::new(),
    };
    let ciphertext = encrypt(
        &local.secret,
        &recipient_endpoint,
        b"topo-connection-transit-v1",
        &codec::transit_associated_data(&envelope),
        &nonce,
        inner,
    )?;
    Ok(codec::encode_transit(&TransitEnvelope::Connection {
        connection_id,
        sender_endpoint: local.endpoint,
        recipient_endpoint,
        nonce,
        ciphertext,
    }))
}

fn encrypt(
    local_secret: &[u8; 32],
    remote_endpoint: &EndpointId,
    purpose: &[u8],
    associated_data: &[u8],
    nonce: &TransitNonce,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let key = derive_key(local_secret, remote_endpoint, purpose)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: associated_data,
            },
        )
        .map_err(|_| "encrypt transit envelope".to_string())
}

fn decrypt(
    local_secret: &[u8; 32],
    remote_endpoint: &EndpointId,
    purpose: &[u8],
    associated_data: &[u8],
    nonce: &TransitNonce,
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let key = derive_key(local_secret, remote_endpoint, purpose)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: associated_data,
            },
        )
        .map_err(|_| "decrypt transit envelope".to_string())
}

fn derive_key(
    local_secret: &[u8; 32],
    remote_endpoint: &EndpointId,
    purpose: &[u8],
) -> Result<[u8; 32], String> {
    let secret = StaticSecret::from(*local_secret);
    let remote = PublicKey::from(*remote_endpoint);
    let shared = secret.diffie_hellman(&remote);
    let hkdf = Hkdf::<Sha256>::new(Some(purpose), shared.as_bytes());
    let mut key = [0; 32];
    hkdf.expand(b"topo transit key", &mut key)
        .map_err(|_| "derive transit key".to_string())?;
    Ok(key)
}

fn ensure_local_keypair(store: &Store) -> Result<EndpointKeypair, String> {
    let secret = store
        .module_row(tables::LOCAL_ENDPOINT_SECRET, b"local")
        .map_err(|err| format!("load local endpoint secret: {err}"))?;
    let endpoint = store
        .module_row(tables::LOCAL_ENDPOINT, b"local")
        .map_err(|err| format!("load local endpoint: {err}"))?;

    match (secret, endpoint) {
        (Some(secret), Some(endpoint)) => {
            let secret = bytes_to_id(&secret)?;
            let endpoint = bytes_to_id(&endpoint)?;
            let derived = PublicKey::from(&StaticSecret::from(secret)).to_bytes();
            if derived != endpoint {
                return Err("stored endpoint does not match local endpoint secret".to_string());
            }
            Ok(EndpointKeypair { endpoint, secret })
        }
        (None, None) => {
            let secret = StaticSecret::random_from_rng(OsRng);
            let endpoint = PublicKey::from(&secret).to_bytes();
            let secret = secret.to_bytes();
            apply(store, projector::project_local_endpoint(endpoint, secret))?;
            Ok(EndpointKeypair { endpoint, secret })
        }
        (None, Some(_)) => Err("local endpoint secret is missing".to_string()),
        (Some(_), None) => Err("local endpoint public key is missing".to_string()),
    }
}

fn remote_endpoint(store: &Store, connection_id: &ConnectionId) -> Result<EndpointId, String> {
    let bytes = store
        .module_row(tables::CONNECTIONS, connection_id)
        .map_err(|err| format!("load connection: {err}"))?
        .ok_or_else(|| "unknown connection".to_string())?;
    bytes_to_id(&bytes)
}

fn apply(store: &Store, projection: projector::Projection) -> Result<(), String> {
    store
        .insert_module_rows(projection.rows)
        .map(|_| ())
        .map_err(|err| format!("apply connection projection: {err}"))
}

fn parse_invite(value: &str) -> Result<Invite, String> {
    let body = value
        .strip_prefix(INVITE_PREFIX)
        .ok_or_else(|| "invite must start with topo://invite/".to_string())?;
    let mut parts = body.split('/');
    let version = parts
        .next()
        .ok_or_else(|| "invite is missing version".to_string())?;
    if version != INVITE_VERSION {
        return Err(format!("unsupported invite version {version}"));
    }
    let kind = parts
        .next()
        .ok_or_else(|| "invite is missing kind".to_string())?;
    if kind != INVITE_KIND {
        return Err(format!("unsupported invite kind {kind}"));
    }

    let mut endpoint = None;
    let mut bootstrap_secret = None;
    let mut addr = None;
    let mut invite_event_id = None;
    let mut workspace_id = None;

    for part in parts {
        let (label, value) = part
            .split_once('.')
            .ok_or_else(|| format!("invite part `{part}` is missing label"))?;
        match label {
            LABEL_INVITE_ID => invite_event_id = Some(decode_hex_32(value)?),
            LABEL_INVITE_PRIVKEY => bootstrap_secret = Some(decode_hex_32(value)?),
            LABEL_WORKSPACE => workspace_id = Some(decode_hex_32(value)?),
            LABEL_ENDPOINT_ID => endpoint = Some(decode_hex_32(value)?),
            LABEL_ADDRESS => addr = Some(decode_address(value)?),
            other => return Err(format!("unknown invite part `{other}`")),
        }
    }

    Ok(Invite {
        endpoint: endpoint.ok_or_else(|| "invite is missing ENDPOINT_ID".to_string())?,
        bootstrap_secret: bootstrap_secret
            .ok_or_else(|| "invite is missing INVITE_PRIVKEY".to_string())?,
        addr: addr.ok_or_else(|| "invite is missing ADDRESS".to_string())?,
        invite_event_id: invite_event_id
            .ok_or_else(|| "invite is missing INVITE_ID".to_string())?,
        workspace_id: workspace_id.ok_or_else(|| "invite is missing WORKSPACE".to_string())?,
    })
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn invite_secret_hash(secret: &[u8; 32]) -> [u8; 32] {
    codec::bootstrap_hash(&encode_hex(secret))
}

fn bootstrap_hash_is_authorized(store: &Store, bootstrap_hash: &[u8; 32]) -> Result<bool, String> {
    store
        .module_row(tables::INVITE_SECRETS, bootstrap_hash)
        .map(|row| row.is_some())
        .map_err(|err| format!("load invite secret: {err}"))
}

fn encode_address(addr: SocketAddr) -> String {
    format!("{}_{}", addr.ip(), addr.port())
}

fn decode_address(value: &str) -> Result<SocketAddr, String> {
    if let Ok(addr) = SocketAddr::from_str(value) {
        return Ok(addr);
    }
    let (host, port) = value
        .rsplit_once('_')
        .ok_or_else(|| "invite ADDRESS must include a port".to_string())?;
    let port = port
        .parse::<u16>()
        .map_err(|_| "invite ADDRESS port is invalid".to_string())?;
    let candidate = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    SocketAddr::from_str(&candidate).map_err(|_| "invite ADDRESS is invalid".to_string())
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err("invite hex field must be 64 hex characters".to_string());
    }
    let mut out = [0; 32];
    let bytes = value.as_bytes();
    for idx in 0..32 {
        out[idx] = (hex_value(bytes[idx * 2])? << 4) | hex_value(bytes[idx * 2 + 1])?;
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invite hex field is not hex".to_string()),
    }
}

fn bytes_to_id(bytes: &[u8]) -> Result<EndpointId, String> {
    if bytes.len() != 32 {
        return Err("stored endpoint id is malformed".to_string());
    }
    let mut out = [0; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn nonce24() -> TransitNonce {
    let mut nonce = [0; 24];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn nonce32() -> [u8; 32] {
    let mut nonce = [0; 32];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

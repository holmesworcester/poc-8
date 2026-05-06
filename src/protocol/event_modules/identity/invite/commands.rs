//! Invite creation and parsing.
//!
//! An invite is a human-copyable carrier for address, endpoint, workspace id,
//! and a bootstrap private value. The durable/local state is only the
//! hash-to-secret event proposed by `create`; parsing a link performs no writes.
//! This mirrors the event-module rule: commands return events and values, while
//! workers/projectors decide what becomes rows.

use std::{net::SocketAddr, str::FromStr};

use crate::core::crypto;
use crate::core::crypto::Ed25519PrivateKey;
use crate::protocol::event_modules::identity::endpoint::types::EndpointRole;
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker::CommandOutput;

use super::super::endpoint;
use super::codec;
use super::types::{Invite, InviteSecretEvent};

const INVITE_PREFIX: &str = "topo://invite/";
const INVITE_VERSION: &str = "v6";
const INVITE_KIND: &str = "user";
const LABEL_INVITE_ID: &str = "INVITE_ID";
const LABEL_INVITE_PRIVKEY: &str = "INVITE_PRIVKEY";
const LABEL_WORKSPACE: &str = "WORKSPACE";
const LABEL_SCOPE: &str = "SCOPE";
const SCOPE_IDENTITY: &str = "identity";
const LABEL_USER_ID: &str = "USER_ID";
const LABEL_ENDPOINT_ROLE: &str = "ENDPOINT_ROLE";
const LABEL_ENDPOINT_ID: &str = "ENDPOINT_ID";
const LABEL_ADDRESS: &str = "ADDRESS";

pub fn create(
    local: endpoint::types::EndpointKeypair,
    public_addr: SocketAddr,
) -> CommandOutput<String> {
    // The link includes the secret; the local event stores only the mapping
    // needed to authorize a future request that proves knowledge of it.
    let invite_event_id = nonce32();
    let bootstrap_secret = nonce32();
    let workspace_id = nonce32();
    let secret_event = InviteSecretEvent::new(bootstrap_secret);
    let bytes = codec::encode(&secret_event);
    CommandOutput::with_events(
        format!(
            "{INVITE_PREFIX}{INVITE_VERSION}/{INVITE_KIND}/{LABEL_INVITE_ID}.{invite_id}/{LABEL_INVITE_PRIVKEY}.{invite_secret}/{LABEL_WORKSPACE}.{workspace}/{LABEL_ENDPOINT_ID}.{endpoint}/{LABEL_ADDRESS}.{address}",
            invite_id = encode_hex(&invite_event_id),
            invite_secret = encode_hex(&bootstrap_secret),
            workspace = encode_hex(&workspace_id),
            endpoint = encode_hex(&local.endpoint),
            address = encode_address(public_addr),
        ),
        vec![codec::record_from_bytes(bytes).expect("encoded invite secret is valid")],
    )
}

pub fn create_scoped(
    local: endpoint::types::EndpointKeypair,
    public_addr: SocketAddr,
    workspace_id: EventId,
    invite_event_id: EventId,
    invite_private_key: Ed25519PrivateKey,
) -> CommandOutput<String> {
    create_scoped_with_role(
        local,
        public_addr,
        workspace_id,
        invite_event_id,
        invite_private_key,
        EndpointRole::Device,
        None,
    )
}

pub fn create_scoped_with_user_authority(
    local: endpoint::types::EndpointKeypair,
    public_addr: SocketAddr,
    workspace_id: EventId,
    invite_event_id: EventId,
    invite_private_key: Ed25519PrivateKey,
    user_authority_event_id: Option<EventId>,
) -> CommandOutput<String> {
    create_scoped_with_role(
        local,
        public_addr,
        workspace_id,
        invite_event_id,
        invite_private_key,
        EndpointRole::Device,
        user_authority_event_id,
    )
}

pub fn create_scoped_with_role(
    local: endpoint::types::EndpointKeypair,
    public_addr: SocketAddr,
    workspace_id: EventId,
    invite_event_id: EventId,
    invite_private_key: Ed25519PrivateKey,
    endpoint_role: EndpointRole,
    user_authority_event_id: Option<EventId>,
) -> CommandOutput<String> {
    let secret_event = InviteSecretEvent::scoped(invite_private_key, workspace_id, invite_event_id);
    let bytes = codec::encode(&secret_event);
    let user_part = user_authority_event_id
        .map(|user_id| format!("/{LABEL_USER_ID}.{}", encode_hex(&user_id)))
        .unwrap_or_default();
    CommandOutput::with_events(
        format!(
            "{INVITE_PREFIX}{INVITE_VERSION}/{INVITE_KIND}/{LABEL_INVITE_ID}.{invite_id}/{LABEL_INVITE_PRIVKEY}.{invite_secret}/{LABEL_WORKSPACE}.{workspace}/{LABEL_SCOPE}.{scope}/{LABEL_ENDPOINT_ROLE}.{endpoint_role}{user_part}/{LABEL_ENDPOINT_ID}.{endpoint}/{LABEL_ADDRESS}.{address}",
            invite_id = encode_hex(&invite_event_id),
            invite_secret = encode_hex(&invite_private_key),
            workspace = encode_hex(&workspace_id),
            scope = SCOPE_IDENTITY,
            endpoint_role = endpoint_role.as_str(),
            user_part = user_part,
            endpoint = encode_hex(&local.endpoint),
            address = encode_address(public_addr),
        ),
        vec![codec::record_from_bytes(bytes).expect("encoded invite secret is valid")],
    )
}

pub fn create_with_local(
    context: &impl endpoint::commands::LocalEndpointRead,
    public_addr: SocketAddr,
) -> Result<CommandOutput<String>, String> {
    let local = endpoint::commands::local_or_create(context)?;
    Ok(create(local.value, public_addr).prepend_events(local.events))
}

pub fn addr(invite: &str) -> Result<SocketAddr, String> {
    Ok(parse(invite)?.addr)
}

pub fn parse(value: &str) -> Result<Invite, String> {
    // The current syntax follows the older POC shape closely so black-box CLI
    // tests can treat invites as real links rather than test-only handles.
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
    let mut user_authority_event_id = None;
    let mut endpoint_role = None;
    let mut identity_scope = false;

    for part in parts {
        let (label, value) = part
            .split_once('.')
            .ok_or_else(|| format!("invite part `{part}` is missing label"))?;
        match label {
            LABEL_INVITE_ID => {
                if invite_event_id.replace(decode_hex_32(value)?).is_some() {
                    return Err("invite has duplicate INVITE_ID".to_string());
                }
            }
            LABEL_INVITE_PRIVKEY => {
                if bootstrap_secret.replace(decode_hex_32(value)?).is_some() {
                    return Err("invite has duplicate INVITE_PRIVKEY".to_string());
                }
            }
            LABEL_WORKSPACE => {
                if workspace_id.replace(decode_hex_32(value)?).is_some() {
                    return Err("invite has duplicate WORKSPACE".to_string());
                }
            }
            LABEL_SCOPE => {
                if identity_scope {
                    return Err("invite has duplicate SCOPE".to_string());
                }
                if value != SCOPE_IDENTITY {
                    return Err(format!("unsupported invite scope {value}"));
                }
                identity_scope = true;
            }
            LABEL_USER_ID => {
                if user_authority_event_id
                    .replace(decode_hex_32(value)?)
                    .is_some()
                {
                    return Err("invite has duplicate USER_ID".to_string());
                }
            }
            LABEL_ENDPOINT_ROLE => {
                if endpoint_role
                    .replace(decode_endpoint_role(value)?)
                    .is_some()
                {
                    return Err("invite has duplicate ENDPOINT_ROLE".to_string());
                }
            }
            LABEL_ENDPOINT_ID => {
                if endpoint.replace(decode_hex_32(value)?).is_some() {
                    return Err("invite has duplicate ENDPOINT_ID".to_string());
                }
            }
            LABEL_ADDRESS => {
                if addr.replace(decode_address(value)?).is_some() {
                    return Err("invite has duplicate ADDRESS".to_string());
                }
            }
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
        user_authority_event_id,
        endpoint_role: endpoint_role.unwrap_or(EndpointRole::Device),
        identity_scope,
    })
}

pub fn secret_hash(secret: &[u8; 32]) -> [u8; 32] {
    super::types::bootstrap_secret_hash(secret)
}

pub fn encode_hex(bytes: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
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

fn decode_endpoint_role(value: &str) -> Result<EndpointRole, String> {
    match value {
        "device" => Ok(EndpointRole::Device),
        "invite-server" => Ok(EndpointRole::InviteServer),
        other => Err(format!("unsupported endpoint role {other}")),
    }
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

fn nonce32() -> [u8; 32] {
    crypto::random_bytes_32()
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::identity::endpoint;
    use crate::protocol::event_modules::types::EventScope;

    use super::*;

    fn local_endpoint() -> endpoint::types::EndpointKeypair {
        endpoint::commands::create_local_keypair().value
    }

    #[test]
    fn create_invite_proposes_local_only_secret_event_and_parseable_link() {
        let local = local_endpoint();
        let public_addr = "127.0.0.1:41001".parse().expect("socket addr");
        let output = create(local, public_addr);

        assert_eq!(output.events.len(), 1);
        let record = output.events[0].record();
        assert_eq!(record.scope, EventScope::Local);
        assert!(!record.scope.is_shared());
        assert!(record.dependencies.is_empty());

        let invite = parse(&output.value).expect("parse created invite");
        assert_eq!(invite.endpoint, local.endpoint);
        assert_eq!(invite.addr, public_addr);

        let secret_event =
            codec::decode(&record.canonical_bytes).expect("decode local invite secret");
        assert_eq!(
            secret_event.bootstrap_hash,
            secret_hash(&invite.bootstrap_secret)
        );
        assert_eq!(secret_event.bootstrap_secret, invite.bootstrap_secret);
    }

    #[test]
    fn parse_accepts_stable_invite_link_shape() {
        let link = concat!(
            "topo://invite/v6/user/",
            "INVITE_ID.",
            "1111111111111111111111111111111111111111111111111111111111111111/",
            "INVITE_PRIVKEY.",
            "2222222222222222222222222222222222222222222222222222222222222222/",
            "WORKSPACE.",
            "3333333333333333333333333333333333333333333333333333333333333333/",
            "ENDPOINT_ID.",
            "4444444444444444444444444444444444444444444444444444444444444444/",
            "ADDRESS.127.0.0.1_42000"
        );

        let invite = parse(link).expect("parse stable invite");

        assert_eq!(invite.invite_event_id, [0x11; 32]);
        assert_eq!(invite.bootstrap_secret, [0x22; 32]);
        assert_eq!(invite.workspace_id, [0x33; 32]);
        assert_eq!(invite.endpoint, [0x44; 32]);
        assert_eq!(
            invite.addr,
            "127.0.0.1:42000".parse::<std::net::SocketAddr>().unwrap()
        );
        assert_eq!(addr(link).expect("parse invite addr"), invite.addr);
    }

    #[test]
    fn parse_rejects_duplicate_or_unknown_invite_parts() {
        let duplicate = concat!(
            "topo://invite/v6/user/",
            "INVITE_ID.",
            "1111111111111111111111111111111111111111111111111111111111111111/",
            "INVITE_ID.",
            "2222222222222222222222222222222222222222222222222222222222222222/",
            "INVITE_PRIVKEY.",
            "2222222222222222222222222222222222222222222222222222222222222222/",
            "WORKSPACE.",
            "3333333333333333333333333333333333333333333333333333333333333333/",
            "ENDPOINT_ID.",
            "4444444444444444444444444444444444444444444444444444444444444444/",
            "ADDRESS.127.0.0.1_42000"
        );
        let unknown = concat!(
            "topo://invite/v6/user/",
            "INVITE_ID.",
            "1111111111111111111111111111111111111111111111111111111111111111/",
            "INVITE_PRIVKEY.",
            "2222222222222222222222222222222222222222222222222222222222222222/",
            "WORKSPACE.",
            "3333333333333333333333333333333333333333333333333333333333333333/",
            "ENDPOINT_ID.",
            "4444444444444444444444444444444444444444444444444444444444444444/",
            "EXTRA.value/",
            "ADDRESS.127.0.0.1_42000"
        );

        assert_eq!(
            parse(duplicate).expect_err("duplicate field must fail"),
            "invite has duplicate INVITE_ID"
        );
        assert_eq!(
            parse(unknown).expect_err("unknown field must fail"),
            "unknown invite part `EXTRA`"
        );
    }

    #[test]
    fn secret_hash_is_stable_domain_separated_and_secret_sensitive() {
        let secret = [0x42; 32];
        let same_secret = [0x42; 32];
        let other_secret = [0x43; 32];

        assert_eq!(secret_hash(&secret), secret_hash(&same_secret));
        assert_ne!(secret_hash(&secret), secret);
        assert_ne!(secret_hash(&secret), secret_hash(&other_secret));
        assert_eq!(
            encode_hex(&secret_hash(&secret)),
            "be8e6cf94085c4c35ebb239b6128f50cb5b3fb9d6d624b6db280833a6d47797e"
        );
    }
}

//! Invite value types.
//!
//! `Invite` is the parsed link used by commands. `InviteSecretEvent` is the
//! local event projected into authorization state. Keeping them separate makes
//! it clear which fields travel in a link and which fields enter the store.

use std::net::SocketAddr;

use crate::protocol::event_modules::types::EventId;

use super::super::endpoint::types::{EndpointId, EndpointRole};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    pub endpoint: EndpointId,
    pub bootstrap_secret: [u8; 32],
    pub addr: SocketAddr,
    pub invite_event_id: EventId,
    pub workspace_id: EventId,
    pub user_authority_event_id: Option<EventId>,
    pub endpoint_role: EndpointRole,
    pub identity_scope: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteSecretEvent {
    pub bootstrap_hash: [u8; 32],
    pub bootstrap_secret: [u8; 32],
    pub workspace_id: Option<EventId>,
    pub invite_event_id: Option<EventId>,
}

impl InviteSecretEvent {
    pub fn new(bootstrap_secret: [u8; 32]) -> Self {
        Self {
            bootstrap_hash: bootstrap_secret_hash(&bootstrap_secret),
            bootstrap_secret,
            workspace_id: None,
            invite_event_id: None,
        }
    }

    pub fn scoped(
        bootstrap_secret: [u8; 32],
        workspace_id: EventId,
        invite_event_id: EventId,
    ) -> Self {
        Self {
            bootstrap_hash: bootstrap_secret_hash(&bootstrap_secret),
            bootstrap_secret,
            workspace_id: Some(workspace_id),
            invite_event_id: Some(invite_event_id),
        }
    }

    pub fn validate(self) -> Result<Self, String> {
        let expected = bootstrap_secret_hash(&self.bootstrap_secret);
        if self.bootstrap_hash != expected {
            return Err("invite secret hash does not match secret".to_string());
        }
        if self.workspace_id.is_some() != self.invite_event_id.is_some() {
            return Err("invite secret scope is incomplete".to_string());
        }
        Ok(self)
    }
}

pub fn bootstrap_secret_hash(secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"topo-bootstrap-token-v1");
    hasher.update(encode_hex(secret).as_bytes());
    *hasher.finalize().as_bytes()
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

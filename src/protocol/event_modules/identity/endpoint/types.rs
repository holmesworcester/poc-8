//! Local endpoint types.
//!
//! Endpoint ids are X25519 public keys used for transit. Endpoints also carry a
//! distinct Ed25519 signing key used by shared events that are authorized by an
//! endpoint's workspace membership. Both private keys are local-only facts.

use crate::core::crypto::{Ed25519PrivateKey, Ed25519PublicKey};

pub type EndpointId = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointRole {
    Device,
    InviteServer,
}

impl EndpointRole {
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Device => 1,
            Self::InviteServer => 2,
        }
    }

    pub fn from_u8(value: u8) -> Result<Self, String> {
        match value {
            1 => Ok(Self::Device),
            2 => Ok(Self::InviteServer),
            _ => Err("unknown endpoint role".to_string()),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::InviteServer => "invite-server",
        }
    }

    pub const fn can_receive_key_wraps(self) -> bool {
        matches!(self, Self::Device)
    }

    pub const fn can_grant(self, target: Self) -> bool {
        matches!(self, Self::Device) || matches!(target, Self::InviteServer)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointKeypair {
    pub endpoint: EndpointId,
    pub secret: [u8; 32],
    pub signing_public_key: Ed25519PublicKey,
    pub signing_secret: Ed25519PrivateKey,
}

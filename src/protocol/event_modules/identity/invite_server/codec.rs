//! Codec for invite-server payloads.
//!
//! Invite-server payloads mirror user-invite payloads and are signed by
//! `identity::signed` before admission:
//!
//! ```text
//! type(1) || created_at_ms(8) || public_key(32) || workspace_id(32) || authority_event_id(32)
//! ```

use crate::protocol::wire::{Reader, Writer};

use super::types::InviteServerEvent;

pub const TYPE_INVITE_SERVER: u8 = 136;
pub const INVITE_SERVER_WIRE_SIZE: usize = 1 + 8 + 32 + 32 + 32;

pub fn encode(event: &InviteServerEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(INVITE_SERVER_WIRE_SIZE);
    out.u8(TYPE_INVITE_SERVER);
    out.u64(event.created_at_ms);
    out.id(&event.public_key);
    out.id(&event.workspace_id);
    out.id(&event.authority_event_id);
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<InviteServerEvent, String> {
    let mut reader = Reader::new(bytes, "invite_server");
    let tag = reader.u8()?;
    if tag != TYPE_INVITE_SERVER {
        return Err("expected invite_server".to_string());
    }
    let event = InviteServerEvent {
        created_at_ms: reader.u64()?,
        public_key: reader.id()?,
        workspace_id: reader.id()?,
        authority_event_id: reader.id()?,
    };
    reader.finish()?;
    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> InviteServerEvent {
        InviteServerEvent {
            created_at_ms: 123,
            public_key: [1; 32],
            workspace_id: [2; 32],
            authority_event_id: [2; 32],
        }
    }

    #[test]
    fn roundtrips_fixed_width_invite_server_payload() {
        let encoded = encode(&event());

        assert_eq!(encoded.len(), INVITE_SERVER_WIRE_SIZE);
        assert_eq!(decode(&encoded).expect("decode invite_server"), event());
    }

    #[test]
    fn rejects_wrong_type_and_trailing_bytes() {
        let mut wrong_type = encode(&event());
        wrong_type[0] = 99;
        assert_eq!(
            decode(&wrong_type).expect_err("wrong type must fail"),
            "expected invite_server"
        );

        let mut trailing = encode(&event());
        trailing.push(0);
        assert!(decode(&trailing)
            .expect_err("trailing bytes must fail")
            .contains("trailing invite_server bytes"));
    }
}

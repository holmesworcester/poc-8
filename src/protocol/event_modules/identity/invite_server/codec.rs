//! Codec for invite-server payloads.
//!
//! Invite-server payloads mirror user-invite payloads and are signed by
//! `identity::signed` before admission:
//!
//! ```text
//! type(1) || created_at_ms(8) || public_key(32) || workspace_id(32) || authority_event_id(32)
//! ```

use crate::protocol::wire_schema::{Field, WireSchema};

use super::types::InviteServerEvent;

pub const TYPE_INVITE_SERVER: u8 = 136;

pub const SCHEMA: WireSchema = WireSchema::new(
    "invite_server",
    TYPE_INVITE_SERVER,
    &[
        Field::u64("created_at_ms"),
        Field::id("public_key"),
        Field::id("workspace_id"),
        Field::id("authority_event_id"),
    ],
);

pub const INVITE_SERVER_WIRE_SIZE: usize = SCHEMA.wire_size();

pub fn encode(event: &InviteServerEvent) -> Vec<u8> {
    SCHEMA
        .encoder()
        .u64(event.created_at_ms)
        .id(&event.public_key)
        .id(&event.workspace_id)
        .id(&event.authority_event_id)
        .finish()
}

pub fn decode(bytes: &[u8]) -> Result<InviteServerEvent, String> {
    let v = SCHEMA.parse(bytes)?;
    Ok(InviteServerEvent {
        created_at_ms: v.u64("created_at_ms")?,
        public_key: v.id("public_key")?,
        workspace_id: v.id("workspace_id")?,
        authority_event_id: v.id("authority_event_id")?,
    })
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
        assert!(decode(&wrong_type)
            .expect_err("wrong type must fail")
            .contains("expected"));

        let mut trailing = encode(&event());
        trailing.push(0);
        assert!(decode(&trailing)
            .expect_err("trailing bytes must fail")
            .contains("expected"));
    }
}

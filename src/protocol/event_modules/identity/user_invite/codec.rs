//! Codec for user-invite payloads.
//!
//! User-invite payloads are signed by `identity::signed` before admission. The
//! inner payload format is fixed-width:
//!
//! ```text
//! type(1) || created_at_ms(8) || public_key(32) || workspace_id(32) || authority_event_id(32)
//! ```

use crate::protocol::wire_schema::{Field, WireSchema};

use super::types::UserInviteEvent;

pub const TYPE_USER_INVITE: u8 = 10;

pub const SCHEMA: WireSchema = WireSchema::new(
    "user_invite",
    TYPE_USER_INVITE,
    &[
        Field::u64("created_at_ms"),
        Field::id("public_key"),
        Field::id("workspace_id"),
        Field::id("authority_event_id"),
    ],
);

pub const USER_INVITE_WIRE_SIZE: usize = SCHEMA.wire_size();

pub fn encode(event: &UserInviteEvent) -> Vec<u8> {
    SCHEMA
        .encoder()
        .u64(event.created_at_ms)
        .id(&event.public_key)
        .id(&event.workspace_id)
        .id(&event.authority_event_id)
        .finish()
}

pub fn decode(bytes: &[u8]) -> Result<UserInviteEvent, String> {
    let v = SCHEMA.parse(bytes)?;
    Ok(UserInviteEvent {
        created_at_ms: v.u64("created_at_ms")?,
        public_key: v.id("public_key")?,
        workspace_id: v.id("workspace_id")?,
        authority_event_id: v.id("authority_event_id")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> UserInviteEvent {
        UserInviteEvent {
            created_at_ms: 123,
            public_key: [1; 32],
            workspace_id: [2; 32],
            authority_event_id: [2; 32],
        }
    }

    #[test]
    fn roundtrips_fixed_width_user_invite_payload() {
        let encoded = encode(&event());

        assert_eq!(encoded.len(), USER_INVITE_WIRE_SIZE);
        assert_eq!(decode(&encoded).expect("decode user_invite"), event());
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

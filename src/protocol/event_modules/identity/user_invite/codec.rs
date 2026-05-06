//! Codec for user-invite payloads.
//!
//! User-invite payloads are signed by `identity::signed` before admission. The
//! inner payload format is fixed-width:
//!
//! ```text
//! type(1) || created_at_ms(8) || public_key(32) || workspace_id(32) || authority_event_id(32)
//! ```

use crate::protocol::wire::{Reader, Writer};

use super::types::UserInviteEvent;

pub const TYPE_USER_INVITE: u8 = 10;
pub const USER_INVITE_WIRE_SIZE: usize = 1 + 8 + 32 + 32 + 32;

pub fn encode(event: &UserInviteEvent) -> Vec<u8> {
    let mut out = Writer::with_capacity(USER_INVITE_WIRE_SIZE);
    out.u8(TYPE_USER_INVITE);
    out.u64(event.created_at_ms);
    out.id(&event.public_key);
    out.id(&event.workspace_id);
    out.id(&event.authority_event_id);
    out.finish()
}

pub fn decode(bytes: &[u8]) -> Result<UserInviteEvent, String> {
    let mut reader = Reader::new(bytes, "user_invite");
    let tag = reader.u8()?;
    if tag != TYPE_USER_INVITE {
        return Err("expected user_invite".to_string());
    }
    let event = UserInviteEvent {
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

    fn event() -> UserInviteEvent {
        UserInviteEvent {
            created_at_ms: 123,
            public_key: [1; 32],
            workspace_id: [2; 32],
            authority_event_id: [2; 32],
        }
    }

    // Invariant: roundtrips fixed width user invite payload.
    #[test]
    fn roundtrips_fixed_width_user_invite_payload() {
        let encoded = encode(&event());

        assert_eq!(encoded.len(), USER_INVITE_WIRE_SIZE);
        assert_eq!(decode(&encoded).expect("decode user_invite"), event());
    }

    // Invariant: rejects wrong type and trailing bytes.
    #[test]
    fn rejects_wrong_type_and_trailing_bytes() {
        let mut wrong_type = encode(&event());
        wrong_type[0] = 99;
        assert_eq!(
            decode(&wrong_type).expect_err("wrong type must fail"),
            "expected user_invite"
        );

        let mut trailing = encode(&event());
        trailing.push(0);
        assert!(decode(&trailing)
            .expect_err("trailing bytes must fail")
            .contains("trailing user_invite bytes"));
    }
}

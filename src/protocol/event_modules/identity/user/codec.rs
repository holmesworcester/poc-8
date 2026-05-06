//! Codec for user payloads.
//!
//! User payloads are signed by the user-invite key before admission:
//!
//! ```text
//! type(1) || created_at_ms(8) || workspace_id(32)
//! || public_key(32) || username_utf8_zero_padded(64)
//! ```

use crate::protocol::wire::{Reader, Writer};

use super::types::{UserEvent, USERNAME_BYTES};

pub const TYPE_USER: u8 = 14;
pub const USER_WIRE_SIZE: usize = 1 + 8 + 32 + 32 + USERNAME_BYTES;

pub fn encode(event: &UserEvent) -> Result<Vec<u8>, String> {
    let username = encode_username(&event.username)?;
    let mut out = Writer::with_capacity(USER_WIRE_SIZE);
    out.u8(TYPE_USER);
    out.u64(event.created_at_ms);
    out.id(&event.workspace_id);
    out.id(&event.public_key);
    out.raw(&username);
    Ok(out.finish())
}

pub fn decode(bytes: &[u8]) -> Result<UserEvent, String> {
    let mut reader = Reader::new(bytes, "user");
    let tag = reader.u8()?;
    if tag != TYPE_USER {
        return Err("expected user".to_string());
    }
    let created_at_ms = reader.u64()?;
    let workspace_id = reader.id()?;
    let public_key = reader.id()?;
    let username = decode_username(reader.slice(USERNAME_BYTES)?)?;
    reader.finish()?;
    Ok(UserEvent {
        created_at_ms,
        workspace_id,
        public_key,
        username,
    })
}

pub(crate) fn encode_username(username: &str) -> Result<[u8; USERNAME_BYTES], String> {
    let bytes = username.as_bytes();
    if bytes.len() > USERNAME_BYTES {
        return Err("username is too long".to_string());
    }
    if bytes.contains(&0) {
        return Err("username cannot contain NUL".to_string());
    }

    let mut out = [0; USERNAME_BYTES];
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(out)
}

pub(crate) fn decode_username(bytes: &[u8]) -> Result<String, String> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if bytes[end..].iter().any(|byte| *byte != 0) {
        return Err("username has non-canonical padding".to_string());
    }
    std::str::from_utf8(&bytes[..end])
        .map_err(|_| "username is not valid utf-8".to_string())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event() -> UserEvent {
        UserEvent {
            created_at_ms: 42,
            workspace_id: [2; 32],
            public_key: [7; 32],
            username: "alice".to_string(),
        }
    }

    // Invariant: roundtrips fixed width user payload.
    #[test]
    fn roundtrips_fixed_width_user_payload() {
        let encoded = encode(&event()).expect("encode user");

        assert_eq!(encoded.len(), USER_WIRE_SIZE);
        assert_eq!(decode(&encoded).expect("decode user"), event());
    }

    // Invariant: rejects trailing bytes.
    #[test]
    fn rejects_trailing_bytes() {
        let mut encoded = encode(&event()).expect("encode user");
        encoded.push(0);

        assert!(decode(&encoded)
            .expect_err("trailing bytes must fail")
            .contains("trailing user bytes"));
    }

    // Invariant: rejects non canonical username padding.
    #[test]
    fn rejects_non_canonical_username_padding() {
        let mut encoded = encode(&event()).expect("encode user");
        let username_start = 1 + 8 + 32 + 32;
        encoded[username_start + "alice".len() + 1] = b'x';

        assert_eq!(
            decode(&encoded).expect_err("bad padding must fail"),
            "username has non-canonical padding"
        );
    }

    // Invariant: rejects usernames that do not fit fixed slot.
    #[test]
    fn rejects_usernames_that_do_not_fit_fixed_slot() {
        let err = encode(&UserEvent {
            created_at_ms: 42,
            workspace_id: [2; 32],
            public_key: [7; 32],
            username: "a".repeat(USERNAME_BYTES + 1),
        })
        .expect_err("long username must fail");

        assert_eq!(err, "username is too long");
    }
}

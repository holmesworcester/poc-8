//! Codec for endpoint-shared inner events.
//!
//! Endpoint-shared payloads are fixed-width and are expected to be carried by a
//! signed envelope whose signer is the device invite authorizing the join:
//!
//! ```text
//! type(1) || created_at_ms(8) || workspace_id(32)
//! || user_authority_event_id(32) || endpoint_id(32)
//! || signing_public_key(32) || endpoint_role(1)
//! || device_name_utf8_zero_padded(64)
//! ```

use crate::protocol::event_modules::identity::endpoint::types::EndpointRole;
use crate::protocol::event_modules::types::{EventRecord, EventScope};
use crate::protocol::wire::{Reader, Writer};

use super::types::{EndpointSharedEvent, ENDPOINT_DEVICE_NAME_BYTES};

pub const TYPE_ENDPOINT_SHARED: u8 = 135;
pub const ENDPOINT_SHARED_WIRE_SIZE: usize =
    1 + 8 + 32 + 32 + 32 + 32 + 1 + ENDPOINT_DEVICE_NAME_BYTES;

pub fn encode(event: &EndpointSharedEvent) -> Result<Vec<u8>, String> {
    let device_name = encode_device_name(&event.device_name)?;
    let mut out = Writer::with_capacity(ENDPOINT_SHARED_WIRE_SIZE);
    out.u8(TYPE_ENDPOINT_SHARED);
    out.u64(event.created_at_ms);
    out.id(&event.workspace_id);
    out.id(&event.user_authority_event_id);
    out.id(&event.endpoint_id);
    out.id(&event.signing_public_key);
    out.u8(event.endpoint_role.as_u8());
    out.raw(&device_name);
    Ok(out.finish())
}

pub fn decode(bytes: &[u8]) -> Result<EndpointSharedEvent, String> {
    let mut reader = Reader::new(bytes, "endpoint shared");
    let tag = reader.u8()?;
    if tag != TYPE_ENDPOINT_SHARED {
        return Err("expected endpoint shared".to_string());
    }
    let created_at_ms = reader.u64()?;
    let workspace_id = reader.id()?;
    let user_authority_event_id = reader.id()?;
    let endpoint_id = reader.id()?;
    let signing_public_key = reader.id()?;
    let endpoint_role = EndpointRole::from_u8(reader.u8()?)?;
    let device_name = decode_device_name(reader.slice(ENDPOINT_DEVICE_NAME_BYTES)?)?;
    reader.finish()?;
    Ok(EndpointSharedEvent {
        created_at_ms,
        workspace_id,
        user_authority_event_id,
        endpoint_id,
        signing_public_key,
        endpoint_role,
        device_name,
    })
}

pub fn record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let event = decode(&bytes)?;
    Ok(EventRecord {
        timestamp: event.created_at_ms,
        body_len: ENDPOINT_SHARED_WIRE_SIZE - 1,
        canonical_bytes: bytes,
        dependencies: vec![event.workspace_id, event.user_authority_event_id],
        workspace_id: Some(event.workspace_id),
        scope: EventScope::Shared,
    })
}

pub(crate) fn encode_device_name(name: &str) -> Result<[u8; ENDPOINT_DEVICE_NAME_BYTES], String> {
    let bytes = name.as_bytes();
    if bytes.len() > ENDPOINT_DEVICE_NAME_BYTES {
        return Err("endpoint device name is too long".to_string());
    }
    if bytes.contains(&0) {
        return Err("endpoint device name cannot contain NUL".to_string());
    }

    let mut out = [0; ENDPOINT_DEVICE_NAME_BYTES];
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(out)
}

pub(crate) fn decode_device_name(bytes: &[u8]) -> Result<String, String> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if bytes[end..].iter().any(|byte| *byte != 0) {
        return Err("endpoint device name has non-canonical padding".to_string());
    }
    std::str::from_utf8(&bytes[..end])
        .map_err(|_| "endpoint device name is not valid utf-8".to_string())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::types::EventScope;

    use super::*;

    fn event() -> EndpointSharedEvent {
        EndpointSharedEvent {
            created_at_ms: 66,
            workspace_id: [1; 32],
            user_authority_event_id: [2; 32],
            endpoint_id: [3; 32],
            signing_public_key: [4; 32],
            endpoint_role: EndpointRole::Device,
            device_name: "laptop".to_string(),
        }
    }

    #[test]
    fn roundtrips_fixed_width_endpoint_shared_event() {
        let encoded = encode(&event()).expect("encode endpoint shared");

        assert_eq!(encoded.len(), ENDPOINT_SHARED_WIRE_SIZE);
        assert_eq!(decode(&encoded).expect("decode endpoint shared"), event());
    }

    #[test]
    fn rejects_bad_type_trailing_bytes_and_bad_name() {
        let mut encoded = encode(&event()).expect("encode endpoint shared");
        encoded[0] = 0xff;
        assert_eq!(
            decode(&encoded).expect_err("wrong type must fail"),
            "expected endpoint shared"
        );

        let mut encoded = encode(&event()).expect("encode endpoint shared");
        encoded.push(0);
        let err = decode(&encoded).expect_err("trailing byte must fail");
        assert!(err.starts_with("trailing "), "{err}");

        assert_eq!(
            encode(&EndpointSharedEvent {
                device_name: "bad\0name".to_string(),
                ..event()
            })
            .expect_err("NUL name must fail"),
            "endpoint device name cannot contain NUL"
        );
    }

    #[test]
    fn rejects_non_canonical_device_name_padding() {
        let mut encoded = encode(&event()).expect("encode endpoint shared");
        let name_start = 1 + 8 + 32 + 32 + 32 + 32;
        let name_start = name_start + 1;
        encoded[name_start + "laptop".len() + 1] = b'x';

        assert_eq!(
            decode(&encoded).expect_err("padding must fail"),
            "endpoint device name has non-canonical padding"
        );
    }

    #[test]
    fn raw_record_shape_is_shared_with_workspace_and_user_dependencies() {
        let encoded = encode(&event()).expect("encode endpoint shared");
        let record = record_from_bytes(encoded.clone()).expect("record");

        assert_eq!(record.timestamp, 66);
        assert_eq!(record.body_len, ENDPOINT_SHARED_WIRE_SIZE - 1);
        assert_eq!(record.canonical_bytes, encoded);
        assert_eq!(record.dependencies, vec![[1; 32], [2; 32]]);
        assert_eq!(record.scope, EventScope::Shared);
    }
}

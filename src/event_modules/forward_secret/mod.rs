//! Forward-secret encryption facts as canonical events.
//!
//! This module keeps the first poc-8 port deliberately narrow: one fixed-wire
//! event family carries the forward-secret facts, and the projector expands
//! them into queryable tables. Authoring-side CLI commands then run bounded,
//! deterministic maintenance (`fs expand`) by emitting more canonical facts.

pub mod codec;
pub mod projector;

pub use codec::{
    encode_forward_secret, parse_forward_secret, ForwardSecretEvent, FORWARD_SECRET_FIELDS,
    FORWARD_SECRET_META, FORWARD_SECRET_PAYLOAD_BYTES, FORWARD_SECRET_WIRE_SIZE,
    KIND_DEVICE_PUBKEY, KIND_HISTORY_DELETE, KIND_KEY_EPOCH, KIND_KEY_WRAP, KIND_KEY_WRAP_RECEIPT,
    KIND_MESSAGE_ENCRYPTED, KIND_RECIPIENT_CREATED, RECIPIENT_DEVICE, RECIPIENT_INVITE,
};
pub use projector::{ensure_schema, project_pure};

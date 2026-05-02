use super::super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{EventError, ParsedEvent, EVENT_TYPE_FORWARD_SECRET};

pub const FORWARD_SECRET_PAYLOAD_BYTES: usize = 256;

pub const KIND_RECIPIENT_CREATED: u8 = 1;
pub const KIND_DEVICE_PUBKEY: u8 = 2;
pub const KIND_KEY_EPOCH: u8 = 3;
pub const KIND_KEY_WRAP: u8 = 4;
pub const KIND_KEY_WRAP_RECEIPT: u8 = 5;
pub const KIND_MESSAGE_ENCRYPTED: u8 = 7;
pub const KIND_HISTORY_DELETE: u8 = 8;

pub const RECIPIENT_DEVICE: u8 = 1;
pub const RECIPIENT_INVITE: u8 = 2;

pub const FORWARD_SECRET_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("workspace_id"),
    FieldSpec::U8("kind"),
    FieldSpec::EventId("subject_id"),
    FieldSpec::EventId("aux_id_1"),
    FieldSpec::EventId("aux_id_2"),
    FieldSpec::EventId("coord_event_id"),
    FieldSpec::EventId("node_bytes"),
    FieldSpec::EventId("data_1"),
    FieldSpec::EventId("data_2"),
    FieldSpec::U64("scalar_1"),
    FieldSpec::U32("scalar_2"),
    FieldSpec::U8("small_1"),
    FieldSpec::U32("payload_len"),
    FieldSpec::FixedBytes("payload", FORWARD_SECRET_PAYLOAD_BYTES),
];

pub const FORWARD_SECRET_WIRE_SIZE: usize = wire_size_for_fields(FORWARD_SECRET_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardSecretEvent {
    pub created_at_ms: u64,
    pub workspace_id: [u8; 32],
    /// Variant discriminator. See `KIND_*` constants above.
    pub kind: u8,
    /// Variant primary id:
    /// recipient_id, epoch_id, pubkey_id, or invite_recipient_id.
    pub subject_id: [u8; 32],
    /// Variant secondary id:
    /// prev_pubkey_id, pubkey_id, prev_epoch_id, or wrap_id.
    pub aux_id_1: [u8; 32],
    /// Variant tertiary id:
    /// removed_recipient_id or wrap_id.
    pub aux_id_2: [u8; 32],
    /// History coordinate event id for encrypted-message/delete facts.
    pub coord_event_id: [u8; 32],
    /// History-tree node prefix bytes for wrap/receipt facts.
    pub node_bytes: [u8; 32],
    /// Variant payload commitment or hash:
    /// public_key, root_commitment, secret_commitment, or ciphertext hash.
    pub data_1: [u8; 32],
    /// Variant second payload hash, typically wrap ciphertext hash.
    pub data_2: [u8; 32],
    /// Variant scalar: unix minute for history coordinates.
    pub scalar_1: u64,
    /// Variant scalar: node prefix bit length.
    pub scalar_2: u32,
    /// Variant small enum: recipient kind.
    pub small_1: u8,
    /// Length of `payload` in bytes.
    pub payload_len: u32,
    /// Real encrypted payload bytes for key-wrap and encrypted-message facts.
    pub payload: Vec<u8>,
}

impl ForwardSecretEvent {
    pub fn recipient_created(
        created_at_ms: u64,
        workspace_id: [u8; 32],
        recipient_id: [u8; 32],
        recipient_kind: u8,
    ) -> Self {
        Self {
            created_at_ms,
            workspace_id,
            kind: KIND_RECIPIENT_CREATED,
            subject_id: recipient_id,
            small_1: recipient_kind,
            ..Self::blank()
        }
    }

    pub fn device_pubkey(
        created_at_ms: u64,
        workspace_id: [u8; 32],
        recipient_id: [u8; 32],
        prev_pubkey_id: [u8; 32],
        public_key: [u8; 32],
    ) -> Self {
        Self {
            created_at_ms,
            workspace_id,
            kind: KIND_DEVICE_PUBKEY,
            subject_id: recipient_id,
            aux_id_1: prev_pubkey_id,
            data_1: public_key,
            ..Self::blank()
        }
    }

    pub fn key_epoch(
        created_at_ms: u64,
        workspace_id: [u8; 32],
        prev_epoch_id: [u8; 32],
        removed_recipient_id: [u8; 32],
        root_commitment: [u8; 32],
    ) -> Self {
        Self {
            created_at_ms,
            workspace_id,
            kind: KIND_KEY_EPOCH,
            aux_id_1: prev_epoch_id,
            aux_id_2: removed_recipient_id,
            data_1: root_commitment,
            ..Self::blank()
        }
    }

    pub fn key_wrap(
        created_at_ms: u64,
        workspace_id: [u8; 32],
        epoch_id: [u8; 32],
        pubkey_id: [u8; 32],
        node_bytes: [u8; 32],
        node_bit_len: u32,
        secret_commitment: [u8; 32],
        ciphertext_hash: [u8; 32],
        ciphertext: Vec<u8>,
    ) -> Self {
        let payload_len = ciphertext.len() as u32;
        Self {
            created_at_ms,
            workspace_id,
            kind: KIND_KEY_WRAP,
            subject_id: epoch_id,
            aux_id_1: pubkey_id,
            node_bytes,
            data_1: secret_commitment,
            data_2: ciphertext_hash,
            scalar_2: node_bit_len,
            payload_len,
            payload: ciphertext,
            ..Self::blank()
        }
    }

    pub fn key_wrap_receipt(
        created_at_ms: u64,
        workspace_id: [u8; 32],
        epoch_id: [u8; 32],
        pubkey_id: [u8; 32],
        wrap_id: [u8; 32],
        node_bytes: [u8; 32],
        node_bit_len: u32,
    ) -> Self {
        Self {
            created_at_ms,
            workspace_id,
            kind: KIND_KEY_WRAP_RECEIPT,
            subject_id: epoch_id,
            aux_id_1: pubkey_id,
            aux_id_2: wrap_id,
            node_bytes,
            scalar_2: node_bit_len,
            ..Self::blank()
        }
    }

    pub fn message_encrypted(
        created_at_ms: u64,
        workspace_id: [u8; 32],
        epoch_id: [u8; 32],
        unix_minute: u64,
        coord_event_id: [u8; 32],
        ciphertext_hash: [u8; 32],
        ciphertext: Vec<u8>,
    ) -> Self {
        let payload_len = ciphertext.len() as u32;
        Self {
            created_at_ms,
            workspace_id,
            kind: KIND_MESSAGE_ENCRYPTED,
            subject_id: epoch_id,
            coord_event_id,
            data_1: ciphertext_hash,
            scalar_1: unix_minute,
            payload_len,
            payload: ciphertext,
            ..Self::blank()
        }
    }

    pub fn history_delete(
        created_at_ms: u64,
        workspace_id: [u8; 32],
        epoch_id: [u8; 32],
        unix_minute: u64,
        coord_event_id: [u8; 32],
    ) -> Self {
        Self {
            created_at_ms,
            workspace_id,
            kind: KIND_HISTORY_DELETE,
            subject_id: epoch_id,
            coord_event_id,
            scalar_1: unix_minute,
            ..Self::blank()
        }
    }

    fn blank() -> Self {
        Self {
            created_at_ms: 0,
            workspace_id: [0; 32],
            kind: 0,
            subject_id: [0; 32],
            aux_id_1: [0; 32],
            aux_id_2: [0; 32],
            coord_event_id: [0; 32],
            node_bytes: [0; 32],
            data_1: [0; 32],
            data_2: [0; 32],
            scalar_1: 0,
            scalar_2: 0,
            small_1: 0,
            payload_len: 0,
            payload: Vec::new(),
        }
    }
}

impl super::super::Describe for ForwardSecretEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("kind", kind_name(self.kind).to_string()),
            ("subject", super::super::short_id_b64(&self.subject_id)),
            ("aux_1", super::super::short_id_b64(&self.aux_id_1)),
        ]
    }
}

pub fn kind_name(kind: u8) -> &'static str {
    match kind {
        KIND_RECIPIENT_CREATED => "recipient_created",
        KIND_DEVICE_PUBKEY => "device_pubkey",
        KIND_KEY_EPOCH => "key_epoch",
        KIND_KEY_WRAP => "key_wrap",
        KIND_KEY_WRAP_RECEIPT => "key_wrap_receipt",
        KIND_MESSAGE_ENCRYPTED => "message_encrypted",
        KIND_HISTORY_DELETE => "history_delete",
        _ => "unknown",
    }
}

pub fn parse_forward_secret(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_FORWARD_SECRET, FORWARD_SECRET_FIELDS, blob)?;
    let payload_len = values[13].as_u32().unwrap() as usize;
    if payload_len > FORWARD_SECRET_PAYLOAD_BYTES {
        return Err(EventError::ContentTooLong(payload_len));
    }
    let payload_slot = values[14].as_fixed_bytes().unwrap();
    Ok(ParsedEvent::ForwardSecret(ForwardSecretEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        workspace_id: values[1].as_event_id().unwrap(),
        kind: values[2].as_u8().unwrap(),
        subject_id: values[3].as_event_id().unwrap(),
        aux_id_1: values[4].as_event_id().unwrap(),
        aux_id_2: values[5].as_event_id().unwrap(),
        coord_event_id: values[6].as_event_id().unwrap(),
        node_bytes: values[7].as_event_id().unwrap(),
        data_1: values[8].as_event_id().unwrap(),
        data_2: values[9].as_event_id().unwrap(),
        scalar_1: values[10].as_u64().unwrap(),
        scalar_2: values[11].as_u32().unwrap(),
        small_1: values[12].as_u8().unwrap(),
        payload_len: payload_len as u32,
        payload: payload_slot[..payload_len].to_vec(),
    }))
}

pub fn encode_forward_secret(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let event = match event {
        ParsedEvent::ForwardSecret(event) => event,
        _ => return Err(EventError::WrongVariant),
    };
    if event.payload.len() > FORWARD_SECRET_PAYLOAD_BYTES {
        return Err(EventError::ContentTooLong(event.payload.len()));
    }
    let mut payload = vec![0u8; FORWARD_SECRET_PAYLOAD_BYTES];
    payload[..event.payload.len()].copy_from_slice(&event.payload);
    let values = vec![
        FieldValue::Timestamp(event.created_at_ms),
        FieldValue::EventId(event.workspace_id),
        FieldValue::U8(event.kind),
        FieldValue::EventId(event.subject_id),
        FieldValue::EventId(event.aux_id_1),
        FieldValue::EventId(event.aux_id_2),
        FieldValue::EventId(event.coord_event_id),
        FieldValue::EventId(event.node_bytes),
        FieldValue::EventId(event.data_1),
        FieldValue::EventId(event.data_2),
        FieldValue::U64(event.scalar_1),
        FieldValue::U32(event.scalar_2),
        FieldValue::U8(event.small_1),
        FieldValue::U32(event.payload.len() as u32),
        FieldValue::FixedBytes(payload),
    ];
    Ok(encode_fields(
        EVENT_TYPE_FORWARD_SECRET,
        FORWARD_SECRET_FIELDS,
        &values,
    )?)
}

pub static FORWARD_SECRET_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_FORWARD_SECRET,
    type_name: "forward_secret",
    projection_table: "fs_events",
    share_scope: ShareScope::Shared,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_forward_secret,
    encode: encode_forward_secret,
    projector: super::projector::project_pure,
    ensure_schema: Some(super::ensure_schema),
};

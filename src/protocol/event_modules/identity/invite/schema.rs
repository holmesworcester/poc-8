//! Schema for local invite-secret rows.
//!
//! The table is intentionally private to the invite module: it records local
//! authority to accept future bootstrap requests, not shared membership state.

use crate::core::store::{Schema, TableName};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::wire::{Reader, Writer};

pub const INVITE_SECRETS: TableName = TableName::new("identity.invite_secrets");

pub const SCHEMAS: &[Schema] = &[Schema::durable_row_table(
    "identity.invite_secrets.v1",
    INVITE_SECRETS,
)];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteSecretRow {
    pub bootstrap_secret: [u8; 32],
    pub workspace_id: Option<EventId>,
    pub invite_event_id: Option<EventId>,
}

pub fn encode_invite_secret_row(
    bootstrap_secret: [u8; 32],
    workspace_id: Option<EventId>,
    invite_event_id: Option<EventId>,
) -> Vec<u8> {
    let mut out = Writer::with_capacity(32 + 32 + 32);
    out.id(&bootstrap_secret);
    out.id(&workspace_id.unwrap_or([0; 32]));
    out.id(&invite_event_id.unwrap_or([0; 32]));
    out.finish()
}

pub fn decode_invite_secret_row(value: &[u8]) -> Result<InviteSecretRow, String> {
    if value.len() == 32 {
        let mut bootstrap_secret = [0; 32];
        bootstrap_secret.copy_from_slice(value);
        return Ok(InviteSecretRow {
            bootstrap_secret,
            workspace_id: None,
            invite_event_id: None,
        });
    }

    let mut reader = Reader::new(value, "invite secret row");
    let row = InviteSecretRow {
        bootstrap_secret: reader.id()?,
        workspace_id: optional_id(reader.id()?),
        invite_event_id: optional_id(reader.id()?),
    };
    reader.finish()?;
    if row.workspace_id.is_some() != row.invite_event_id.is_some() {
        return Err("invite secret row scope is incomplete".to_string());
    }
    Ok(row)
}

fn optional_id(id: EventId) -> Option<EventId> {
    if id.iter().all(|byte| *byte == 0) {
        None
    } else {
        Some(id)
    }
}

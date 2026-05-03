use crate::wire::{Reader, Writer};

use super::types::CompareEvent;

pub const TAG: u8 = 1;

pub fn encode(event: &CompareEvent, out: &mut Writer) {
    out.u8(TAG);
    out.id(&event.connection_id);
    out.u8(u8::from(event.sender_is_initiator));
    out.sized_bytes(&event.message);
}

pub fn decode(reader: &mut Reader<'_>) -> Result<CompareEvent, String> {
    let connection_id = reader.id()?;
    let sender_is_initiator = match reader.u8()? {
        0 => false,
        1 => true,
        other => return Err(format!("invalid sync compare role {other}")),
    };
    Ok(CompareEvent {
        connection_id,
        sender_is_initiator,
        message: reader.sized_bytes()?,
    })
}

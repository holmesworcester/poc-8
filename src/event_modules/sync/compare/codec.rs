use crate::wire::{Reader, Writer};

use super::types::CompareEvent;

pub const TAG: u8 = 1;

pub fn encode(event: &CompareEvent, out: &mut Writer) {
    out.u8(TAG);
    out.id(&event.connection_id);
    out.sized_bytes(&event.message);
}

pub fn decode(reader: &mut Reader<'_>) -> Result<CompareEvent, String> {
    Ok(CompareEvent {
        connection_id: reader.id()?,
        message: reader.sized_bytes()?,
    })
}

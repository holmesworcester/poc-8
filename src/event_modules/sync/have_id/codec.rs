use crate::wire::{Reader, Writer};

use super::types::HaveIdEvent;

pub const TAG: u8 = 2;

pub fn encode(event: &HaveIdEvent, out: &mut Writer) {
    out.u8(TAG);
    out.id(&event.connection_id);
    out.id(&event.id);
}

pub fn decode(reader: &mut Reader<'_>) -> Result<HaveIdEvent, String> {
    Ok(HaveIdEvent {
        connection_id: reader.id()?,
        id: reader.id()?,
    })
}

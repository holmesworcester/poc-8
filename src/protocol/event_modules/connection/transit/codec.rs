//! Transit envelope codec.
//!
//! Transit bytes are not canonical events and do not have event ids. They are
//! encrypted envelopes around canonical inner bytes, used only at the connection
//! boundary. The associated-data helpers intentionally encode every routing
//! field covered by authentication, so unwrap can reject frames whose plaintext
//! was copied under a different endpoint or connection.

use crate::protocol::wire::{Reader, Writer};

use super::types::{TransitEnvelope, TransitNonce};

const MAGIC: &[u8; 10] = b"TOPOTRANS1";
const INNER_EVENTS_MAGIC: &[u8; 10] = b"TOPOINNER1";
const TAG_BOOTSTRAP: u8 = 1;
const TAG_CONNECTION: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransitEnvelopeRef<'a> {
    Bootstrap {
        sender_endpoint: [u8; 32],
        recipient_endpoint: [u8; 32],
        nonce: TransitNonce,
        ciphertext: &'a [u8],
    },
    Connection {
        connection_id: [u8; 32],
        sender_endpoint: [u8; 32],
        recipient_endpoint: [u8; 32],
        nonce: TransitNonce,
        ciphertext: &'a [u8],
    },
}

pub fn associated_data(envelope: &TransitEnvelope) -> Vec<u8> {
    match envelope {
        TransitEnvelope::Bootstrap {
            sender_endpoint,
            recipient_endpoint,
            nonce,
            ciphertext: _,
        } => associated_data_bootstrap(sender_endpoint, recipient_endpoint, nonce),
        TransitEnvelope::Connection {
            connection_id,
            sender_endpoint,
            recipient_endpoint,
            nonce,
            ciphertext: _,
        } => associated_data_connection(connection_id, sender_endpoint, recipient_endpoint, nonce),
    }
}

/// Encode the bytes that are authenticated but not encrypted.
///
/// Keep this in lockstep with `encode`: if a field affects routing or envelope
/// identity, it must be present here as well.
pub fn associated_data_bootstrap(
    sender_endpoint: &[u8; 32],
    recipient_endpoint: &[u8; 32],
    nonce: &TransitNonce,
) -> Vec<u8> {
    let mut out = Writer::with_capacity(MAGIC.len() + 1 + 32 + 32 + 24);
    out.raw(MAGIC);
    out.u8(TAG_BOOTSTRAP);
    out.id(sender_endpoint);
    out.id(recipient_endpoint);
    out.raw(nonce);
    out.finish()
}

pub fn associated_data_connection(
    connection_id: &[u8; 32],
    sender_endpoint: &[u8; 32],
    recipient_endpoint: &[u8; 32],
    nonce: &TransitNonce,
) -> Vec<u8> {
    let mut out = Writer::with_capacity(MAGIC.len() + 1 + 32 + 32 + 32 + 24);
    out.raw(MAGIC);
    out.u8(TAG_CONNECTION);
    out.id(connection_id);
    out.id(sender_endpoint);
    out.id(recipient_endpoint);
    out.raw(nonce);
    out.finish()
}

pub fn encode(envelope: &TransitEnvelope) -> Vec<u8> {
    let mut out = Writer::new();
    out.raw(MAGIC);
    match envelope {
        TransitEnvelope::Bootstrap {
            sender_endpoint,
            recipient_endpoint,
            nonce,
            ciphertext,
        } => {
            out.u8(TAG_BOOTSTRAP);
            out.id(sender_endpoint);
            out.id(recipient_endpoint);
            out.raw(nonce);
            out.sized_bytes(ciphertext);
        }
        TransitEnvelope::Connection {
            connection_id,
            sender_endpoint,
            recipient_endpoint,
            nonce,
            ciphertext,
        } => {
            out.u8(TAG_CONNECTION);
            out.id(connection_id);
            out.id(sender_endpoint);
            out.id(recipient_endpoint);
            out.raw(nonce);
            out.sized_bytes(ciphertext);
        }
    }
    out.finish()
}

pub fn encode_inner_events(inners: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    let count = inners.len();
    if count > u32::MAX as usize {
        return Err("too many inner events in transit".to_string());
    }
    let mut out = Writer::new();
    out.raw(INNER_EVENTS_MAGIC);
    out.u32(count);
    for inner in inners {
        out.sized_bytes(inner);
    }
    Ok(out.finish())
}

pub fn decode_inner_events(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if !bytes.starts_with(INNER_EVENTS_MAGIC) {
        return Err("not a transit inner-event batch".to_string());
    }
    let mut reader = Reader::new(&bytes[INNER_EVENTS_MAGIC.len()..], "transit inner events");
    let count = reader.u32()? as usize;
    let mut inners = Vec::with_capacity(count);
    for _ in 0..count {
        inners.push(reader.sized_slice()?.to_vec());
    }
    reader.finish()?;
    Ok(inners)
}

pub fn decode(bytes: &[u8]) -> Result<TransitEnvelope, String> {
    Ok(match decode_ref(bytes)? {
        TransitEnvelopeRef::Bootstrap {
            sender_endpoint,
            recipient_endpoint,
            nonce,
            ciphertext,
        } => TransitEnvelope::Bootstrap {
            sender_endpoint,
            recipient_endpoint,
            nonce,
            ciphertext: ciphertext.to_vec(),
        },
        TransitEnvelopeRef::Connection {
            connection_id,
            sender_endpoint,
            recipient_endpoint,
            nonce,
            ciphertext,
        } => TransitEnvelope::Connection {
            connection_id,
            sender_endpoint,
            recipient_endpoint,
            nonce,
            ciphertext: ciphertext.to_vec(),
        },
    })
}

pub(crate) fn decode_ref(bytes: &[u8]) -> Result<TransitEnvelopeRef<'_>, String> {
    // Borrow the ciphertext slice during decoding so unwrap can decrypt without
    // first allocating a second copy.
    if !bytes.starts_with(MAGIC) {
        return Err("not a transit envelope".to_string());
    }
    let mut reader = Reader::new(&bytes[MAGIC.len()..], "transit envelope");
    let envelope = match reader.u8()? {
        TAG_BOOTSTRAP => TransitEnvelopeRef::Bootstrap {
            sender_endpoint: reader.id()?,
            recipient_endpoint: reader.id()?,
            nonce: nonce24(&mut reader)?,
            ciphertext: reader.sized_slice()?,
        },
        TAG_CONNECTION => TransitEnvelopeRef::Connection {
            connection_id: reader.id()?,
            sender_endpoint: reader.id()?,
            recipient_endpoint: reader.id()?,
            nonce: nonce24(&mut reader)?,
            ciphertext: reader.sized_slice()?,
        },
        other => return Err(format!("unknown transit envelope tag {other}")),
    };
    reader.finish()?;
    Ok(envelope)
}

fn nonce24(reader: &mut Reader<'_>) -> Result<TransitNonce, String> {
    let bytes = reader.slice(24)?;
    let mut nonce = [0; 24];
    nonce.copy_from_slice(bytes);
    Ok(nonce)
}

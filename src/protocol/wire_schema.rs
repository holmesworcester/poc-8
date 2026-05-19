//! Schema-driven wire format for events.
//!
//! Each event declares its tag and an ordered list of fixed-size fields.
//! Encode, decode, and dispatch all derive from that. The wire format drops
//! the length prefixes that were there because layouts weren't declared.
//!
//! That's the whole language. There is no envelope abstraction, no AAD layout,
//! no scope/timestamp/dep grammar — those things stay as ordinary per-event
//! code, kept short by the schema-derived field accessors.
//!
//! Variable-size payloads (e.g. the BAO proof in `file_slice`) are declared
//! as two ordinary fields: a `u32` length next to a `bytes(MAX)` slot. The
//! per-event decode validates `len <= MAX` and that the trailer is zero.
//!
//! Signed events have signer/signature fields declared directly in the
//! schema, in their wire-order positions. There is no separate envelope
//! type — a signed event is just an event whose layout includes those fields.

use crate::protocol::event_modules::types::EventId;

/// Static description of an event's wire layout.
pub struct WireSchema {
    pub tag: u8,
    pub label: &'static str,
    pub fields: &'static [Field],
}

#[derive(Clone, Copy)]
pub struct Field {
    pub name: &'static str,
    pub size: usize,
}

impl Field {
    pub const fn id(name: &'static str) -> Self {
        Self { name, size: 32 }
    }
    pub const fn u8(name: &'static str) -> Self {
        Self { name, size: 1 }
    }
    pub const fn u16(name: &'static str) -> Self {
        Self { name, size: 2 }
    }
    pub const fn u32(name: &'static str) -> Self {
        Self { name, size: 4 }
    }
    pub const fn u64(name: &'static str) -> Self {
        Self { name, size: 8 }
    }
    pub const fn bytes(name: &'static str, n: usize) -> Self {
        Self { name, size: n }
    }
}

impl WireSchema {
    pub const fn new(label: &'static str, tag: u8, fields: &'static [Field]) -> Self {
        Self { tag, label, fields }
    }

    /// Total bytes on the wire: tag + sum of field sizes.
    pub const fn wire_size(&self) -> usize {
        let mut total: usize = 1;
        let mut i = 0;
        while i < self.fields.len() {
            total += self.fields[i].size;
            i += 1;
        }
        total
    }

    /// Begin building the canonical bytes for an event of this schema.
    pub fn encoder(&'static self) -> WireEncoder {
        let mut out = Vec::with_capacity(self.wire_size());
        out.push(self.tag);
        WireEncoder {
            schema: self,
            out,
            field_index: 0,
        }
    }

    /// Verify the bytes look like an event of this schema and return a borrowed
    /// view that supports field-by-name access.
    ///
    /// Tag is checked first so callers can distinguish "wrong event type"
    /// (different tag) from "malformed event of the expected type" (wrong
    /// length) without parsing the rest of the bytes.
    pub fn parse<'a>(&'static self, bytes: &'a [u8]) -> Result<Parsed<'a>, String> {
        if bytes.is_empty() || bytes[0] != self.tag {
            return Err(format!("expected {}", self.label));
        }
        let expected = self.wire_size();
        if bytes.len() != expected {
            return Err(format!(
                "{}: expected {} bytes, got {}",
                self.label,
                expected,
                bytes.len()
            ));
        }
        Ok(Parsed {
            schema: self,
            bytes,
        })
    }
}

pub struct WireEncoder {
    schema: &'static WireSchema,
    out: Vec<u8>,
    field_index: usize,
}

impl WireEncoder {
    fn consume(&mut self, expected_size: usize) {
        let field = self.schema.fields.get(self.field_index).unwrap_or_else(|| {
            panic!(
                "{}: encoder wrote past end of field list",
                self.schema.label
            )
        });
        assert_eq!(
            field.size, expected_size,
            "{}: field {} expected size {}, encoder gave {}",
            self.schema.label, field.name, field.size, expected_size
        );
        self.field_index += 1;
    }

    pub fn u8(mut self, value: u8) -> Self {
        self.consume(1);
        self.out.push(value);
        self
    }
    pub fn u16(mut self, value: u16) -> Self {
        self.consume(2);
        self.out.extend_from_slice(&value.to_be_bytes());
        self
    }
    pub fn u32(mut self, value: u32) -> Self {
        self.consume(4);
        self.out.extend_from_slice(&value.to_be_bytes());
        self
    }
    pub fn u64(mut self, value: u64) -> Self {
        self.consume(8);
        self.out.extend_from_slice(&value.to_be_bytes());
        self
    }
    pub fn id(mut self, value: &[u8; 32]) -> Self {
        self.consume(32);
        self.out.extend_from_slice(value);
        self
    }
    pub fn bytes(mut self, value: &[u8]) -> Self {
        self.consume(value.len());
        self.out.extend_from_slice(value);
        self
    }

    pub fn finish(self) -> Vec<u8> {
        assert_eq!(
            self.field_index,
            self.schema.fields.len(),
            "{}: encoder finished early ({} of {} fields)",
            self.schema.label,
            self.field_index,
            self.schema.fields.len()
        );
        self.out
    }

    /// Finish an intentionally truncated prefix of the schema.
    ///
    /// Signed events use this for the bytes covered by the signature: the
    /// signed prefix is the complete schema except the final signature field.
    /// Keeping this operation on `WireEncoder` means the prefix still has to
    /// write fields in the declared order and with the declared sizes.
    pub fn finish_without_trailing_fields(self, trailing_fields: usize) -> Vec<u8> {
        assert_eq!(
            self.field_index + trailing_fields,
            self.schema.fields.len(),
            "{}: encoder finished at field {}, expected {} trailing fields out of {}",
            self.schema.label,
            self.field_index,
            trailing_fields,
            self.schema.fields.len()
        );
        self.out
    }
}

/// Borrowed view of a parsed event's bytes.
pub struct Parsed<'a> {
    schema: &'static WireSchema,
    bytes: &'a [u8],
}

impl<'a> Parsed<'a> {
    pub fn canonical_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    fn locate(&self, name: &str) -> Result<(&Field, usize), String> {
        let mut offset: usize = 1; // skip tag byte
        for field in self.schema.fields {
            if field.name == name {
                return Ok((field, offset));
            }
            offset += field.size;
        }
        Err(format!("{}: no field named {}", self.schema.label, name))
    }

    pub fn raw(&self, name: &str) -> Result<&'a [u8], String> {
        let (field, offset) = self.locate(name)?;
        Ok(&self.bytes[offset..offset + field.size])
    }

    pub fn u8(&self, name: &str) -> Result<u8, String> {
        let raw = self.raw(name)?;
        if raw.len() != 1 {
            return Err(format!("{}: field {} not u8", self.schema.label, name));
        }
        Ok(raw[0])
    }

    pub fn u16(&self, name: &str) -> Result<u16, String> {
        let raw = self.raw(name)?;
        let bytes: [u8; 2] = raw
            .try_into()
            .map_err(|_| format!("{}: field {} not u16", self.schema.label, name))?;
        Ok(u16::from_be_bytes(bytes))
    }

    pub fn u32(&self, name: &str) -> Result<u32, String> {
        let raw = self.raw(name)?;
        let bytes: [u8; 4] = raw
            .try_into()
            .map_err(|_| format!("{}: field {} not u32", self.schema.label, name))?;
        Ok(u32::from_be_bytes(bytes))
    }

    pub fn u64(&self, name: &str) -> Result<u64, String> {
        let raw = self.raw(name)?;
        let bytes: [u8; 8] = raw
            .try_into()
            .map_err(|_| format!("{}: field {} not u64", self.schema.label, name))?;
        Ok(u64::from_be_bytes(bytes))
    }

    pub fn id(&self, name: &str) -> Result<EventId, String> {
        let raw = self.raw(name)?;
        raw.try_into()
            .map_err(|_| format!("{}: field {} not 32 bytes", self.schema.label, name))
    }
}

//! Shared fixed-field wire helpers for protocol codecs.
//!
//! Event modules own their event formats, but they should not each invent a
//! byte reader. This file gives them a small, explicit vocabulary for big-endian
//! integers, fixed ids, raw bytes, and length-prefixed byte slices. A codec is
//! still responsible for its tags, field order, and invariants; the helper only
//! makes truncation and trailing data checks uniform.
//!
//! Keep this layer intentionally plain. It is not a schema language and it does
//! not know which event type it is reading. The useful discipline is that every
//! decoder consumes exactly the bytes it claims by calling `finish`.

pub struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    /// Start a new byte writer with no implied type tag or header.
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    pub fn raw(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    pub fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub fn u32(&mut self, value: usize) {
        let value = u32::try_from(value).expect("value too large for wire u32");
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub fn id(&mut self, value: &[u8; 32]) {
        self.bytes.extend_from_slice(value);
    }

    pub fn sized_bytes(&mut self, bytes: &[u8]) {
        self.u32(bytes.len());
        self.raw(bytes);
    }

    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Reader<'a> {
    rest: &'a [u8],
    label: &'static str,
}

impl<'a> Reader<'a> {
    /// Read from a codec-owned byte slice.
    ///
    /// `label` is only for errors. It should name the event or nested item
    /// being decoded so malformed bytes are diagnosable without teaching the
    /// reader any protocol vocabulary.
    pub fn new(bytes: &'a [u8], label: &'static str) -> Self {
        Self { rest: bytes, label }
    }

    pub fn u8(&mut self) -> Result<u8, String> {
        if self.rest.is_empty() {
            return Err(format!("truncated {}", self.label));
        }
        let value = self.rest[0];
        self.rest = &self.rest[1..];
        Ok(value)
    }

    pub fn u32(&mut self) -> Result<u32, String> {
        if self.rest.len() < 4 {
            return Err(format!("truncated {}", self.label));
        }
        let mut bytes = [0; 4];
        bytes.copy_from_slice(&self.rest[..4]);
        self.rest = &self.rest[4..];
        Ok(u32::from_be_bytes(bytes))
    }

    pub fn u16(&mut self) -> Result<u16, String> {
        if self.rest.len() < 2 {
            return Err(format!("truncated {}", self.label));
        }
        let mut bytes = [0; 2];
        bytes.copy_from_slice(&self.rest[..2]);
        self.rest = &self.rest[2..];
        Ok(u16::from_be_bytes(bytes))
    }

    pub fn u64(&mut self) -> Result<u64, String> {
        if self.rest.len() < 8 {
            return Err(format!("truncated {}", self.label));
        }
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&self.rest[..8]);
        self.rest = &self.rest[8..];
        Ok(u64::from_be_bytes(bytes))
    }

    pub fn id(&mut self) -> Result<[u8; 32], String> {
        if self.rest.len() < 32 {
            return Err(format!("truncated {}", self.label));
        }
        let mut id = [0; 32];
        id.copy_from_slice(&self.rest[..32]);
        self.rest = &self.rest[32..];
        Ok(id)
    }

    pub fn bytes(&mut self, len: usize) -> Result<Vec<u8>, String> {
        Ok(self.slice(len)?.to_vec())
    }

    pub fn slice(&mut self, len: usize) -> Result<&'a [u8], String> {
        if self.rest.len() < len {
            return Err(format!("truncated {}", self.label));
        }
        let (head, tail) = self.rest.split_at(len);
        self.rest = tail;
        Ok(head)
    }

    pub fn sized_bytes(&mut self) -> Result<Vec<u8>, String> {
        let len = self.u32()? as usize;
        self.bytes(len)
    }

    pub fn sized_slice(&mut self) -> Result<&'a [u8], String> {
        let len = self.u32()? as usize;
        self.slice(len)
    }

    pub fn finish(&self) -> Result<(), String> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(format!("trailing {} bytes", self.label))
        }
    }

    /// Return whatever bytes remain in the reader and advance to the end.
    /// Used by codecs whose trailing field is "rest of frame" — typically the
    /// transit envelope's ciphertext, where the outer transport layer supplies
    /// the frame boundary so no inner length prefix is needed.
    pub fn rest(&mut self) -> &'a [u8] {
        let out = self.rest;
        self.rest = &[];
        out
    }
}

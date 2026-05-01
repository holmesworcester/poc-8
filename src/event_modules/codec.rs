use super::EventError;

pub fn put_string_u16(out: &mut Vec<u8>, value: &str) {
    let len = u16::try_from(value.len()).expect("string too large for u16 codec");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}

pub fn put_string_u32(out: &mut Vec<u8>, value: &str) {
    let len = u32::try_from(value.len()).expect("string too large for u32 codec");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}

pub fn put_bytes_u64(out: &mut Vec<u8>, value: &[u8]) {
    let len = u64::try_from(value.len()).expect("bytes too large for u64 codec");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value);
}

pub fn encode_three_id_event(
    kind: u8,
    first_id: [u8; 32],
    second_id: [u8; 32],
    third_id: [u8; 32],
) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&first_id);
    out.extend_from_slice(&second_id);
    out.extend_from_slice(&third_id);
    out
}

pub struct Cursor<'a> {
    rest: &'a [u8],
}

impl<'a> Cursor<'a> {
    pub fn new(rest: &'a [u8]) -> Self {
        Self { rest }
    }

    pub fn id(&mut self) -> Result<[u8; 32], EventError> {
        if self.rest.len() < 32 {
            return Err(EventError::Truncated);
        }
        let (head, tail) = self.rest.split_at(32);
        self.rest = tail;
        let mut id = [0; 32];
        id.copy_from_slice(head);
        Ok(id)
    }

    pub fn string_u16(&mut self) -> Result<String, EventError> {
        if self.rest.len() < 2 {
            return Err(EventError::Truncated);
        }
        let len = u16::from_be_bytes([self.rest[0], self.rest[1]]) as usize;
        self.rest = &self.rest[2..];
        self.string(len)
    }

    pub fn string_u32(&mut self) -> Result<String, EventError> {
        if self.rest.len() < 4 {
            return Err(EventError::Truncated);
        }
        let len =
            u32::from_be_bytes([self.rest[0], self.rest[1], self.rest[2], self.rest[3]]) as usize;
        self.rest = &self.rest[4..];
        self.string(len)
    }

    pub fn bytes_u64(&mut self) -> Result<Vec<u8>, EventError> {
        if self.rest.len() < 8 {
            return Err(EventError::Truncated);
        }
        let len = u64::from_be_bytes([
            self.rest[0],
            self.rest[1],
            self.rest[2],
            self.rest[3],
            self.rest[4],
            self.rest[5],
            self.rest[6],
            self.rest[7],
        ]);
        self.rest = &self.rest[8..];
        let len = usize::try_from(len).map_err(|_| EventError::Truncated)?;
        if self.rest.len() < len {
            return Err(EventError::Truncated);
        }
        let (head, tail) = self.rest.split_at(len);
        self.rest = tail;
        Ok(head.to_vec())
    }

    pub fn three_ids(&mut self) -> Result<([u8; 32], [u8; 32], [u8; 32]), EventError> {
        let first = self.id()?;
        let second = self.id()?;
        let third = self.id()?;
        self.finish()?;
        Ok((first, second, third))
    }

    pub fn finish(&self) -> Result<(), EventError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(EventError::Truncated)
        }
    }

    fn string(&mut self, len: usize) -> Result<String, EventError> {
        if self.rest.len() < len {
            return Err(EventError::Truncated);
        }
        let (head, tail) = self.rest.split_at(len);
        self.rest = tail;
        String::from_utf8(head.to_vec()).map_err(|_| EventError::InvalidUtf8)
    }
}

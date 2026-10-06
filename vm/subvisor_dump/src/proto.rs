// Copyright (c) Matt Suiche.
// Licensed under the MIT License.

//! A minimal reader for the protobuf wire format.
//!
//! OpenVMM encodes snapshot state with `mesh`, which is protobuf-compatible on
//! the wire. This tool reads those files without depending on the VMM, so it
//! can parse snapshots produced by any OpenVMM fork. Only the three wire types
//! the snapshot uses are supported: varint, 64-bit, and length-delimited.

/// A protobuf wire error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The buffer ended in the middle of a value.
    #[error("unexpected end of protobuf buffer")]
    Truncated,
    /// A varint was longer than 10 bytes.
    #[error("malformed varint")]
    BadVarint,
    /// A wire type this reader does not implement was encountered.
    #[error("unsupported protobuf wire type {0}")]
    UnsupportedWireType(u8),
}

/// One field read from a protobuf message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value<'a> {
    /// A varint (wire type 0).
    Varint(u64),
    /// A fixed 64-bit value (wire type 1).
    Fixed64(u64),
    /// A length-delimited value: bytes, string, or a nested message
    /// (wire type 2).
    Bytes(&'a [u8]),
    /// A fixed 32-bit value (wire type 5).
    Fixed32(u32),
}

/// A cursor over a protobuf message.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Creates a reader over `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Returns true if the whole message has been consumed.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn read_varint(&mut self) -> Result<u64, Error> {
        let mut result = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = *self.buf.get(self.pos).ok_or(Error::Truncated)?;
            self.pos += 1;
            result |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
        }
        Err(Error::BadVarint)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    /// Reads the next `(field_number, value)` pair, or `None` at the end.
    pub fn next_field(&mut self) -> Result<Option<(u32, Value<'a>)>, Error> {
        if self.is_empty() {
            return Ok(None);
        }
        let tag = self.read_varint()?;
        let field = u32::try_from(tag >> 3).map_err(|_| Error::BadVarint)?;
        let wire = (tag & 7) as u8;
        let value = match wire {
            0 => Value::Varint(self.read_varint()?),
            1 => Value::Fixed64(u64::from_le_bytes(self.take(8)?.try_into().unwrap())),
            2 => {
                let len = usize::try_from(self.read_varint()?).map_err(|_| Error::Truncated)?;
                Value::Bytes(self.take(len)?)
            }
            5 => Value::Fixed32(u32::from_le_bytes(self.take(4)?.try_into().unwrap())),
            other => return Err(Error::UnsupportedWireType(other)),
        };
        Ok(Some((field, value)))
    }

    /// Returns the length-delimited value of the first field numbered `field`.
    pub fn bytes_field(buf: &'a [u8], field: u32) -> Result<Option<&'a [u8]>, Error> {
        let mut r = Reader::new(buf);
        while let Some((f, v)) = r.next_field()? {
            if f == field {
                if let Value::Bytes(b) = v {
                    return Ok(Some(b));
                }
            }
        }
        Ok(None)
    }

    /// Returns the varint value of the first field numbered `field`.
    pub fn varint_field(buf: &'a [u8], field: u32) -> Result<Option<u64>, Error> {
        let mut r = Reader::new(buf);
        while let Some((f, v)) = r.next_field()? {
            if f == field {
                match v {
                    Value::Varint(n) => return Ok(Some(n)),
                    Value::Fixed64(n) => return Ok(Some(n)),
                    Value::Fixed32(n) => return Ok(Some(u64::from(n))),
                    Value::Bytes(_) => {}
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encodes a varint for building test messages.
    fn varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if v == 0 {
                break;
            }
        }
        out
    }

    fn tag(field: u32, wire: u8) -> Vec<u8> {
        varint(u64::from(field) << 3 | u64::from(wire))
    }

    #[test]
    fn reads_each_wire_type() {
        let mut msg = Vec::new();
        msg.extend(tag(1, 0));
        msg.extend(varint(300));
        msg.extend(tag(2, 2));
        msg.extend(varint(3));
        msg.extend(b"abc");
        msg.extend(tag(3, 1));
        msg.extend(0x1122_3344_5566_7788u64.to_le_bytes());
        msg.extend(tag(4, 5));
        msg.extend(0xdead_beefu32.to_le_bytes());

        let mut r = Reader::new(&msg);
        assert_eq!(r.next_field().unwrap(), Some((1, Value::Varint(300))));
        assert_eq!(r.next_field().unwrap(), Some((2, Value::Bytes(b"abc"))));
        assert_eq!(
            r.next_field().unwrap(),
            Some((3, Value::Fixed64(0x1122_3344_5566_7788)))
        );
        assert_eq!(
            r.next_field().unwrap(),
            Some((4, Value::Fixed32(0xdead_beef)))
        );
        assert_eq!(r.next_field().unwrap(), None);
    }

    #[test]
    fn multibyte_varint() {
        // 0x40000000 = 1 GiB, encoded as five bytes.
        let bytes = varint(0x4000_0000);
        assert_eq!(bytes, [0x80, 0x80, 0x80, 0x80, 0x04]);
        let msg = [&tag(4, 0)[..], &bytes].concat();
        let mut r = Reader::new(&msg);
        assert_eq!(
            r.next_field().unwrap(),
            Some((4, Value::Varint(0x4000_0000)))
        );
    }

    #[test]
    fn field_accessors() {
        let mut msg = Vec::new();
        msg.extend(tag(4, 0));
        msg.extend(varint(0x4000_0000));
        msg.extend(tag(7, 2));
        msg.extend(varint(7));
        msg.extend(b"aarch64");
        assert_eq!(Reader::varint_field(&msg, 4).unwrap(), Some(0x4000_0000));
        assert_eq!(Reader::bytes_field(&msg, 7).unwrap(), Some(&b"aarch64"[..]));
        assert_eq!(Reader::varint_field(&msg, 99).unwrap(), None);
    }

    #[test]
    fn truncated_is_error() {
        // Length-delimited field claiming 10 bytes but only 2 present.
        let mut msg = tag(2, 2);
        msg.extend(varint(10));
        msg.extend(b"ab");
        let mut r = Reader::new(&msg);
        assert!(matches!(r.next_field(), Err(Error::Truncated)));
    }

    #[test]
    fn bad_varint_is_error() {
        let msg = [0x80u8; 11];
        let mut r = Reader::new(&msg);
        assert!(matches!(r.next_field(), Err(Error::BadVarint)));
    }
}

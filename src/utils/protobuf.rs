use crate::utils::varint;

/// A quick protobuf encode helper.
pub fn encode<'a>(out: &'a mut [u8]) -> Encoder<'a> {
    Encoder { start_len: out.len(), out }
}

pub struct Encoder<'a> {
    out: &'a mut [u8],
    start_len: usize,
}

impl <'a> Encoder<'a> {
    pub fn encode_varint(mut self, field_id: u64, value: impl Into<u64>) -> Self {
        self.encode_field_id_and_wire_type(field_id, WireType::Varint);
        // Encode value as varint
        self.encode_varint_value(value.into());
        self
    }
    pub fn encode_data(mut self, field_id: u64, data: &[u8]) -> Self {
        self.encode_field_id_and_wire_type(field_id, WireType::Data);
        // Encode length first
        self.encode_varint_value(data.len() as u64);
        // Then encode data, advancing the cursor
        self.out[..data.len()].copy_from_slice(data);
        self.out = &mut self.out[data.len()..];
        self
    }
    pub fn num_encoded(&self) -> usize {
        self.start_len - self.out.len()
    }
    fn encode_field_id_and_wire_type(&mut self, field_id: u64, wire_type: WireType) {
        let wire_type_u8: u8 = wire_type.into();
        let tag_value = (field_id << 3) | (wire_type_u8 as u64);
        self.encode_varint_value(tag_value);
    }
    fn encode_varint_value(&mut self, val: u64) {
        let n = varint::encode(val, self.out);
        let out = core::mem::take(&mut self.out);
        self.out = &mut out[n..];
    }
}

/// Decode some protobuf bytes.
pub fn decode<'input, V: Visitor<'input>>(cursor: &mut &'input [u8], visitor: &mut V) -> Result<(), Error> {
    while !cursor.is_empty() {
        let tag_val = varint::decode(cursor)?;
        // everything but the smallest 3 bits are the field number
        let field_number = (tag_val >> 3) as u64;
        // the smallest 3 bits denote the typw of the field
        let wire_type = WireType::from((tag_val & 0x07) as u8);

        match wire_type {
            // varint
            WireType::Varint => {
                let val = varint::decode(cursor)?;
                visitor.varint(field_number, val);
            },
            // i64 (fixed 8 bytes)
            WireType::I64 => {
                const BYTES: usize = 8;
                let Some(bytes) = cursor.get(0..BYTES) else {
                    return Err(Error::UnexpectedEndOfInput {
                        need: BYTES,
                        got: cursor.len()
                    })
                };
                let bytes: [u8; BYTES] = bytes.try_into().unwrap();
                *cursor = &cursor[BYTES..];
                visitor.i64(field_number, bytes);
            }
            // LEN (varint length followed by data)
            WireType::Data => {
                let val = varint::decode(cursor)? as usize;
                let Some(bytes) = cursor.get(0..val) else {
                    return Err(Error::UnexpectedEndOfInput {
                        need: val,
                        got: cursor.len()
                    })
                };
                *cursor = &cursor[val..];
                visitor.data(field_number, bytes);
            }
            // Groups (deprecated)
            WireType::DeprecatedGroups(_) => {
                // Nothing to do; group tags have no value associated with them.
            }
            // i32 (fixed 4 bytes)
            WireType::I32 => {
                const BYTES: usize = 4;
                let Some(bytes) = cursor.get(0..BYTES) else {
                    return Err(Error::UnexpectedEndOfInput {
                        need: BYTES,
                        got: cursor.len()
                    })
                };
                let bytes: [u8; BYTES] = bytes.try_into().unwrap();
                *cursor = &cursor[BYTES..];
                visitor.i32(field_number, bytes);
            },
            // Invalid wire type
            WireType::Unknown(n) => {
                return Err(Error::InvalidWireType {
                    got: n
                })
            }
        }
    }
    Ok(())
}

/// Visit some protobuf type; pass to [`decode`].
pub trait Visitor<'input> {
    fn varint(&mut self, _field_id: u64, _n: u64) {}
    fn i64(&mut self, _field_id: u64, _n: [u8; 8]) {}
    fn i32(&mut self, _field_id: u64, _n: [u8; 4]) {}
    fn data(&mut self, _field_id: u64, _bytes: &'input [u8]) {}
}

/// A nerror decoding some protobuf type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to decode varint: {0}")]
    Varint(#[from] varint::Error),
    #[error("unexpected end of input; need {need} bytes but have {got}")]
    UnexpectedEndOfInput {
        need: usize,
        got: usize
    },
    #[error("invalid/unknown wire type {got}")]
    InvalidWireType {
        got: u8
    }
}

/// The protobuf wire type
pub enum WireType {
    Varint,
    I64,
    Data,
    DeprecatedGroups(u8),
    I32,
    Unknown(u8),
}

impl From<u8> for WireType {
    fn from(value: u8) -> Self {
        match value {
            0 => WireType::Varint,
            1 => WireType::I64,
            2 => WireType::Data,
            3 | 4 => WireType::DeprecatedGroups(value),
            5 => WireType::I32,
            n => WireType::Unknown(n),
        }
    }
}

impl From<WireType> for u8 {
    fn from(value: WireType) -> Self {
        match value {
            WireType::Varint => 0,
            WireType::I64 => 1,
            WireType::Data => 2,
            WireType::DeprecatedGroups(n) => n,
            WireType::I32 => 5,
            WireType::Unknown(n) => n,
        }
    }
}
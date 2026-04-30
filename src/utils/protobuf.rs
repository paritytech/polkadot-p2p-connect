use crate::utils::varint;

/// Number of bytes used to store I64 data.
const I64_LEN: usize = 8;
/// Number of bytes used to store I32 data.
const I32_LEN: usize = 4;

/// A quick protobuf encode helper.
pub fn encode<'a>(out: &'a mut [u8]) -> Encoder<'a> {
    Encoder {
        start_len: out.len(),
        out,
    }
}

pub struct Encoder<'a> {
    out: &'a mut [u8],
    start_len: usize,
}

impl<'a> Encoder<'a> {
    pub fn encode_varint(mut self, field_id: u64, value: impl Into<u64>) -> Self {
        self.encode_field_id_and_wire_type(field_id, WireType::Varint);
        // Encode value as varint
        self.encode_varint_value(value.into());
        self
    }
    #[allow(unused)]
    pub fn encode_i64(mut self, field_id: u64, value: [u8; I64_LEN]) -> Self {
        self.encode_field_id_and_wire_type(field_id, WireType::I64);
        self.out[..I64_LEN].copy_from_slice(&value);
        self.out = &mut self.out[I64_LEN..];
        self
    }
    #[allow(unused)]
    pub fn encode_i32(mut self, field_id: u64, value: [u8; I32_LEN]) -> Self {
        self.encode_field_id_and_wire_type(field_id, WireType::I32);
        self.out[..I32_LEN].copy_from_slice(&value);
        self.out = &mut self.out[I32_LEN..];
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
pub fn decode<'input, V: Visitor<'input>>(
    cursor: &mut &'input [u8],
    visitor: &mut V,
) -> Result<(), Error> {
    while !cursor.is_empty() {
        let tag_val = varint::decode(cursor)?;
        // everything but the smallest 3 bits are the field number
        let field_number = (tag_val >> 3);
        // the smallest 3 bits denote the typw of the field
        let wire_type = WireType::from((tag_val & 0x07) as u8);

        match wire_type {
            // varint
            WireType::Varint => {
                let val = varint::decode(cursor)?;
                visitor.varint(field_number, val);
            }
            // i64 (fixed 8 bytes)
            WireType::I64 => {
                let Some(bytes) = cursor.get(0..I64_LEN) else {
                    return Err(Error::UnexpectedEndOfInput {
                        need: I64_LEN,
                        got: cursor.len(),
                    });
                };
                let bytes: [u8; I64_LEN] = bytes.try_into().unwrap();
                *cursor = &cursor[I64_LEN..];
                visitor.i64(field_number, bytes);
            }
            // LEN (varint length followed by data)
            WireType::Data => {
                let val = varint::decode(cursor)? as usize;
                let Some(bytes) = cursor.get(0..val) else {
                    return Err(Error::UnexpectedEndOfInput {
                        need: val,
                        got: cursor.len(),
                    });
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
                let Some(bytes) = cursor.get(0..I32_LEN) else {
                    return Err(Error::UnexpectedEndOfInput {
                        need: I32_LEN,
                        got: cursor.len(),
                    });
                };
                let bytes: [u8; I32_LEN] = bytes.try_into().unwrap();
                *cursor = &cursor[I32_LEN..];
                visitor.i32(field_number, bytes);
            }
            // Invalid wire type
            WireType::Unknown(n) => return Err(Error::InvalidWireType { got: n }),
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
    UnexpectedEndOfInput { need: usize, got: usize },
    #[error("invalid/unknown wire type {got}")]
    InvalidWireType { got: u8 },
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

#[cfg(test)]
mod test {
    use super::*;
    use alloc::{vec, vec::Vec};

    // -- Test Visitor that collects all decoded fields --

    #[derive(Debug, PartialEq)]
    struct Field {
        id: u64,
        value: FieldValue,
    }

    #[derive(Debug, PartialEq)]
    enum FieldValue {
        Varint(u64),
        I64([u8; 8]),
        I32([u8; 4]),
        Data(Vec<u8>),
    }

    #[derive(Debug, Default)]
    struct CollectVisitor {
        fields: Vec<Field>,
    }

    impl<'input> Visitor<'input> for CollectVisitor {
        fn varint(&mut self, field_id: u64, n: u64) {
            self.fields.push(Field {
                id: field_id,
                value: FieldValue::Varint(n),
            });
        }
        fn i64(&mut self, field_id: u64, n: [u8; 8]) {
            self.fields.push(Field {
                id: field_id,
                value: FieldValue::I64(n),
            });
        }
        fn i32(&mut self, field_id: u64, n: [u8; 4]) {
            self.fields.push(Field {
                id: field_id,
                value: FieldValue::I32(n),
            });
        }
        fn data(&mut self, field_id: u64, bytes: &'input [u8]) {
            self.fields.push(Field {
                id: field_id,
                value: FieldValue::Data(bytes.to_vec()),
            });
        }
    }

    /// Encode into a Vec via our Encoder, returning only the written bytes.
    fn encode_to_vec(f: impl FnOnce(Encoder) -> Encoder) -> Vec<u8> {
        let mut buf = [0u8; 256];
        let enc = encode(&mut buf);
        let enc = f(enc);
        let n = enc.num_encoded();
        buf[..n].to_vec()
    }

    // =================== WireType conversions ===================

    #[test]
    fn wire_type_from_u8() {
        assert!(matches!(WireType::from(0), WireType::Varint));
        assert!(matches!(WireType::from(1), WireType::I64));
        assert!(matches!(WireType::from(2), WireType::Data));
        assert!(matches!(WireType::from(3), WireType::DeprecatedGroups(3)));
        assert!(matches!(WireType::from(4), WireType::DeprecatedGroups(4)));
        assert!(matches!(WireType::from(5), WireType::I32));
        assert!(matches!(WireType::from(6), WireType::Unknown(6)));
        assert!(matches!(WireType::from(7), WireType::Unknown(7)));
    }

    #[test]
    fn wire_type_to_u8_round_trip() {
        assert_eq!(u8::from(WireType::Varint), 0);
        assert_eq!(u8::from(WireType::I64), 1);
        assert_eq!(u8::from(WireType::Data), 2);
        assert_eq!(u8::from(WireType::DeprecatedGroups(3)), 3);
        assert_eq!(u8::from(WireType::DeprecatedGroups(4)), 4);
        assert_eq!(u8::from(WireType::I32), 5);
        assert_eq!(u8::from(WireType::Unknown(6)), 6);
    }

    // =================== Encoder basics ===================

    #[test]
    fn encode_single_varint() {
        // field 1, varint 150 => tag (1<<3|0)=8 as varint [0x08], value 150 as varint [0x96,0x01]
        let bytes = encode_to_vec(|e| e.encode_varint(1, 150u64));
        assert_eq!(bytes, &[0x08, 0x96, 0x01]);
    }

    #[test]
    fn encode_single_varint_zero() {
        // field 1, varint 0 => tag [0x08], value [0x00]
        let bytes = encode_to_vec(|e| e.encode_varint(1, 0u64));
        assert_eq!(bytes, &[0x08, 0x00]);
    }

    #[test]
    fn encode_data_field() {
        // field 2, data "hello" => tag (2<<3|2)=18 as varint [0x12], len 5 [0x05], then "hello"
        let bytes = encode_to_vec(|e| e.encode_data(2, b"hello"));
        assert_eq!(bytes, &[0x12, 0x05, b'h', b'e', b'l', b'l', b'o']);
    }

    #[test]
    fn encode_empty_data_field() {
        // field 1, data [] => tag (1<<3|2)=10 as varint [0x0A], len 0 [0x00]
        let bytes = encode_to_vec(|e| e.encode_data(1, &[]));
        assert_eq!(bytes, &[0x0A, 0x00]);
    }

    #[test]
    fn encode_i64_field() {
        let value = [1, 2, 3, 4, 5, 6, 7, 8];
        // field 1, i64 => tag (1<<3|1)=9 as varint [0x09], then 8 bytes
        let bytes = encode_to_vec(|e| e.encode_i64(1, value));
        assert_eq!(bytes, &[0x09, 1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn encode_i32_field() {
        let value = [0xAA, 0xBB, 0xCC, 0xDD];
        // field 3, i32 => tag (3<<3|5)=29 as varint [0x1D], then 4 bytes
        let bytes = encode_to_vec(|e| e.encode_i32(3, value));
        assert_eq!(bytes, &[0x1D, 0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn encode_num_encoded_tracks_bytes() {
        let mut buf = [0u8; 64];
        let enc = encode(&mut buf);
        assert_eq!(enc.num_encoded(), 0);
        let enc = enc.encode_varint(1, 0u64);
        assert_eq!(enc.num_encoded(), 2); // 1 byte tag + 1 byte value
        let enc = enc.encode_data(2, b"ab");
        // +1 tag + 1 len + 2 data = 4 more
        assert_eq!(enc.num_encoded(), 6);
    }

    // =================== Decode basics ===================

    #[test]
    fn decode_single_varint() {
        let bytes = &[0x08, 0x96, 0x01]; // field 1, varint 150
        let mut cursor = &bytes[..];
        let mut v = CollectVisitor::default();
        decode(&mut cursor, &mut v).unwrap();
        assert!(cursor.is_empty());
        assert_eq!(v.fields.len(), 1);
        assert_eq!(
            v.fields[0],
            Field {
                id: 1,
                value: FieldValue::Varint(150)
            }
        );
    }

    #[test]
    fn decode_data_field() {
        let bytes = &[0x12, 0x05, b'h', b'e', b'l', b'l', b'o']; // field 2, data "hello"
        let mut cursor = &bytes[..];
        let mut v = CollectVisitor::default();
        decode(&mut cursor, &mut v).unwrap();
        assert!(cursor.is_empty());
        assert_eq!(v.fields.len(), 1);
        assert_eq!(
            v.fields[0],
            Field {
                id: 2,
                value: FieldValue::Data(b"hello".to_vec())
            }
        );
    }

    #[test]
    fn decode_i64_field() {
        let bytes = &[0x09, 1, 2, 3, 4, 5, 6, 7, 8]; // field 1, i64
        let mut cursor = &bytes[..];
        let mut v = CollectVisitor::default();
        decode(&mut cursor, &mut v).unwrap();
        assert!(cursor.is_empty());
        assert_eq!(
            v.fields[0],
            Field {
                id: 1,
                value: FieldValue::I64([1, 2, 3, 4, 5, 6, 7, 8])
            }
        );
    }

    #[test]
    fn decode_i32_field() {
        let bytes = &[0x1D, 0xAA, 0xBB, 0xCC, 0xDD]; // field 3, i32
        let mut cursor = &bytes[..];
        let mut v = CollectVisitor::default();
        decode(&mut cursor, &mut v).unwrap();
        assert!(cursor.is_empty());
        assert_eq!(
            v.fields[0],
            Field {
                id: 3,
                value: FieldValue::I32([0xAA, 0xBB, 0xCC, 0xDD])
            }
        );
    }

    #[test]
    fn decode_empty_input_is_ok() {
        let mut cursor: &[u8] = &[];
        let mut v = CollectVisitor::default();
        decode(&mut cursor, &mut v).unwrap();
        assert!(v.fields.is_empty());
    }

    // =================== Round-trips ===================

    #[test]
    fn round_trip_varint() {
        let bytes = encode_to_vec(|e| e.encode_varint(5, 12345u64));
        let mut cursor = &bytes[..];
        let mut v = CollectVisitor::default();
        decode(&mut cursor, &mut v).unwrap();
        assert_eq!(
            v.fields,
            &[Field {
                id: 5,
                value: FieldValue::Varint(12345)
            }]
        );
    }

    #[test]
    fn round_trip_data() {
        let payload = b"protobuf test data!";
        let bytes = encode_to_vec(|e| e.encode_data(10, payload));
        let mut cursor = &bytes[..];
        let mut v = CollectVisitor::default();
        decode(&mut cursor, &mut v).unwrap();
        assert_eq!(
            v.fields,
            &[Field {
                id: 10,
                value: FieldValue::Data(payload.to_vec())
            }]
        );
    }

    #[test]
    fn round_trip_i64() {
        let val = 0x0102030405060708u64.to_le_bytes();
        let bytes = encode_to_vec(|e| e.encode_i64(7, val));
        let mut cursor = &bytes[..];
        let mut v = CollectVisitor::default();
        decode(&mut cursor, &mut v).unwrap();
        assert_eq!(
            v.fields,
            &[Field {
                id: 7,
                value: FieldValue::I64(val)
            }]
        );
    }

    #[test]
    fn round_trip_i32() {
        let val = 0xDEADBEEFu32.to_le_bytes();
        let bytes = encode_to_vec(|e| e.encode_i32(4, val));
        let mut cursor = &bytes[..];
        let mut v = CollectVisitor::default();
        decode(&mut cursor, &mut v).unwrap();
        assert_eq!(
            v.fields,
            &[Field {
                id: 4,
                value: FieldValue::I32(val)
            }]
        );
    }

    #[test]
    fn round_trip_multiple_fields() {
        let bytes = encode_to_vec(|e| {
            e.encode_varint(1, 42u64)
                .encode_data(2, b"abc")
                .encode_i32(3, [0x01, 0x02, 0x03, 0x04])
                .encode_i64(4, [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80])
                .encode_varint(5, 0u64)
                .encode_data(6, &[])
        });
        let mut cursor = &bytes[..];
        let mut v = CollectVisitor::default();
        decode(&mut cursor, &mut v).unwrap();
        assert_eq!(v.fields.len(), 6);
        assert_eq!(
            v.fields[0],
            Field {
                id: 1,
                value: FieldValue::Varint(42)
            }
        );
        assert_eq!(
            v.fields[1],
            Field {
                id: 2,
                value: FieldValue::Data(b"abc".to_vec())
            }
        );
        assert_eq!(
            v.fields[2],
            Field {
                id: 3,
                value: FieldValue::I32([0x01, 0x02, 0x03, 0x04])
            }
        );
        assert_eq!(
            v.fields[3],
            Field {
                id: 4,
                value: FieldValue::I64([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80])
            }
        );
        assert_eq!(
            v.fields[4],
            Field {
                id: 5,
                value: FieldValue::Varint(0)
            }
        );
        assert_eq!(
            v.fields[5],
            Field {
                id: 6,
                value: FieldValue::Data(vec![])
            }
        );
    }

    #[test]
    fn round_trip_large_field_id() {
        // Field IDs above 15 require multi-byte tags.
        let bytes = encode_to_vec(|e| e.encode_varint(1000, 99u64));
        let mut cursor = &bytes[..];
        let mut v = CollectVisitor::default();
        decode(&mut cursor, &mut v).unwrap();
        assert_eq!(
            v.fields,
            &[Field {
                id: 1000,
                value: FieldValue::Varint(99)
            }]
        );
    }

    #[test]
    fn round_trip_max_varint_value() {
        let bytes = encode_to_vec(|e| e.encode_varint(1, u64::MAX));
        let mut cursor = &bytes[..];
        let mut v = CollectVisitor::default();
        decode(&mut cursor, &mut v).unwrap();
        assert_eq!(
            v.fields,
            &[Field {
                id: 1,
                value: FieldValue::Varint(u64::MAX)
            }]
        );
    }

    // =================== Decode error cases ===================

    #[test]
    fn decode_truncated_i64() {
        // Tag for field 1, i64, but only 3 value bytes instead of 8
        let bytes = &[0x09, 0x01, 0x02, 0x03];
        let mut cursor = &bytes[..];
        let mut v = CollectVisitor::default();
        let err = decode(&mut cursor, &mut v).unwrap_err();
        assert!(matches!(
            err,
            Error::UnexpectedEndOfInput { need: 8, got: 3 }
        ));
    }

    #[test]
    fn decode_truncated_i32() {
        // Tag for field 1, i32 (wire type 5), but only 2 value bytes instead of 4
        let bytes = &[0x0D, 0x01, 0x02];
        let mut cursor = &bytes[..];
        let mut v = CollectVisitor::default();
        let err = decode(&mut cursor, &mut v).unwrap_err();
        assert!(matches!(
            err,
            Error::UnexpectedEndOfInput { need: 4, got: 2 }
        ));
    }

    #[test]
    fn decode_truncated_data() {
        // Tag for field 1, data; length says 10 but only 3 bytes follow
        let bytes = &[0x0A, 0x0A, 0x01, 0x02, 0x03];
        let mut cursor = &bytes[..];
        let mut v = CollectVisitor::default();
        let err = decode(&mut cursor, &mut v).unwrap_err();
        assert!(matches!(
            err,
            Error::UnexpectedEndOfInput { need: 10, got: 3 }
        ));
    }

    #[test]
    fn decode_invalid_wire_type_6() {
        // Fabricate a tag with wire type 6 (unknown): field 1, wire type 6 => (1<<3)|6 = 14
        let bytes = &[0x0E];
        let mut cursor = &bytes[..];
        let mut v = CollectVisitor::default();
        let err = decode(&mut cursor, &mut v).unwrap_err();
        assert!(matches!(err, Error::InvalidWireType { got: 6 }));
    }

    #[test]
    fn decode_invalid_wire_type_7() {
        // field 1, wire type 7 => (1<<3)|7 = 15
        let bytes = &[0x0F];
        let mut cursor = &bytes[..];
        let mut v = CollectVisitor::default();
        let err = decode(&mut cursor, &mut v).unwrap_err();
        assert!(matches!(err, Error::InvalidWireType { got: 7 }));
    }

    #[test]
    fn decode_deprecated_group_tags_are_skipped() {
        // Encode: varint field, then a group start tag (wire type 3), then another varint field.
        // field 1 varint 42 => [0x08, 0x2A]
        // field 2 group start (wire type 3) => (2<<3)|3 = 19 => [0x13]
        // field 3 varint 99 => [0x18, 0x63]
        let bytes = &[0x08, 0x2A, 0x13, 0x18, 0x63];
        let mut cursor = &bytes[..];
        let mut v = CollectVisitor::default();
        decode(&mut cursor, &mut v).unwrap();
        // Group tag should be silently skipped; we should see field 1 and field 3.
        assert_eq!(v.fields.len(), 2);
        assert_eq!(
            v.fields[0],
            Field {
                id: 1,
                value: FieldValue::Varint(42)
            }
        );
        assert_eq!(
            v.fields[1],
            Field {
                id: 3,
                value: FieldValue::Varint(99)
            }
        );
    }

    #[test]
    fn decode_bad_varint_in_tag_propagates_error() {
        // A tag that is an invalid varint (too many continuation bytes)
        let bytes = [0x80u8; 11];
        let mut cursor = &bytes[..];
        let mut v = CollectVisitor::default();
        let err = decode(&mut cursor, &mut v).unwrap_err();
        assert!(matches!(err, Error::Varint(_)));
    }

    #[test]
    fn decode_bad_varint_in_value_propagates_error() {
        // Valid tag for field 1 varint [0x08], then a broken varint value
        let mut bytes = vec![0x08];
        bytes.extend_from_slice(&[0x80; 11]);
        let mut cursor = &bytes[..];
        let mut v = CollectVisitor::default();
        let err = decode(&mut cursor, &mut v).unwrap_err();
        assert!(matches!(err, Error::Varint(_)));
    }

    // =================== Tag encoding sanity ===================

    #[test]
    fn tag_encoding_field_ids_1_through_15_are_single_byte() {
        // field_id << 3 | wire_type for fields 1-15 with wire type 0 fit in one byte (max 15<<3 = 120)
        for field_id in 1u64..=15 {
            let bytes = encode_to_vec(|e| e.encode_varint(field_id, 0u64));
            // Single-byte tag + single-byte value(0) = 2 bytes
            assert_eq!(
                bytes.len(),
                2,
                "field_id {field_id} should have single-byte tag"
            );
        }
    }

    #[test]
    fn tag_encoding_field_id_16_is_two_bytes() {
        // 16 << 3 = 128, which requires a 2-byte varint for the tag
        let bytes = encode_to_vec(|e| e.encode_varint(16, 0u64));
        // 2-byte tag + 1-byte value(0) = 3 bytes
        assert_eq!(bytes.len(), 3);
    }
}

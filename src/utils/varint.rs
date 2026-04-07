use crate::utils::async_stream::{self, AsyncStream};
use alloc::vec::Vec;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("stream error reading varint: {0}")]
    Stream(#[from] async_stream::Error),
    #[error("varint is too large")]
    OutOfRange,
    #[error("ran out of input decoding varint")]
    UnexpectedEndOfInput,
}

/// Encode a u64 as an unsigned varint, returning the number of bytes written.
/// Prefer [`encode_to_vec`] where possible as this cannot hit out-of-bound issues.
/// 
/// # Panics
/// 
/// Panics if the buffer given to encode it to is not large enough.
pub fn encode(mut value: u64, out: &mut [u8]) -> usize {
    let mut idx = 0;
    loop {
        // encode 7 bits at a time
        let byte = (value & 0b0111_1111) as u8;
        value >>= 7;

        // .. until no more "1" bits to encode
        if value == 0 {
            out[idx] = byte;
            idx += 1;
            break;
        }

        // Each byte has MSB set to 1 to indicate more bytes will follow.
        out[idx] = byte | 0b1000_0000;
        idx += 1;
    }

    // Return the number of bytes written.
    idx
}

/// Encode a u64 as an unsigned varint. Unlike [`encode`], this encodes directly
/// to a growable vector and thus won't hit any out of bound issues, as the vector
/// can grow as needed.
pub fn encode_to_vec(value: u64, out: &mut Vec<u8>) {
    let mut buf = [0u8; 10];
    let n = encode(value, &mut buf);
    out.extend_from_slice(&buf[..n]);
}

/// Decode some bytes as a varint into a u64. This advanced the given
/// cursor by the number of bytes decoded.
pub fn decode(bytes: &mut &[u8]) -> Result<u64, Error> {
    let mut decoder = Decoder::new();
    while !bytes.is_empty() {
        // Read a byte
        let byte = bytes[0];
        *bytes = &bytes[1..];

        // Feed it to the decoder
        match decoder.feed(byte) {
            DecoderOutput::Value(val) => return Ok(val),
            DecoderOutput::NeedsMoreBytes(d) => decoder = d,
            DecoderOutput::OutOfRange => return Err(Error::OutOfRange)
        }
    }
    Err(Error::UnexpectedEndOfInput)
}

/// Read an unsigned varint from an async stream, one byte at a time.
pub async fn decode_from_stream(stream: &mut impl AsyncStream) -> Result<u64, Error> {
    let mut decoder = Decoder::new();
    loop {
        // Read a byte
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte).await?;

        // Feed it to the decoder
        match decoder.feed(byte[0]) {
            DecoderOutput::Value(val) => return Ok(val),
            DecoderOutput::NeedsMoreBytes(d) => decoder = d,
            DecoderOutput::OutOfRange => return Err(Error::OutOfRange)
        }
    }
}

/// The low-level varint decoder that [`decode`] and [`decode_from_stream`] use internally
#[derive(Debug, Clone, Copy)]
pub struct Decoder {
    buf: [u8; 10],
    len: usize,
}

/// Output from [`Decoder::feed`].
#[derive(Debug)]
pub enum DecoderOutput {
    Value(u64),
    NeedsMoreBytes(Decoder),
    OutOfRange,
}

impl Decoder {
    pub fn new() -> Decoder {
        Self {
            buf: [0u8; 10],
            len: 0,
        }
    }

    /// Feed a byte to the decoder, and get back output depending on the
    /// state of decoding.
    pub fn feed(mut self, byte: u8) -> DecoderOutput {
        if self.len >= self.buf.len() {
            // Too many bytes given.
            return DecoderOutput::OutOfRange;
        }
        
        // Push the given byte to our buf.
        self.buf[self.len] = byte;
        self.len += 1;
        
        if byte & 0b1000_0000 == 0 {
            // MSB not set: this is the last byte; decode!
            DecoderOutput::Value(self.decode_valid_bytes())
        } else {
            // MSB set: more bytes will follow.
            DecoderOutput::NeedsMoreBytes(self)
        }
    }

    fn decode_valid_bytes(self) -> u64 {
        let mut value: u64 = 0;        
        for (idx, &byte) in self.buf[..self.len].iter().enumerate() {
            let byte_val = (byte & 0b0111_1111) as u64;
            value |= byte_val << (idx * 7)
        }
        value
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec;

    // Known unsigned varint (LEB128) encodings.
    const KNOWN_ENCODINGS: &[(u64, &[u8])] = &[
        (0, &[0x00]),
        (1, &[0x01]),
        (127, &[0x7F]),
        (128, &[0x80, 0x01]),
        (255, &[0xFF, 0x01]),
        (300, &[0xAC, 0x02]),
        (16384, &[0x80, 0x80, 0x01]),
        (u64::MAX, &[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]),
    ];

    #[test]
    fn encode_known_values() {
        for &(value, expected) in KNOWN_ENCODINGS {
            let mut buf = [0u8; 10];
            let n = encode(value, &mut buf);
            assert_eq!(&buf[..n], expected, "encoding {value}");
        }
    }

    #[test]
    fn decode_known_values() {
        for &(expected, bytes) in KNOWN_ENCODINGS {
            let mut cursor = bytes;
            let value = decode(&mut cursor).unwrap();
            assert_eq!(value, expected, "decoding {expected}");
            assert!(cursor.is_empty(), "all bytes consumed for {expected}");
        }
    }

    #[test]
    fn encode_to_vec_matches_encode() {
        for &(value, expected) in KNOWN_ENCODINGS {
            let mut vec = Vec::new();
            encode_to_vec(value, &mut vec);
            assert_eq!(&vec, expected, "encode_to_vec for {value}");
        }
    }

    #[test]
    fn encode_to_vec_appends() {
        let mut vec = vec![0xAA, 0xBB];
        encode_to_vec(300, &mut vec);
        assert_eq!(vec, &[0xAA, 0xBB, 0xAC, 0x02]);
    }

    #[test]
    fn encode_returns_correct_length() {
        let mut buf = [0u8; 10];
        assert_eq!(encode(0, &mut buf), 1);
        assert_eq!(encode(127, &mut buf), 1);
        assert_eq!(encode(128, &mut buf), 2);
        assert_eq!(encode(16383, &mut buf), 2);
        assert_eq!(encode(16384, &mut buf), 3);
        assert_eq!(encode(u64::MAX, &mut buf), 10);
    }

    #[test]
    fn decode_advances_cursor_past_varint_only() {
        // Put a varint followed by trailing bytes; cursor should stop after the varint.
        let bytes = &[0xAC, 0x02, 0xFF, 0xFF];
        let mut cursor = &bytes[..];
        let value = decode(&mut cursor).unwrap();
        assert_eq!(value, 300);
        assert_eq!(cursor, &[0xFF, 0xFF]);
    }

    #[test]
    fn decode_multiple_varints_from_one_slice() {
        let mut buf = Vec::new();
        encode_to_vec(1, &mut buf);
        encode_to_vec(300, &mut buf);
        encode_to_vec(u64::MAX, &mut buf);

        let mut cursor = &buf[..];
        assert_eq!(decode(&mut cursor).unwrap(), 1);
        assert_eq!(decode(&mut cursor).unwrap(), 300);
        assert_eq!(decode(&mut cursor).unwrap(), u64::MAX);
        assert!(cursor.is_empty());
    }

    #[test]
    fn decode_empty_input() {
        let mut cursor: &[u8] = &[];
        let err = decode(&mut cursor).unwrap_err();
        assert!(matches!(err, Error::UnexpectedEndOfInput));
    }

    #[test]
    fn decode_truncated_input() {
        // 0x80 has continuation bit set but no following byte.
        let mut cursor: &[u8] = &[0x80];
        let err = decode(&mut cursor).unwrap_err();
        assert!(matches!(err, Error::UnexpectedEndOfInput));
    }

    #[test]
    fn decode_out_of_range() {
        // 11 bytes all with continuation bit set; exceeds 10-byte buffer.
        let bytes = [0x80u8; 11];
        let mut cursor = &bytes[..];
        let err = decode(&mut cursor).unwrap_err();
        assert!(matches!(err, Error::OutOfRange));
    }

    #[test]
    fn decoder_overflow_returns_out_of_range() {
        // Feed 10 continuation bytes, then one more should trigger OutOfRange.
        let mut decoder = Decoder::new();
        for _ in 0..10 {
            match decoder.feed(0x80) {
                DecoderOutput::NeedsMoreBytes(d) => decoder = d,
                other => panic!("expected NeedsMoreBytes, got {other:?}"),
            }
        }
        assert!(matches!(decoder.feed(0x80), DecoderOutput::OutOfRange));
    }

    #[test]
    #[should_panic]
    fn encode_panics_on_small_buffer() {
        let mut buf = [0u8; 1];
        encode(128, &mut buf); // needs 2 bytes
    }
}
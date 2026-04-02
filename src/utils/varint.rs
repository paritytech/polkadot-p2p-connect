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
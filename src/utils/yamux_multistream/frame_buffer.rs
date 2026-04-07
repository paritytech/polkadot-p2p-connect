use alloc::collections::VecDeque;
use crate::utils::varint;

/// A state machine which processes the bytes for a single mulistream,
/// taking in bytes as they are available and handing back frames as 
/// they become ready.
#[derive(Debug, Clone, Default)]
pub struct MultistreamFrameBuffer {
    // The first bytes in the multistream denote how many bytes the full
    // payload is, so we wait for these before handing anything back.
    needs: MultistreamFrameBufferNeeds,
    // Until we have what we need we buffer any bytes that we are given.
    buf: VecDeque<u8>,
    // Failed with `VarintOutOfRange` error so don't try anything more.
    failed: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("varint out of range")]
pub struct Error;

#[derive(Debug, Clone, Copy)]
enum MultistreamFrameBufferNeeds {
    DecodingLen(varint::Decoder),
    Len(usize),
}

impl Default for MultistreamFrameBufferNeeds {
    fn default() -> Self {
        Self::DecodingLen(varint::Decoder::new())
    }
}

impl MultistreamFrameBuffer {
    pub fn new() -> Self {
        Self {
            needs: MultistreamFrameBufferNeeds::default(),
            buf: VecDeque::new(),
            failed: false,
        }
    }

    /// Hand some bytes to this buffer.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.buf.extend(bytes);
    }

    /// Advance the state of the internal buffer, handing back messages once they are available.
    pub fn next(&mut self) -> Option<Result<impl ExactSizeIterator<Item=u8>, Error>> {
        if self.failed {
            return Some(Err(Error))
        }

        loop {
            match self.needs {
                // We're still decoding the length bytes. Try and decode another 
                // byte from the input.
                MultistreamFrameBufferNeeds::DecodingLen(decoder) => {
                    let Some(byte) = self.buf.pop_front() else {
                        return None
                    };
                    match decoder.feed(byte) {
                        varint::DecoderOutput::Value(len) => {
                            self.needs = MultistreamFrameBufferNeeds::Len(len as usize);
                            // Loop around again to see if we can return bytes already.
                        },
                        varint::DecoderOutput::NeedsMoreBytes(d) => {
                            self.needs = MultistreamFrameBufferNeeds::DecodingLen(d);
                            return None
                        },
                        varint::DecoderOutput::OutOfRange => {
                            return Some(Err(Error))
                        }
                    }
                },
                // We've decoded length; just waiting for enough buffer bytes
                // and then we'll hand an iterator to them back, clearing them
                // from our internal buf.
                MultistreamFrameBufferNeeds::Len(len) => {
                    if self.buf.len() >= len {
                        let iter = self.buf.drain(0..len);
                        self.needs = MultistreamFrameBufferNeeds::default();
                        return Some(Ok(iter))
                    } else {
                        return None
                    }
                }
            }
        }
    }
}
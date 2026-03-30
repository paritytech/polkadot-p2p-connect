use std::collections::VecDeque;
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

/// The output from calling [`MultistreamState::feed()`]
pub enum MultistreamFrameBufferOutput<BytesIter> {
    // Ready with the bytes for the next multistream frame.
    Ready(BytesIter),
    // Need more btyes before we can hand a frame back.
    NeedsMoreBytes,
    // Failed to decode the varint for a frame; no more progress can be made.
    VarintOutOfRange,
}

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

    /// Hand some bytes to this buffer. If we have enough bytes to
    /// hand back the next multistream frame then we hand it back,
    /// else give None back (we'll need more bytes).
    pub fn feed(&mut self, bytes: &[u8]) -> MultistreamFrameBufferOutput<impl ExactSizeIterator<Item=u8>> {
        if self.failed {
            return MultistreamFrameBufferOutput::VarintOutOfRange
        }

        self.buf.extend(bytes);

        loop {
            match self.needs {
                // We're still decoding the length bytes. Try and decode another 
                // byte from the input.
                MultistreamFrameBufferNeeds::DecodingLen(decoder) => {
                    let Some(byte) = self.buf.pop_front() else {
                        return MultistreamFrameBufferOutput::NeedsMoreBytes;
                    };
                    match decoder.feed(byte) {
                        varint::DecoderOutput::Value(len) => {
                            self.needs = MultistreamFrameBufferNeeds::Len(len as usize);
                            // Loop around again to see if we can return bytes already.
                        },
                        varint::DecoderOutput::NeedsMoreBytes(d) => {
                            self.needs = MultistreamFrameBufferNeeds::DecodingLen(d);
                            return MultistreamFrameBufferOutput::NeedsMoreBytes;
                        },
                        varint::DecoderOutput::OutOfRange => {
                            return MultistreamFrameBufferOutput::VarintOutOfRange;
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
                        return MultistreamFrameBufferOutput::Ready(iter)
                    } else {
                        return MultistreamFrameBufferOutput::NeedsMoreBytes
                    }
                }
            }
        }
    }
}
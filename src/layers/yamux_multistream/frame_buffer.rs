use crate::utils::varint;
use alloc::collections::VecDeque;

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

    /// Number of bytes currently stored in the internal buffer.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Hand some bytes to this buffer.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.buf.extend(bytes);
    }

    /// Advance the state of the internal buffer, handing back messages once they are available.
    pub fn next(&mut self) -> Option<Result<impl ExactSizeIterator<Item = u8>, Error>> {
        if self.failed {
            return Some(Err(Error));
        }

        loop {
            match self.needs {
                // We're still decoding the length bytes. Try and decode another
                // byte from the input.
                MultistreamFrameBufferNeeds::DecodingLen(decoder) => {
                    let byte = self.buf.pop_front()?;
                    match decoder.feed(byte) {
                        varint::DecoderOutput::Value(len) => {
                            self.needs = MultistreamFrameBufferNeeds::Len(len as usize);
                            // Loop around again to see if we can return bytes already.
                        }
                        varint::DecoderOutput::NeedsMoreBytes(d) => {
                            self.needs = MultistreamFrameBufferNeeds::DecodingLen(d);
                            // Loop around again to see if we can buffer more bytes.
                        }
                        varint::DecoderOutput::OutOfRange => {
                            self.failed = true;
                            return Some(Err(Error));
                        }
                    }
                }
                // We've decoded length; just waiting for enough buffer bytes
                // and then we'll hand an iterator to them back, clearing them
                // from our internal buf.
                MultistreamFrameBufferNeeds::Len(len) => {
                    if self.buf.len() >= len {
                        let iter = self.buf.drain(0..len);
                        self.needs = MultistreamFrameBufferNeeds::default();
                        return Some(Ok(iter));
                    } else {
                        return None;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::utils::varint;
    use alloc::{vec, vec::Vec};

    /// Helper: encode a payload as a multistream frame (varint length ++ payload).
    fn make_frame(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        varint::encode_to_vec(payload.len() as u64, &mut out);
        out.extend_from_slice(payload);
        out
    }

    /// Call next and collect the result.
    fn collect_next(buf: &mut MultistreamFrameBuffer) -> Option<Result<Vec<u8>, Error>> {
        buf.next().map(|r| r.map(|iter| iter.collect()))
    }

    #[test]
    fn decodes_frames() {
        let inputs = ["", "h", "hello"];

        for input in inputs {
            let mut buf = MultistreamFrameBuffer::new();
            buf.feed(&make_frame(input.as_bytes()));
            let output = collect_next(&mut buf).unwrap().unwrap();
            assert_eq!(
                input.as_bytes(),
                output,
                "output does not match input '{input}'"
            );
        }
    }

    #[test]
    fn empty_buffer_returns_none() {
        let mut buf = MultistreamFrameBuffer::new();
        assert!(buf.next().is_none());
    }

    #[test]
    fn two_frames_fed_together() {
        let mut buf = MultistreamFrameBuffer::new();
        let mut data = make_frame(b"abc");
        data.extend_from_slice(&make_frame(b"defgh"));
        buf.feed(&data);

        let first = collect_next(&mut buf).unwrap().unwrap();
        assert_eq!(first, b"abc");

        let second = collect_next(&mut buf).unwrap().unwrap();
        assert_eq!(second, b"defgh");

        assert!(buf.next().is_none());
    }

    #[test]
    fn three_frames_fed_together() {
        let mut buf = MultistreamFrameBuffer::new();
        let mut data = make_frame(b"x");
        data.extend_from_slice(&make_frame(b"yy"));
        data.extend_from_slice(&make_frame(b"zzz"));
        buf.feed(&data);

        assert_eq!(collect_next(&mut buf).unwrap().unwrap(), b"x");
        assert_eq!(collect_next(&mut buf).unwrap().unwrap(), b"yy");
        assert_eq!(collect_next(&mut buf).unwrap().unwrap(), b"zzz");
        assert!(buf.next().is_none());
    }

    #[test]
    fn byte_at_a_time() {
        let mut buf = MultistreamFrameBuffer::new();
        let frame = make_frame(b"hi");

        // Feed one byte at a time; only the last feed should produce a result.
        for &byte in &frame[..frame.len() - 1] {
            buf.feed(&[byte]);
            assert!(buf.next().is_none(), "should not be ready yet");
        }

        buf.feed(&frame[frame.len() - 1..]);
        let result = collect_next(&mut buf).unwrap().unwrap();
        assert_eq!(result, b"hi");
    }

    #[test]
    fn partial_length_then_rest() {
        // Use a payload large enough that the varint length is 2 bytes (>= 128).
        let payload = vec![0xABu8; 200];
        let frame = make_frame(&payload);

        let mut buf = MultistreamFrameBuffer::new();

        // Feed just the first byte of the varint (has continuation bit set).
        buf.feed(&frame[..1]);
        assert!(buf.next().is_none());

        // Feed the rest.
        buf.feed(&frame[1..]);
        let result = collect_next(&mut buf).unwrap().unwrap();
        assert_eq!(result, payload);
    }

    #[test]
    fn partial_payload_then_rest() {
        let mut buf = MultistreamFrameBuffer::new();
        let frame = make_frame(b"hello world");

        // Feed the length + partial payload.
        let split = 5; // varint is 1 byte, so this gives length + 4 payload bytes
        buf.feed(&frame[..split]);
        assert!(buf.next().is_none());

        // Feed the rest of the payload.
        buf.feed(&frame[split..]);
        let result = collect_next(&mut buf).unwrap().unwrap();
        assert_eq!(result, b"hello world");
    }

    #[test]
    fn second_frame_arrives_later() {
        let mut buf = MultistreamFrameBuffer::new();

        buf.feed(&make_frame(b"first"));
        assert_eq!(collect_next(&mut buf).unwrap().unwrap(), b"first");
        assert!(buf.next().is_none());

        buf.feed(&make_frame(b"second"));
        assert_eq!(collect_next(&mut buf).unwrap().unwrap(), b"second");
        assert!(buf.next().is_none());
    }

    #[test]
    fn payload_at_varint_boundary_128() {
        // 128 bytes requires a 2-byte varint.
        let payload = vec![0xFFu8; 128];
        let frame = make_frame(&payload);
        assert_eq!(frame[0], 0x80); // first varint byte: continuation bit set
        assert_eq!(frame[1], 0x01); // second varint byte

        let mut buf = MultistreamFrameBuffer::new();
        buf.feed(&frame);

        let result = collect_next(&mut buf).unwrap().unwrap();
        assert_eq!(result, payload);
    }

    #[test]
    fn varint_out_of_range_returns_error() {
        let mut buf = MultistreamFrameBuffer::new();
        // 11 continuation bytes is too many for a u64 varint.
        buf.feed(&[0x80; 11]);

        let result = collect_next(&mut buf).unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn after_error_always_returns_error() {
        let mut buf = MultistreamFrameBuffer::new();
        buf.feed(&[0x80; 11]);

        // First call: error.
        assert!(collect_next(&mut buf).unwrap().is_err());

        // Subsequent calls also return error, even after feeding valid data.
        buf.feed(&make_frame(b"valid"));
        assert!(collect_next(&mut buf).unwrap().is_err());
    }

    #[test]
    fn next_returns_exact_size_iterator() {
        let mut buf = MultistreamFrameBuffer::new();
        buf.feed(&make_frame(b"size check"));

        let iter = buf.next().unwrap().unwrap();
        assert_eq!(iter.len(), 10);
    }

    #[test]
    fn interleaved_feed_and_next() {
        let mut buf = MultistreamFrameBuffer::new();
        let frame1 = make_frame(b"aaa");
        let frame2 = make_frame(b"bb");

        // Feed half of frame1, then all of frame2 appended to second half of frame1.
        let split = 2;
        buf.feed(&frame1[..split]);
        assert!(buf.next().is_none());

        let mut rest = frame1[split..].to_vec();
        rest.extend_from_slice(&frame2);
        buf.feed(&rest);

        assert_eq!(collect_next(&mut buf).unwrap().unwrap(), b"aaa");
        assert_eq!(collect_next(&mut buf).unwrap().unwrap(), b"bb");
        assert!(buf.next().is_none());
    }

    #[test]
    fn large_payload() {
        let payload = vec![0x42u8; 16384]; // requires 3-byte varint
        let frame = make_frame(&payload);

        let mut buf = MultistreamFrameBuffer::new();
        buf.feed(&frame);

        let result = collect_next(&mut buf).unwrap().unwrap();
        assert_eq!(result.len(), 16384);
        assert!(result.iter().all(|&b| b == 0x42));
    }
}

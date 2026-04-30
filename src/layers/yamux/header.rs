use core::fmt::Write;

/// Yamux headers are 12 bytes exactly.
const YAMUX_FRAME_HEADER_SIZE: usize = 12;

/// We only support Yamux version 0 (the only version that exists at the time of writing)
const YAMUX_VERSION: u8 = 0;

/// A yamux frame header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct YamuxHeader {
    pub version: u8,
    pub frame_type: FrameType,
    pub flags: FrameFlags,
    pub stream_id: YamuxStreamId,
    pub length: u32,
}

impl YamuxHeader {
    /// The size of the [`YamuxHeader`] when encoded.
    pub const SIZE: usize = 12;

    /// Send data on some stream.
    pub fn send_data(stream_id: YamuxStreamId, data_len: u32) -> Self {
        YamuxHeader {
            version: YAMUX_VERSION,
            frame_type: FrameType::Data,
            flags: FrameFlags::empty(),
            stream_id,
            length: data_len,
        }
    }

    /// Open a new stream with the given ID.
    pub fn open_stream(stream_id: YamuxStreamId) -> Self {
        YamuxHeader {
            version: YAMUX_VERSION,
            frame_type: FrameType::WindowUpdate,
            flags: FrameFlag::Syn.into(),
            stream_id,
            length: 0,
        }
    }

    /// Accept an incoming stream
    pub fn accept_stream(stream_id: YamuxStreamId) -> Self {
        YamuxHeader {
            version: YAMUX_VERSION,
            frame_type: FrameType::WindowUpdate,
            flags: FrameFlag::Ack.into(),
            stream_id,
            length: 0,
        }
    }

    /// Send an RST flag to terminate / reject a stream
    pub fn reset_stream(stream_id: YamuxStreamId) -> Self {
        YamuxHeader {
            version: YAMUX_VERSION,
            frame_type: FrameType::WindowUpdate,
            flags: FrameFlag::Rst.into(),
            stream_id,
            length: 0,
        }
    }

    /// Send a FIN flag to indicate closure (peer can still send responses)
    pub fn close_stream(stream_id: YamuxStreamId) -> Self {
        YamuxHeader {
            version: YAMUX_VERSION,
            frame_type: FrameType::WindowUpdate,
            flags: FrameFlag::Fin.into(),
            stream_id,
            length: 0,
        }
    }

    /// Respond to a ping.
    pub fn pong(stream_id: YamuxStreamId, data: u32) -> Self {
        YamuxHeader {
            version: YAMUX_VERSION,
            frame_type: FrameType::Ping,
            flags: FrameFlag::Ack.into(),
            stream_id,
            length: data,
        }
    }

    /// Send a window update so that they can send more bytes.
    pub fn window_update(stream_id: YamuxStreamId, delta: u32) -> Self {
        YamuxHeader {
            version: YAMUX_VERSION,
            frame_type: FrameType::WindowUpdate,
            flags: FrameFlags::empty(),
            stream_id,
            length: delta,
        }
    }

    pub fn encode(&self) -> [u8; YAMUX_FRAME_HEADER_SIZE] {
        let mut buf = [0u8; YAMUX_FRAME_HEADER_SIZE];
        buf[0] = self.version;
        buf[1] = self.frame_type as u8;
        buf[2..4].copy_from_slice(&self.flags.0.to_be_bytes());
        buf[4..8].copy_from_slice(&self.stream_id.0.to_be_bytes());
        buf[8..12].copy_from_slice(&self.length.to_be_bytes());
        buf
    }

    pub fn decode(buf: &[u8; YAMUX_FRAME_HEADER_SIZE]) -> Result<Self, YamuxHeaderDecodeError> {
        let version = buf[0];
        if version != YAMUX_VERSION {
            return Err(YamuxHeaderDecodeError::InvalidVersion(version));
        }

        let frame_type =
            FrameType::from_u8(buf[1]).ok_or(YamuxHeaderDecodeError::InvalidFrameType(buf[1]))?;

        let flags = FrameFlags(u16::from_be_bytes([buf[2], buf[3]]));
        let stream_id = YamuxStreamId(u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]));
        let length = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);

        Ok(Self {
            version,
            frame_type,
            flags,
            stream_id,
            length,
        })
    }
}

/// An error decoding yamux headers.
#[derive(thiserror::Error, Debug)]
pub enum YamuxHeaderDecodeError {
    #[error("invalud yamux version; expected 0 but got {0}")]
    InvalidVersion(u8),
    #[error("invalud yamux frame type; got {0}")]
    InvalidFrameType(u8),
}

/// Opaque yamux stream ID
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct YamuxStreamId(u32);

impl YamuxStreamId {
    /// Create a new stream ID with a specific value.
    pub fn new(value: u32) -> Self {
        YamuxStreamId(value)
    }
    /// Return the first stream ID for clients to use (always an odd number)
    pub fn first() -> Self {
        YamuxStreamId(1)
    }
    /// Increment the stream ID to the next one for clients to use (always an odd number)
    pub fn increment(&mut self) {
        // This will eventually overflow in theory, but it'll take a long
        // time to get through 2 billion stream IDs so I'm not worried.
        self.0 = self.0.checked_add(2).expect("stream ID has overflown")
    }
    /// Is the stream ID an even number (ie a valid stream to be received)
    pub fn is_even(&self) -> bool {
        self.0 & 1 == 0
    }
    /// is the stream Id the session-wide identifier (0)?
    pub fn is_session_id(&self) -> bool {
        self.0 == 0
    }
}

impl core::fmt::Display for YamuxStreamId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

/// Yamux frame type
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum FrameType {
    /// Data being sent in this frame
    Data = 0x00,
    /// This frame is a window length update (header length == window size increase)
    WindowUpdate = 0x01,
    /// This frame is a ping (header length == opaque bytes to echo back)
    Ping = 0x02,
    /// Close the entire yamux session (header length == error code)
    GoAway = 0x03,
}

impl FrameType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x00 => Some(FrameType::Data),
            0x01 => Some(FrameType::WindowUpdate),
            0x02 => Some(FrameType::Ping),
            0x03 => Some(FrameType::GoAway),
            _ => None,
        }
    }
}

/// If [`FrameType::GoAway`] then the window length should resolve to this, to indicate why.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum GoAwayType {
    NormalTermination = 0x00,
    ProtocolError = 0x01,
    InternalError = 0x02,
}

impl GoAwayType {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0x00 => Some(GoAwayType::NormalTermination),
            0x01 => Some(GoAwayType::ProtocolError),
            0x02 => Some(GoAwayType::InternalError),
            _ => None,
        }
    }
}

/// Yamux frame flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FrameFlags(u16);

impl FrameFlags {
    pub fn empty() -> Self {
        FrameFlags(0)
    }
    pub fn is_open_new_stream(&self) -> bool {
        self.contains(FrameFlag::Syn)
            && !self.contains(FrameFlag::Rst)
            && !self.contains(FrameFlag::Fin)
    }
    pub fn contains(&self, flag: FrameFlag) -> bool {
        self.0 & (flag as u16) == (flag as u16)
    }
    fn iter(&self) -> impl Iterator<Item = FrameFlag> {
        let syn = self.contains(FrameFlag::Syn).then_some(FrameFlag::Syn);
        let ack = self.contains(FrameFlag::Ack).then_some(FrameFlag::Ack);
        let fin = self.contains(FrameFlag::Fin).then_some(FrameFlag::Fin);
        let rst = self.contains(FrameFlag::Rst).then_some(FrameFlag::Rst);
        syn.into_iter().chain(ack).chain(fin).chain(rst)
    }
}

impl core::fmt::Display for FrameFlags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut fst = true;
        for flag in self.iter() {
            if !fst {
                f.write_char('|')?;
            }
            fst = false;
            flag.fmt(f)?;
        }
        Ok(())
    }
}

/// Yamux frames have 0 or more flags to provide additional information.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum FrameFlag {
    /// Signals the start of a new stream
    Syn = 1,
    /// Acknowledge the start of a new stream
    Ack = 2,
    /// Perform a half-close of a stream (the sender is closing it)
    Fin = 4,
    /// close a stream immediately.
    Rst = 8,
}

impl From<FrameFlag> for FrameFlags {
    fn from(value: FrameFlag) -> Self {
        FrameFlags(value as u16)
    }
}

impl core::ops::BitOr<FrameFlag> for FrameFlag {
    type Output = FrameFlags;
    fn bitor(self, rhs: FrameFlag) -> Self::Output {
        FrameFlags(self as u16 | rhs as u16)
    }
}

impl core::ops::BitOr<FrameFlags> for FrameFlag {
    type Output = FrameFlags;
    fn bitor(self, rhs: FrameFlags) -> Self::Output {
        FrameFlags(self as u16 | rhs.0)
    }
}

impl core::ops::BitOr<FrameFlag> for FrameFlags {
    type Output = FrameFlags;
    fn bitor(self, rhs: FrameFlag) -> Self::Output {
        FrameFlags(self.0 | rhs as u16)
    }
}

impl core::fmt::Display for FrameFlag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FrameFlag::Syn => f.write_str("SYN"),
            FrameFlag::Ack => f.write_str("ACK"),
            FrameFlag::Fin => f.write_str("FIN"),
            FrameFlag::Rst => f.write_str("RST"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn roundtrip(header: YamuxHeader) {
        let encoded = header.encode();
        let decoded = YamuxHeader::decode(&encoded).unwrap();
        assert_eq!(header, decoded);
    }

    #[test]
    fn roundtrip_send_data() {
        roundtrip(YamuxHeader::send_data(YamuxStreamId(5), 1024));
    }

    #[test]
    fn roundtrip_open_stream() {
        roundtrip(YamuxHeader::open_stream(YamuxStreamId(1)));
    }

    #[test]
    fn roundtrip_accept_stream() {
        roundtrip(YamuxHeader::accept_stream(YamuxStreamId(2)));
    }

    #[test]
    fn roundtrip_reset_stream() {
        roundtrip(YamuxHeader::reset_stream(YamuxStreamId(3)));
    }

    #[test]
    fn roundtrip_close_stream() {
        roundtrip(YamuxHeader::close_stream(YamuxStreamId(3)));
    }

    #[test]
    fn roundtrip_pong() {
        roundtrip(YamuxHeader::pong(YamuxStreamId(0), 0xDEADBEEF));
    }

    #[test]
    fn roundtrip_window_update() {
        roundtrip(YamuxHeader::window_update(YamuxStreamId(7), 65535));
    }

    #[test]
    fn roundtrip_large_stream_id_and_length() {
        roundtrip(YamuxHeader::send_data(YamuxStreamId(u32::MAX), u32::MAX));
    }

    #[test]
    fn roundtrip_zero_values() {
        roundtrip(YamuxHeader::send_data(YamuxStreamId(0), 0));
    }
}

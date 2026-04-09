#[cfg(test)]
pub mod header;
#[cfg(not(test))]
mod header;

use header::{
    YamuxHeader,
    FrameType,
    FrameFlag,
    GoAwayType,
};
use alloc::vec;
use crate::utils::async_stream;
use alloc::collections::{BTreeMap, VecDeque};

// Re-export types in the API
pub use header::{
    YamuxStreamId,
    YamuxHeaderDecodeError,
};

const LOG_TARGET: &str = "yamux";

/// Both sides assume that streams begin with this window size.
const DEFAULT_WINDOW: usize = 256 * 1024; // 256KB

/// Limit the number of streams in a session to limit fallout from malicious connections.
const MAX_STREAMS: usize = 256;

/// If a single frame exceeds this then we terminate the session. Libp2p splits data over
/// 16kb frames to allow different sessions to interleave data and help prevent one session from
/// consuming all of the bandwidth, blocking data from others.
const MAX_FRAME_SIZE: usize = 512 * 1024; // 512kb

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("stream error sending or receiving bytes: {0}")]
    AsyncStream(#[from] async_stream::Error),
    #[error("cannot decode yamux header: {0}")]
    YamuxHeaderDecodeError(#[from] YamuxHeaderDecodeError),
    #[error("client tried to send message on stream ID {0}, which has been closed")]
    StreamNotFound(YamuxStreamId),
    #[error("server sent message on stream ID {0}, which it has already closed")]
    DataSentAfterFin(YamuxStreamId),
    #[error("server tried to initialise stream with invalid ID: {0}")]
    InvalidStreamId(YamuxStreamId),
    #[error("server tried to initialise stream with duplicate ID: {0}")]
    DuplicateStreamId(YamuxStreamId),
    #[error("server tried to send a frame with length {0} which is too large")]
    FrameTooLarge(usize),
    #[error("server sent a GO AWAY indicating that they experienced an internal error")]
    ServerInternalError,
    #[error("server sent a GO AWAY indicating that they experienced a protocol error")]
    ServerProtocolError,
    #[error("server sent a GO AWAY indicating some unspecified error with code {0}")]
    ServerUnknownError(u32),
    #[error("called YamuxSession::next on a session which has failed already")]
    AlreadyFailed,
}

/// This handles opening and closing multiple yamux streams on a single underlying [`AsyncStream`].
pub struct YamuxSession<S> {
    inner: S,
    next_stream_id: YamuxStreamId,
    streams: BTreeMap<YamuxStreamId, StreamState>,
    inbound_buf: [u8; MAX_FRAME_SIZE],
    failed: bool,
    output_buf: Option<InnerOutputState>,
}

/// Some output about a stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Output<'a> {
    /// Of of this stream.
    pub stream_id: YamuxStreamId,
    /// State of the stream.
    pub state: OutputState<'a>
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputState<'a> {
    /// This stream was opened by the remote.
    OpenedByRemote,
    /// Some data was received on this stream. It may be a new stream.
    Data(&'a [u8]),
    /// This stream was closed by the remote.
    ClosedByRemote,
}

enum InnerOutputState {
    OpenedByRemote(YamuxStreamId),
    Data(YamuxStreamId, usize),
    ClosedByRemote(YamuxStreamId),
}

/// The state of a single yamux stream.
struct StreamState {
    send_window: usize,
    recv_window: usize,
    remote_fin: bool,
    closed_by_us: bool,
    outbound_buf: VecDeque<BufferedOutboundMessage>,
}

enum BufferedOutboundMessage {
    Open,
    Data(VecDeque<u8>),
    Close,
}

impl StreamState {
    fn new() -> Self {
        StreamState { 
            send_window: DEFAULT_WINDOW,
            recv_window: DEFAULT_WINDOW as usize,
            outbound_buf: VecDeque::new(),
            remote_fin: false,
            closed_by_us: false,
        }
    }
}

impl<S: async_stream::AsyncStream> YamuxSession<S> {
    /// Create a new, empty Yamux session, given some internal read/write transport.
    pub fn new(stream: S) -> Self {
        Self {
            inner: stream,
            next_stream_id: YamuxStreamId::first(),
            streams: BTreeMap::new(),
            inbound_buf: [0u8; MAX_FRAME_SIZE],
            failed: false,
            output_buf: None,
        }
    }

    /// Schedule a new stream to be opened, returning the ID. Run [`Self::next()`] to
    /// progress this.
    pub fn open_stream(&mut self) -> YamuxStreamId {
        let stream_id = self.next_stream_id;
        self.next_stream_id.increment();

        // TODO: Right now we open streams and then can immediately push
        // data to them before any ACK from the other side. Wait for acks
        // first before sending any buffered messages to a stream? Yamux
        // allows data to be sent before ACK so right now we don't look for one.
        let stream = self.streams.entry(stream_id).or_insert_with(|| StreamState::new());
        stream.outbound_buf.push_back(BufferedOutboundMessage::Open);

        stream_id
    }

    /// Schedule some bytes to be sent on a given stream. Run [`Self::next()`] to 
    /// progress this. This respects the window size and may be slow to send if the
    /// receiver is slow or keeps the window size small on some stream.
    pub fn send_data(&mut self, stream_id: YamuxStreamId, data: impl IntoIterator<Item=u8>) -> Result<(), Error> {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return Err(Error::StreamNotFound(stream_id))
        };

        match stream.outbound_buf.back_mut() {
            Some(BufferedOutboundMessage::Data(buffered_data)) => {
                buffered_data.extend(data.into_iter());
            },
            Some(BufferedOutboundMessage::Open) | None => {
                stream.outbound_buf.push_back(BufferedOutboundMessage::Data(data.into_iter().collect()));
            }
            Some(BufferedOutboundMessage::Close) => {
                return Err(Error::StreamNotFound(stream_id))
            }
        }

        Ok(())
    }

    /// Schedule the stream to be closed. This waits for any other scheduled data to be
    /// sent before inititating the close. Run [`Self::next()`] to progress this. Until the
    /// close has been enacted, data on this stream may still be emitted.
    pub fn close_stream(&mut self, stream_id: YamuxStreamId) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            // If we can't find the stream, it's been closed anyway.
            return
        };

        if let Some(BufferedOutboundMessage::Close) = stream.outbound_buf.back() {
            // Already schedculed to close so do nothing.
        } else {
            stream.outbound_buf.push_back(BufferedOutboundMessage::Close);
        }
    }

    /// Schedule the stream to be closed immediately. This ignores any data scheduled to be sent
    /// and will close the stream as soon as [`Self::next()`] is called. No further data will
    /// be seen for this stream.
    pub fn close_stream_immediately(&mut self, stream_id: YamuxStreamId) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            // If we can't find the stream, it's been closed anyway.
            return
        };

        stream.outbound_buf.clear();
        stream.outbound_buf.push_back(BufferedOutboundMessage::Close);
        stream.closed_by_us = true;
    }

    /// Drive our session, returning the next chunk of bytes on any given stream.
    /// - Returns None when the session is finished and no more data will be handed back
    /// - Returns Some(Ok(id, bytes)) for each yamux frame we receive
    /// - Returns An error (and )
    pub async fn next(&mut self) -> Option<Result<Output<'_>, Error>> {
        if self.failed {
            return Some(Err(Error::AlreadyFailed));
        }

        // If an error; mark failure so we stop pulling bytes etc.
        let res = self.next_inner().await;
        if res.is_err() {
            self.failed = true;
        }

        // Now that we've done any mutation above, convert to our borrowing output.
        res.transpose().map(|res| {
            res.map(|inner_state| {
                match inner_state {
                    InnerOutputState::OpenedByRemote(id) => Output {
                        stream_id: id,
                        state: OutputState::OpenedByRemote,
                    },
                    InnerOutputState::ClosedByRemote(id) => Output {
                        stream_id: id,
                        state: OutputState::ClosedByRemote,
                    },
                    InnerOutputState::Data(id, len) => Output {
                        stream_id: id,
                        state: OutputState::Data(&self.inbound_buf[..len])
                    }
                }
            })
        })
    }

    // It's easier to return Result<Option> internally, but externally we want to look like
    // a stream and return Option<Result>, hence next vs next_inner.
    async fn next_inner(&mut self) -> Result<Option<InnerOutputState>, Error> {
        if let Some(msg) = self.output_buf.take() {
            return Ok(Some(msg))
        }

        loop {
            // First we try to send as much buffered data as we can.
            self.send_buffered_data().await?;

            // Now for receiving; we first download and decode the header:
            let hdr = {
                let mut hdr_buf = [0u8; YamuxHeader::SIZE];
                self.inner.read_exact(&mut hdr_buf).await?;
                YamuxHeader::decode(&hdr_buf)?
            };

            let stream_id = hdr.stream_id;
            let flags = hdr.flags;
            let length = hdr.length;

            // We then act based on the header frame type:
            match hdr.frame_type {
                FrameType::Data => {
                    tracing::debug!(target: LOG_TARGET, "received DATA on stream {stream_id} (flags: {flags}, length: {length})");
                    let data_len = length as usize;

                    // Reject and error out if frame too large; could be malicious.
                    if data_len > MAX_FRAME_SIZE {
                        return Err(Error::FrameTooLarge(data_len));
                    }

                    // Read the data bytes into our buffer. For almost anything we do, we
                    // need to drain these bytes else we'll be out of sync for the next loop.
                    self.inner.read_exact(&mut self.inbound_buf[..data_len]).await?;

                    // Get hold of the stream details, opening a new stream if we need to.
                    let (stream, is_new) = if flags.is_open_new_stream() {
                        let Some(stream) = self.negotiate_new_stream_request(&hdr).await? else { continue };
                        (stream, true)
                    } else if let Some(stream) = self.streams.get_mut(&stream_id) {
                        (stream, false)
                    } else {
                        continue
                    };

                    // If they sent Fin then error. If we closed then we'll remove later, but ignore
                    // anything else immediately.
                    if stream.remote_fin {
                        return Err(Error::DataSentAfterFin(stream_id));
                    }
                    if stream.closed_by_us {
                        continue
                    }

                    // Decrement the receive window given the data.
                    stream.recv_window = stream.recv_window.saturating_sub(data_len);

                    if flags.contains(FrameFlag::Rst) {
                        // If the stream is RST then we remove it immediately; they won't send any
                        // more but they also won't accept any more from us. We still must return any final data.
                        self.streams.remove(&stream_id);
                        self.output_buf = Some(InnerOutputState::ClosedByRemote(stream_id));
                    } else if flags.contains(FrameFlag::Fin) {
                        // If the stream is FIN then we mark that the remote won't send more.
                        // Deliver the data first, then ClosedByRemote on the next call.
                        stream.remote_fin = true;
                        self.output_buf = Some(InnerOutputState::ClosedByRemote(stream_id));
                    } else if stream.recv_window < MAX_FRAME_SIZE / 2 {
                        // We don't care if they send more bytes than our window size, but we do ensure the window
                        // size is always at least MAX_FRAME_SIZE and so if their window size gets to 1/2 then
                        // bump it up so that they keep sending.
                        let delta = MAX_FRAME_SIZE - stream.recv_window;
                        stream.recv_window += delta;
                        tracing::debug!(target: LOG_TARGET, "sending WINDOW UPDATE on stream {stream_id}: +{delta}");
                        self.inner.write_all(&YamuxHeader::window_update(stream_id, delta as u32).encode()).await?;
                    }

                    if data_len == 0 && is_new {
                        // No data to send but new stream, so just send opened message
                        return Ok(Some(InnerOutputState::OpenedByRemote(stream_id)));
                    } else if data_len == 0 && !is_new {
                        // No data to send, and not a new stream, so nothing to send.
                        continue
                    } else if data_len > 0 && is_new {
                        // Data to send and a new stream, so send opened and then data next
                        self.output_buf = Some(InnerOutputState::Data(stream_id, data_len));
                        return Ok(Some(InnerOutputState::OpenedByRemote(stream_id)));
                    } else if data_len > 0 && !is_new {
                        // Data to send and not new stream so just send out the data.
                        return Ok(Some(InnerOutputState::Data(stream_id, data_len)));
                    }
                },
                FrameType::WindowUpdate => {
                    tracing::debug!(target: LOG_TARGET, "received WINDOW UPDATE on stream {stream_id} (flags: {flags}, delta: {length})");

                    // Get hold of the stream details, opening a new stream if we need to.
                    let (stream, is_new) = if flags.is_open_new_stream() {
                        let Some(stream) = self.negotiate_new_stream_request(&hdr).await? else { continue };
                        (stream, true)
                    } else if let Some(stream) = self.streams.get_mut(&stream_id) {
                        (stream, false)
                    } else {
                        continue
                    };

                    // Ignore/don't emit any messages if we closed the stream already.
                    if stream.closed_by_us {
                        continue
                    }

                    // Update stream window size.
                    stream.send_window = stream.send_window.saturating_add(hdr.length as usize);

                    if flags.contains(FrameFlag::Rst) {
                        // If the stream is RST then we remove all knowledge of it as it is closed.
                        // It doesn't matter what the window update header says.
                        self.streams.remove(&stream_id);
                        return Ok(Some(InnerOutputState::ClosedByRemote(stream_id)))
                    } else if flags.contains(FrameFlag::Fin) {
                        // If FIN was sent then they won't send more so we acknowledge,
                        // but we'll still accept window updates and can send to them.
                        // If the stream is SYN then it's just been opened; tell the user this.
                        stream.remote_fin = true;
                        return Ok(Some(InnerOutputState::ClosedByRemote(stream_id)))
                    } else if is_new {
                        // This is a new stream, so emit a message that it is opened. New streams
                        // will never conflict with RST/FIN flags.
                        return Ok(Some(InnerOutputState::OpenedByRemote(stream_id)))
                    }
                },
                FrameType::Ping => {
                    tracing::debug!(target: LOG_TARGET, "received PING on stream {stream_id} (flags: {flags})");

                    // Ignore if stream has gone away.
                    if !stream_id.is_session_id() && !self.streams.contains_key(&stream_id) {
                        continue
                    };

                    // Return a pong to the ping.
                    tracing::debug!(target: LOG_TARGET, "sending PONG on stream {stream_id}");
                    self.inner.write_all(&YamuxHeader::pong(stream_id, hdr.length).encode()).await?;
                },
                FrameType::GoAway => {
                    tracing::debug!(target: LOG_TARGET, "received GO AWAY on stream {stream_id} (flags: {flags})");

                    // Ignore if stream not found (it may have gone away already)
                    if !self.streams.contains_key(&stream_id) {
                        continue
                    };

                    match GoAwayType::from_u32(hdr.length) {
                        // we're being told to go away due to an error:
                        Some(GoAwayType::InternalError) => {
                            return Err(Error::ServerInternalError);
                        },
                        Some(GoAwayType::ProtocolError) => {
                            return Err(Error::ServerProtocolError);
                        },
                        None => {
                            return Err(Error::ServerUnknownError(hdr.length));
                        },
                        // normal termination, all ok:
                        Some(GoAwayType::NormalTermination) => {
                            return Ok(None);
                        },
                    }
                },
            }
        }
    }

    /// Send as much of our buffered data as we can until we run out of window size or data on each stream.
    async fn send_buffered_data(&mut self) -> Result<(), Error> {
        let mut streams_to_close = vec![];

        for (&stream_id, stream) in &mut self.streams {
            let Some(buffered_msg) = stream.outbound_buf.pop_front() else {
                continue
            };

            match buffered_msg {
                BufferedOutboundMessage::Open => {
                    tracing::debug!(target: LOG_TARGET, "opening stream {stream_id}");
                    self.inner.write_all(&YamuxHeader::open_stream(stream_id).encode()).await?;
                },
                BufferedOutboundMessage::Close => {
                    tracing::debug!(target: LOG_TARGET, "closing stream {stream_id}");
                    self.inner.write_all(&YamuxHeader::reject_stream(stream_id).encode()).await?;
                    streams_to_close.push(stream_id);
                },
                BufferedOutboundMessage::Data(mut outbound_data) => {
                    let bytes_to_send = usize::min(stream.send_window, outbound_data.len());
                    tracing::debug!(target: LOG_TARGET, "sending {bytes_to_send} DATA bytes on stream {stream_id}");
        
                    // If we can't send anything on this stream, put the message back on the queue and move on. 
                    // We need a window update before we can send more data on this stream.
                    if bytes_to_send == 0 {
                        stream.outbound_buf.push_back(BufferedOutboundMessage::Data(outbound_data));
                        continue
                    }
        
                    // VecDeque is two slices internally, so we work out how many bytes of
                    // each slice we need to send to satisfy the above.
                    let (a, b) = outbound_data.as_slices();
                    let a_len = usize::min(bytes_to_send, a.len());
                    let b_len = bytes_to_send.saturating_sub(a.len());
        
                    // Send the appropriate header and then the corresponding bytes. Because
                    // we have two slices above, we break this into two sends if necessary.
                    self.inner.write_all(&YamuxHeader::send_data(stream_id, a_len as u32).encode()).await?;
                    self.inner.write_all(&a[..a_len]).await?;
                    if b_len > 0 {
                        self.inner.write_all(&YamuxHeader::send_data(stream_id, b_len as u32).encode()).await?;
                        self.inner.write_all(&b[..b_len]).await?;
                    }
        
                    // If we didn't send all of the bytes, then drain what we did send and put
                    // the message back onto the queue to be tried again later.
                    if bytes_to_send != outbound_data.len() {
                        outbound_data.drain(..bytes_to_send);
                        stream.outbound_buf.push_back(BufferedOutboundMessage::Data(outbound_data));
                    }
                }
            }
        }

        // Remove our stored stream info for any streams we've closed on our end.
        for stream_id in streams_to_close {
            self.streams.remove(&stream_id);
        }
        Ok(())
    }

    /// Accept or reject a new stream. This should be called when the frame type is Data or WindowUpdate,
    /// and when the Syn flag is given.
    /// 
    /// - If this returns true, then the new session has been established and normal logic can continue
    ///   to consume the data for instance.
    /// - If this returns false, then we can ignore this frame and loop around to the next. This code will
    ///   consume any data from the rejected frame if necessary.
    /// - If this returns an error, then we are done and should stop immediately.
    async fn negotiate_new_stream_request(&mut self, hdr: &YamuxHeader) -> Result<Option<&mut StreamState>, Error> {
        let stream_id = hdr.stream_id;

        // they should always send even stream ID numbers, and not the session ID number.
        if !stream_id.is_even() || stream_id.is_session_id() {
            self.inner.write_all(&YamuxHeader::reject_stream(stream_id).encode()).await?;
            tracing::debug!(target: LOG_TARGET, "rejecting incoming stream {stream_id}: invalid stream ID");
            return Err(Error::InvalidStreamId(stream_id))
        }

        // if they try to open too many streams, reject it but all good protocol wise.
        if self.streams.len() > MAX_STREAMS {
            self.inner.write_all(&YamuxHeader::reject_stream(stream_id).encode()).await?;
            tracing::debug!(target: LOG_TARGET, "rejecting incoming stream {stream_id}: too many open streams");
            return Ok(None)
        }

        // If they send a duplicate stream ID, that is a protocol error so bail.
        if self.streams.contains_key(&stream_id) {
            self.inner.write_all(&YamuxHeader::reject_stream(stream_id).encode()).await?;
            tracing::debug!(target: LOG_TARGET, "rejecting incoming stream {stream_id}: duplicate stream ID");
            return Err(Error::InvalidStreamId(stream_id))
        }

        // All good; accept new stream. Don't process any data etc; that's for the main loop.
        tracing::debug!(target: LOG_TARGET, "accepting incoming stream {stream_id}");
        self.inner.write_all(&YamuxHeader::accept_stream(stream_id).encode()).await?;

        Ok(Some(self.streams.entry(stream_id).or_insert_with(StreamState::new)))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        AsyncStream, 
        layers::yamux::header::FrameFlags,
        utils::{
            testing::{block_on, MockStream, MockStreamHandle},
        }
    };

    /// Poll the [`YamuxSession`], expecting it to return an [`Output`].
    fn next_expecting_output<S: AsyncStream>(yamux: &mut YamuxSession<S>) -> Output<'_> {
        block_on(yamux.next())
            .expect("expecting Ready, not Pending, from YamuxSession::next()")
            .expect("output should not be None")
            .expect("output should not be Err")
    }

    /// Read a Yamux header from the [`MockStreamHandle`], consuming the bytes.
    fn read_header(handle: &mut MockStreamHandle) -> YamuxHeader {
        YamuxHeader::decode(&handle.drain(YamuxHeader::SIZE).try_into().unwrap()).unwrap()
    }

    #[test]
    fn new_streams_can_be_opened() {
        let stream = MockStream::new();
        let mut handle = stream.handle();

        let mut yamux = YamuxSession::new(stream);

        // Open, then send data.
        let data = b"Hello world";
        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(2)).encode());
        handle.extend(YamuxHeader::send_data(YamuxStreamId::new(2), data.len() as u32).encode());
        handle.extend(data.iter().copied());

        // First next() notifies us the stream was opened.
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(2));
        assert_eq!(res.state, OutputState::OpenedByRemote);

        // Our Yamux handler will have accepted the stream, replying.
        let response = read_header(&mut handle);
        assert_eq!(response, YamuxHeader::accept_stream(YamuxStreamId::new(2)));

        // Second next() returns the data.
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(2));
        assert_eq!(res.state, OutputState::Data(data));

        // If we call next() again we'll get Pending back as we're waiting for more data
        assert!(block_on(yamux.next()).is_none());
    }

    #[test]
    fn new_streams_can_be_opened_with_data() {
        let stream = MockStream::new();
        let mut handle = stream.handle();

        let mut yamux = YamuxSession::new(stream);

        // Open and send data in one frame
        let data = b"Hello world";
        let header = YamuxHeader {
            version: 0,
            frame_type: FrameType::Data,
            flags: FrameFlag::Syn.into(),
            stream_id: YamuxStreamId::new(2),
            length: data.len() as u32
        };

        handle.extend(header.encode());
        handle.extend(data.iter().copied());

        // First next() notifies us the stream was opened.
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(2));
        assert_eq!(res.state, OutputState::OpenedByRemote);

        // Our Yamux handler will have accepted the stream, replying.
        let response = read_header(&mut handle);
        assert_eq!(response, YamuxHeader::accept_stream(YamuxStreamId::new(2)));

        // Second next() returns the data.
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(2));
        assert_eq!(res.state, OutputState::Data(data));

        // If we call next() again we'll get Pending back as we're waiting for more data
        assert!(block_on(yamux.next()).is_none());
    }

    #[test]
    fn ping_receives_pong() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream);

        // First open a stream so we have one active.
        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(2)).encode());

        // Send a ping on the session ID (stream 0).
        let ping = YamuxHeader {
            version: 0,
            frame_type: FrameType::Ping,
            flags: FrameFlags::empty(),
            stream_id: YamuxStreamId::new(0),
            length: 0xDEADBEEF,
        };
        handle.extend(ping.encode());

        // First drive: processes open_stream, returns OpenedByRemote.
        let _ = block_on(yamux.next());
        // Second drive: processes ping, sends pong, returns Pending.
        let _ = block_on(yamux.next());

        // We should have sent: accept stream, pong.
        let accept = read_header(&mut handle);
        assert_eq!(accept, YamuxHeader::accept_stream(YamuxStreamId::new(2)));
        let pong = read_header(&mut handle);
        assert_eq!(pong, YamuxHeader::pong(YamuxStreamId::new(0), 0xDEADBEEF));
    }

    #[test]
    fn remote_fin_closes_stream() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream);

        // Open a stream.
        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(2)).encode());

        // Send data with FIN flag.
        let data = b"goodbye";
        let header = YamuxHeader {
            version: 0,
            frame_type: FrameType::Data,
            flags: FrameFlag::Fin.into(),
            stream_id: YamuxStreamId::new(2),
            length: data.len() as u32,
        };
        handle.extend(header.encode());
        handle.extend(data.iter().copied());

        // First next() notifies us the stream was opened.
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(2));
        assert_eq!(res.state, OutputState::OpenedByRemote);

        // Second next() returns the data.
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(2));
        assert_eq!(res.state, OutputState::Data(data));

        // Third next() returns ClosedByRemote (buffered from FIN).
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(2));
        assert_eq!(res.state, OutputState::ClosedByRemote);
    }

    #[test]
    fn remote_rst_closes_stream() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream);

        // Open a stream.
        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(2)).encode());

        // Send a data frame with RST flag and some data.
        let data = b"reset";
        let header = YamuxHeader {
            version: 0,
            frame_type: FrameType::Data,
            flags: FrameFlag::Rst.into(),
            stream_id: YamuxStreamId::new(2),
            length: data.len() as u32,
        };
        handle.extend(header.encode());
        handle.extend(data.iter().copied());

        // First next() notifies us the stream was opened.
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(2));
        assert_eq!(res.state, OutputState::OpenedByRemote);

        // Second next() returns the data.
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(2));
        assert_eq!(res.state, OutputState::Data(data));

        // Third next() returns ClosedByRemote (buffered from RST).
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(2));
        assert_eq!(res.state, OutputState::ClosedByRemote);
    }

    #[test]
    fn window_update_with_fin_returns_closed() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream);

        // Open a stream first.
        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(2)).encode());

        // Opening a stream now emits OpenedByRemote.
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(2));
        assert_eq!(res.state, OutputState::OpenedByRemote);

        // Now send a WindowUpdate with FIN.
        let header = YamuxHeader {
            version: 0,
            frame_type: FrameType::WindowUpdate,
            flags: FrameFlag::Fin.into(),
            stream_id: YamuxStreamId::new(2),
            length: 0,
        };
        handle.extend(header.encode());

        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(2));
        assert_eq!(res.state, OutputState::ClosedByRemote);
    }

    #[test]
    fn window_update_with_rst_returns_closed() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream);

        // Open a stream.
        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(2)).encode());
        let data = b"x";
        handle.extend(YamuxHeader::send_data(YamuxStreamId::new(2), data.len() as u32).encode());
        handle.extend(data.iter().copied());

        let _ = block_on(yamux.next()); // OpenedByRemote
        let _ = block_on(yamux.next()); // Data

        // Send a WindowUpdate with RST.
        let header = YamuxHeader {
            version: 0,
            frame_type: FrameType::WindowUpdate,
            flags: FrameFlag::Rst.into(),
            stream_id: YamuxStreamId::new(2),
            length: 0,
        };
        handle.extend(header.encode());

        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(2));
        assert_eq!(res.state, OutputState::ClosedByRemote);
    }

    #[test]
    fn odd_stream_id_from_remote_is_rejected() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream);

        // Remote tries to open stream with odd ID (only even IDs valid from remote).
        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(3)).encode());

        let res = block_on(yamux.next())
            .expect("expecting output")
            .expect("not None");

        assert!(matches!(res, Err(Error::InvalidStreamId(id)) if id == YamuxStreamId::new(3)));
    }

    #[test]
    fn session_id_zero_from_remote_is_rejected() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream);

        // Remote tries to open stream with ID 0 (session ID, invalid).
        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(0)).encode());

        let res = block_on(yamux.next())
            .expect("expecting output")
            .expect("not None");

        assert!(matches!(res, Err(Error::InvalidStreamId(id)) if id == YamuxStreamId::new(0)));
    }

    #[test]
    fn duplicate_stream_id_from_remote_is_rejected() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream);

        // Open stream 2 normally.
        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(2)).encode());
        let data = b"first";
        handle.extend(YamuxHeader::send_data(YamuxStreamId::new(2), data.len() as u32).encode());
        handle.extend(data.iter().copied());

        let _ = block_on(yamux.next()); // OpenedByRemote
        let _ = block_on(yamux.next()); // Data

        // Remote tries to open stream 2 again.
        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(2)).encode());

        let res = block_on(yamux.next())
            .expect("expecting output")
            .expect("not None");

        assert!(matches!(res, Err(Error::InvalidStreamId(id)) if id == YamuxStreamId::new(2)));
    }

    #[test]
    fn goaway_normal_termination_returns_none() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream);

        // Open stream so GoAway finds it.
        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(2)).encode());
        let data = b"x";
        handle.extend(YamuxHeader::send_data(YamuxStreamId::new(2), data.len() as u32).encode());
        handle.extend(data.iter().copied());
        let _ = block_on(yamux.next()); // OpenedByRemote
        let _ = block_on(yamux.next()); // Data

        // Send GoAway with normal termination.
        let goaway = YamuxHeader {
            version: 0,
            frame_type: FrameType::GoAway,
            flags: FrameFlags::empty(),
            stream_id: YamuxStreamId::new(2),
            length: GoAwayType::NormalTermination as u32,
        };
        handle.extend(goaway.encode());

        let res = block_on(yamux.next())
            .expect("expecting output");
        assert!(res.is_none(), "GoAway NormalTermination should yield None");
    }

    #[test]
    fn goaway_internal_error() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream);

        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(2)).encode());
        let data = b"x";
        handle.extend(YamuxHeader::send_data(YamuxStreamId::new(2), data.len() as u32).encode());
        handle.extend(data.iter().copied());
        let _ = block_on(yamux.next()); // OpenedByRemote
        let _ = block_on(yamux.next()); // Data

        let goaway = YamuxHeader {
            version: 0,
            frame_type: FrameType::GoAway,
            flags: FrameFlags::empty(),
            stream_id: YamuxStreamId::new(2),
            length: GoAwayType::InternalError as u32,
        };
        handle.extend(goaway.encode());

        let res = block_on(yamux.next())
            .expect("expecting output")
            .expect("not None");
        assert!(matches!(res, Err(Error::ServerInternalError)));
    }

    #[test]
    fn goaway_protocol_error() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream);

        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(2)).encode());
        let data = b"x";
        handle.extend(YamuxHeader::send_data(YamuxStreamId::new(2), data.len() as u32).encode());
        handle.extend(data.iter().copied());
        let _ = block_on(yamux.next()); // OpenedByRemote
        let _ = block_on(yamux.next()); // Data

        let goaway = YamuxHeader {
            version: 0,
            frame_type: FrameType::GoAway,
            flags: FrameFlags::empty(),
            stream_id: YamuxStreamId::new(2),
            length: GoAwayType::ProtocolError as u32,
        };
        handle.extend(goaway.encode());

        let res = block_on(yamux.next())
            .expect("expecting output")
            .expect("not None");
        assert!(matches!(res, Err(Error::ServerProtocolError)));
    }

    #[test]
    fn goaway_unknown_error() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream);

        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(2)).encode());
        let data = b"x";
        handle.extend(YamuxHeader::send_data(YamuxStreamId::new(2), data.len() as u32).encode());
        handle.extend(data.iter().copied());
        let _ = block_on(yamux.next()); // OpenedByRemote
        let _ = block_on(yamux.next()); // Data

        let goaway = YamuxHeader {
            version: 0,
            frame_type: FrameType::GoAway,
            flags: FrameFlags::empty(),
            stream_id: YamuxStreamId::new(2),
            length: 0xFF,
        };
        handle.extend(goaway.encode());

        let res = block_on(yamux.next())
            .expect("expecting output")
            .expect("not None");
        assert!(matches!(res, Err(Error::ServerUnknownError(0xFF))));
    }

    #[test]
    fn data_after_fin_is_error() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream);

        // Open stream first, then send data with FIN, then more data (which is invalid).
        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(2)).encode());

        let data = b"bye";
        let header = YamuxHeader {
            version: 0,
            frame_type: FrameType::Data,
            flags: FrameFlag::Fin.into(),
            stream_id: YamuxStreamId::new(2),
            length: data.len() as u32,
        };
        handle.extend(header.encode());
        handle.extend(data.iter().copied());

        let bad_data = b"bad";
        handle.extend(YamuxHeader::send_data(YamuxStreamId::new(2), bad_data.len() as u32).encode());
        handle.extend(bad_data.iter().copied());

        // First call: returns OpenedByRemote.
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(2));
        assert_eq!(res.state, OutputState::OpenedByRemote);

        // Second call: returns the data from the FIN frame.
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(2));
        assert_eq!(res.state, OutputState::Data(data));

        // Third call: returns ClosedByRemote (buffered from FIN).
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.state, OutputState::ClosedByRemote);

        // Fourth call: remote sent data after FIN, which is an error.
        let res = block_on(yamux.next())
            .expect("expecting output")
            .expect("not None");
        assert!(matches!(res, Err(Error::DataSentAfterFin(id)) if id == YamuxStreamId::new(2)));
    }

    #[test]
    fn frame_too_large_is_error() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream);

        // Open a stream.
        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(2)).encode());
        let data = b"x";
        handle.extend(YamuxHeader::send_data(YamuxStreamId::new(2), data.len() as u32).encode());
        handle.extend(data.iter().copied());
        let _ = block_on(yamux.next()); // OpenedByRemote
        let _ = block_on(yamux.next()); // Data

        // Send a data header with length exceeding MAX_FRAME_SIZE.
        let too_large = (MAX_FRAME_SIZE + 1) as u32;
        handle.extend(YamuxHeader::send_data(YamuxStreamId::new(2), too_large).encode());

        let res = block_on(yamux.next())
            .expect("expecting output")
            .expect("not None");
        assert!(matches!(res, Err(Error::FrameTooLarge(n)) if n == MAX_FRAME_SIZE + 1));
    }

    #[test]
    fn already_failed_after_error() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream);

        // Cause an error: odd stream ID from remote.
        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(3)).encode());
        let _ = block_on(yamux.next());

        // Subsequent calls should return AlreadyFailed.
        let res = block_on(yamux.next())
            .expect("expecting output")
            .expect("not None");
        assert!(matches!(res, Err(Error::AlreadyFailed)));
    }

    #[test]
    fn client_open_stream_sends_syn() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream);

        let id = yamux.open_stream();
        assert_eq!(id, YamuxStreamId::new(1));

        // Provide something for next() to read so we drive send_buffered_data.
        // Since nothing is available to read, next() will pend after flushing outbound.
        let result = block_on(yamux.next());
        assert!(result.is_none(), "should pend since no inbound data");

        // Verify the SYN was written.
        let hdr = read_header(&mut handle);
        assert_eq!(hdr, YamuxHeader::open_stream(YamuxStreamId::new(1)));
    }

    #[test]
    fn client_open_stream_ids_increment() {
        let stream = MockStream::new();
        let mut yamux = YamuxSession::new(stream);

        let id1 = yamux.open_stream();
        let id2 = yamux.open_stream();
        let id3 = yamux.open_stream();

        assert_eq!(id1, YamuxStreamId::new(1));
        assert_eq!(id2, YamuxStreamId::new(3));
        assert_eq!(id3, YamuxStreamId::new(5));
    }

    #[test]
    fn send_data_on_nonexistent_stream_is_error() {
        let stream = MockStream::new();
        let mut yamux = YamuxSession::new(stream);

        let res = yamux.send_data(YamuxStreamId::new(99), b"hello".iter().copied());
        assert!(matches!(res, Err(Error::StreamNotFound(id)) if id == YamuxStreamId::new(99)));
    }

    #[test]
    fn client_sends_data_on_stream() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream);

        let id = yamux.open_stream();
        yamux.send_data(id, b"hello".iter().copied()).unwrap();

        // First drive sends the Open header (one buffered msg per stream per call).
        let _ = block_on(yamux.next());
        let open_hdr = read_header(&mut handle);
        assert_eq!(open_hdr, YamuxHeader::open_stream(id));

        // Second drive sends the Data header + payload.
        let _ = block_on(yamux.next());
        let data_hdr = read_header(&mut handle);
        assert_eq!(data_hdr, YamuxHeader::send_data(id, 5));

        let data_bytes = handle.drain(5);
        assert_eq!(&data_bytes, b"hello");
    }

    #[test]
    fn close_stream_sends_rst() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream);

        let id = yamux.open_stream();
        yamux.close_stream(id);

        // First drive sends the Open header.
        let _ = block_on(yamux.next());
        let open_hdr = read_header(&mut handle);
        assert_eq!(open_hdr, YamuxHeader::open_stream(id));

        // Second drive sends the Close (RST).
        let _ = block_on(yamux.next());
        let close_hdr = read_header(&mut handle);
        assert_eq!(close_hdr, YamuxHeader::reject_stream(id));
    }

    #[test]
    fn close_stream_immediately_skips_buffered_data() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream);

        let id = yamux.open_stream();
        yamux.send_data(id, b"this should be dropped".iter().copied()).unwrap();
        yamux.close_stream_immediately(id);

        // Drive the session.
        let _ = block_on(yamux.next());

        // Should only see the RST, not the open or data.
        let close_hdr = read_header(&mut handle);
        assert_eq!(close_hdr, YamuxHeader::reject_stream(id));

        // Nothing else should have been written.
        let remaining = handle.drain_all();
        assert!(remaining.is_empty(), "no other frames should be sent");
    }

    #[test]
    fn multiple_streams_interleave() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream);

        // Remote opens two streams, sends data on each.
        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(2)).encode());
        let data_a = b"stream2";
        handle.extend(YamuxHeader::send_data(YamuxStreamId::new(2), data_a.len() as u32).encode());
        handle.extend(data_a.iter().copied());

        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(4)).encode());
        let data_b = b"stream4";
        handle.extend(YamuxHeader::send_data(YamuxStreamId::new(4), data_b.len() as u32).encode());
        handle.extend(data_b.iter().copied());

        // First next: stream 2 opened.
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(2));
        assert_eq!(res.state, OutputState::OpenedByRemote);

        // Second next: stream 2 data.
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(2));
        assert_eq!(res.state, OutputState::Data(data_a));

        // Third next: stream 4 opened.
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(4));
        assert_eq!(res.state, OutputState::OpenedByRemote);

        // Fourth next: stream 4 data.
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(4));
        assert_eq!(res.state, OutputState::Data(data_b));
    }

    #[test]
    fn zero_length_data_frame_is_skipped() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream);

        // Open stream, then send a zero-length data frame, then a real one.
        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(2)).encode());
        handle.extend(YamuxHeader::send_data(YamuxStreamId::new(2), 0).encode());
        let data = b"real data";
        handle.extend(YamuxHeader::send_data(YamuxStreamId::new(2), data.len() as u32).encode());
        handle.extend(data.iter().copied());

        // First next: stream opened.
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(2));
        assert_eq!(res.state, OutputState::OpenedByRemote);

        // Second next: should skip the zero-length frame and return the real data.
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(2));
        assert_eq!(res.state, OutputState::Data(data));
    }

    #[test]
    fn window_update_is_processed() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream);

        // Open a remote stream normally.
        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(2)).encode());
        let data = b"x";
        handle.extend(YamuxHeader::send_data(YamuxStreamId::new(2), data.len() as u32).encode());
        handle.extend(data.iter().copied());
        let _ = block_on(yamux.next()); // OpenedByRemote
        let _ = block_on(yamux.next()); // Data

        // Send a window update followed by more data. The window update should
        // be silently processed (no output) and then the data arrives normally.
        handle.extend(YamuxHeader::window_update(YamuxStreamId::new(2), 4096).encode());
        let data2 = b"after update";
        handle.extend(YamuxHeader::send_data(YamuxStreamId::new(2), data2.len() as u32).encode());
        handle.extend(data2.iter().copied());

        let res = block_on(yamux.next())
            .expect("expecting output")
            .expect("not None")
            .expect("not Err");
        assert_eq!(res.stream_id, YamuxStreamId::new(2));
        assert_eq!(res.state, OutputState::Data(data2));
    }
}
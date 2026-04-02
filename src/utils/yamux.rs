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
pub struct Output<'a> {
    /// Of of this stream.
    pub stream_id: YamuxStreamId,
    /// State of the stream.
    pub state: OutputState<'a>
}

pub enum OutputState<'a> {
    /// Some data was received on this stream. It may be a new stream.
    Data(&'a [u8]),
    /// This stream was closed by the remote.
    ClosedByRemote,
}

enum InnerOutputState {
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
    Close
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
    pub fn open_stream(&mut self) -> Result<YamuxStreamId, Error> {
        let stream_id = self.next_stream_id;
        self.next_stream_id.increment();

        // TODO: Right now we open streams and then can immediately push
        // data to them before any ACK from the other side. Wait for acks
        // first before sending any buffered messages to a stream? Yamux
        // allows data to be sent before ACK so right now we don't look for one.
        let stream = self.streams.entry(stream_id).or_insert_with(|| StreamState::new());
        stream.outbound_buf.push_back(BufferedOutboundMessage::Open);

        Ok(stream_id)
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
    pub fn close_stream(&mut self, stream_id: YamuxStreamId) -> Result<(), Error> {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return Err(Error::StreamNotFound(stream_id))
        };

        if let Some(BufferedOutboundMessage::Close) = stream.outbound_buf.back() {
            // Already schedculed to close so do nothing.
        } else {
            stream.outbound_buf.push_back(BufferedOutboundMessage::Close);
        }
        Ok(())
    }

    /// Schedule the stream to be closed immediately. This ignores any data scheduled to be sent
    /// and will close the stream as soon as [`Self::next()`] is called. No further data will
    /// be seen for this stream.
    pub fn close_stream_immediately(&mut self, stream_id: YamuxStreamId) -> Result<(), Error> {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return Err(Error::StreamNotFound(stream_id))
        };

        stream.outbound_buf.clear();
        stream.outbound_buf.push_back(BufferedOutboundMessage::Close);
        stream.closed_by_us = true;

        Ok(())
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

            // We then act based on the header frame type:
            match hdr.frame_type {
                FrameType::Data => {
                    let data_len = hdr.length as usize;

                    // Reject and error out if frame too large; could be malicious.
                    if data_len > MAX_FRAME_SIZE {
                        return Err(Error::FrameTooLarge(data_len));
                    }

                    // Read the data bytes into our buffer. For almost anything we do, we
                    // need to drain these bytes else we'll be out of sync for the next loop.
                    self.inner.read_exact(&mut self.inbound_buf[..data_len]).await?;

                    // If new stream, negotiate and loop if it was rejected.
                    if hdr.flags.contains(FrameFlag::Syn) && !self.negotiate_new_stream_request(&hdr).await? {
                        continue
                    }

                    // Get stream details. If not found then it may be a bad sender but may also be
                    // that we have closed the stream recently. If remote_fin was sent then we should
                    // definitely get no more data on it.
                    let Some(stream) = self.streams.get_mut(&hdr.stream_id) else {
                        continue
                    };
                    if stream.remote_fin {
                        return Err(Error::DataSentAfterFin(hdr.stream_id));
                    }
                    if stream.closed_by_us {
                        continue
                    }

                    // We don't care if they send more bytes than our window size, but we do ensure the window
                    // size is always at least MAX_FRAME_SIZE and so if their window size gets to 1/2 then
                    // bump it up so that they keep sending.
                    stream.recv_window = stream.recv_window.saturating_sub(data_len);
                    if stream.recv_window < MAX_FRAME_SIZE / 2 {
                        let delta = MAX_FRAME_SIZE - stream.recv_window;
                        self.inner.write_all(&YamuxHeader::window_update(hdr.stream_id, delta as u32).encode()).await?;
                    }

                    // Read the frame into our buffer and return a reference to the bytes read.
                    self.inner.read_exact(&mut self.inbound_buf[..data_len]).await?;

                    // If the stream is FIN then we mark that the remote won't send more.
                    // If the stream is RST then we remove it immediately; they won't send any
                    // more but they also won't accept any more from us.
                    // If the stream is SYN then it's just been opened; tell the user this.
                    if hdr.flags.contains(FrameFlag::Rst) {
                        self.streams.remove(&hdr.stream_id);
                        self.output_buf = Some(InnerOutputState::ClosedByRemote(hdr.stream_id));
                    } else if hdr.flags.contains(FrameFlag::Fin) {
                        stream.remote_fin = true;
                        self.output_buf = Some(InnerOutputState::ClosedByRemote(hdr.stream_id));
                    }

                    return Ok(Some(InnerOutputState::Data(hdr.stream_id, data_len)))
                },
                FrameType::WindowUpdate => {
                    // If the stream is RST then we remove all knowledge of it as it is closed.
                    // It doesn't matter what the window update header says.
                    if hdr.flags.contains(FrameFlag::Rst) {
                        self.streams.remove(&hdr.stream_id);
                        return Ok(Some(InnerOutputState::ClosedByRemote(hdr.stream_id)))
                    }

                    // If new stream, negotiate and loop if it was rejected.
                    if hdr.flags.contains(FrameFlag::Syn) && !self.negotiate_new_stream_request(&hdr).await? {
                        continue
                    }

                    // Get stream details. The stream may have been closed, so just drain the relevant bytes
                    // and ignore this message for now.
                    let Some(stream) = self.streams.get_mut(&hdr.stream_id) else {
                        self.drain_bytes_from_stream(hdr.length as usize).await?;
                        continue
                    };
                    if stream.closed_by_us {
                        continue
                    }

                    // Update stream window size.
                    stream.send_window = stream.send_window.saturating_add(hdr.length as usize);

                    // If FIN was sent then they won't send more so we acknowledge,
                    // but we'll still accept window updates and can send to them.
                    // If the stream is SYN then it's just been opened; tell the user this.
                    if hdr.flags.contains(FrameFlag::Fin) {
                        stream.remote_fin = true;
                        return Ok(Some(InnerOutputState::ClosedByRemote(hdr.stream_id)))
                    }
                },
                FrameType::Ping => {
                    // Ignore if stream has gone away.
                    if !self.streams.contains_key(&hdr.stream_id) {
                        continue
                    };

                    // Return a pong to the ping.
                    self.inner.write_all(&YamuxHeader::pong(hdr.stream_id, hdr.length).encode()).await?;
                },
                FrameType::GoAway => {
                    // Ignore if stream not found (it may have gone away already)
                    if !self.streams.contains_key(&hdr.stream_id) {
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
                    self.inner.write_all(&YamuxHeader::open_stream(stream_id).encode()).await?;
                },
                BufferedOutboundMessage::Close => {
                    self.inner.write_all(&YamuxHeader::reject_stream(stream_id).encode()).await?;
                    streams_to_close.push(stream_id);
                },
                BufferedOutboundMessage::Data(mut outbound_data) => {
                    let bytes_to_send = usize::min(stream.send_window, outbound_data.len());
        
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
    async fn negotiate_new_stream_request(&mut self, hdr: &YamuxHeader) -> Result<bool, Error> {
        // they should always send even stream ID numbers, and not the session ID number.
        if !hdr.stream_id.is_even() || hdr.stream_id.is_session_id() {
            self.inner.write_all(&YamuxHeader::reject_stream(hdr.stream_id).encode()).await?;
            return Err(Error::InvalidStreamId(hdr.stream_id))
        }

        // if they try to open too many streams, reject it but all good protocol wise.
        if self.streams.len() > MAX_STREAMS {
            self.inner.write_all(&YamuxHeader::reject_stream(hdr.stream_id).encode()).await?;
            return Ok(false)
        }

        // If they send a duplicate stream ID, that is a protocol error so bail.
        if self.streams.contains_key(&hdr.stream_id) {
            self.inner.write_all(&YamuxHeader::reject_stream(hdr.stream_id).encode()).await?;
            return Err(Error::InvalidStreamId(hdr.stream_id))
        }

        // All good; accept new stream. Don't process any data etc; that's for the main loop.
        self.inner.write_all(&YamuxHeader::accept_stream(hdr.stream_id).encode()).await?;
        self.streams.insert(hdr.stream_id, StreamState::new());

        Ok(true)
    }

    /// Drains the given number of bytes from the stream, discarding them.
    async fn drain_bytes_from_stream(&mut self, mut remaining: usize) -> Result<(), Error> {
        const MAX_DRAIN_BUF_SIZE: usize = 32 * 1024;
        let mut buf = [0u8; MAX_DRAIN_BUF_SIZE];

        while remaining > 0 {
            // drain via the stack while we can:
            if remaining >= MAX_DRAIN_BUF_SIZE {
                self.inner.read_exact(&mut buf).await?;
                remaining -= MAX_DRAIN_BUF_SIZE;
            } else {
                let mut buf = vec![0u8; remaining];
                self.inner.read_exact(&mut buf).await?;
                remaining = 0;
            }
        }

        Ok(())
    }
}

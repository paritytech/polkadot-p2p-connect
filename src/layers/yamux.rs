#[cfg(test)]
pub mod header;
#[cfg(not(test))]
mod header;

use crate::utils::async_stream::{AsyncRead, AsyncReadError, AsyncWrite, AsyncWriteError};
use crate::utils::read_write_join::ReadWriteJoin;
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::{Ref, RefCell};
use header::{FrameFlag, FrameType, GoAwayType, YamuxHeader};

// Re-export types in the API
pub use header::{YamuxHeaderDecodeError, YamuxStreamId};

const LOG_TARGET: &str = "yamux";

/// Both sides assume that streams begin with this window size.
const DEFAULT_WINDOW: usize = 256 * 1024; // 256KB

/// Limit the number of streams in a session to limit fallout from malicious connections.
const MAX_STREAMS: usize = 256;

/// If a single frame exceeds this then we terminate the session. Libp2p splits data over
/// 16kb frames to allow different sessions to interleave data and help prevent one session from
/// consuming all of the bandwidth, blocking data from others.
const MAX_FRAME_SIZE: usize = 512 * 1024; // 512kb

/// We will send at most this much data at a time on some stream.
const MAX_SEND_SIZE: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[error("stream error receiving bytes: {0}")]
    AsyncRead(#[from] AsyncReadError),
    #[error("stream error sending bytes: {0}")]
    AsyncWrite(#[from] AsyncWriteError),
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
}

/// This handles opening and closing multiple yamux streams given an [`AsyncRead`] and [`AsyncWrite`] stream.
pub struct YamuxSession<R, W> {
    // AsyncReader and AsyncWriter:
    writer: Rc<RefCell<W>>,
    reader: Rc<RefCell<R>>,
    // This holds futures for reading and writing that will be run concurrently.
    read_write_join: ReadWriteJoin<Option<Output>, Error>,
    next_stream_id: YamuxStreamId,
    // This could be on the stack but we want it to be MAX_FRAME_SIZE (ie 512kb)
    // in length so box it to reduce the chance of stack overflows.
    inbound_buf: Rc<RefCell<Box<[u8; MAX_FRAME_SIZE]>>>,
    finished: bool,
    // State shared between our read and write futures as they progress concurrently.
    // It must NOT be held across await points else both futures could borrow it mutably
    // at the same time, leading to a runtime panic.
    shared_state: Rc<RefCell<SharedState>>,
    // The amount of data available on the inbound_buf.
    data_len: usize,
}

struct SharedState {
    streams: BTreeMap<YamuxStreamId, StreamState>,
    write_buf: VecDeque<u8>,
    output_buf: Option<Output>,
}

/// Some output about a stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Output {
    /// Of of this stream.
    pub stream_id: YamuxStreamId,
    /// State of the stream.
    pub state: OutputState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputState {
    /// This stream was opened by the remote.
    OpenedByRemote,
    /// Some data was received on this stream.
    /// Use [`YamuxSession::data()`] to retrieve it.
    Data(usize),
    /// This stream was closed by the remote.
    ClosedByRemote,
}

/// Our output data. Available from [`YamuxSession::data()`].
/// This derefs to a byte slice and can be treated as such.
#[derive(Debug)]
pub struct OutputData<'a> {
    buf: Ref<'a, Box<[u8; MAX_FRAME_SIZE]>>,
    len: usize,
}
impl<'a> PartialEq for OutputData<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.len == other.len && self.buf[..self.len] == other.buf[..other.len]
    }
}
impl<'a> core::ops::Deref for OutputData<'a> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.buf[0..self.len]
    }
}

/// The state of a single yamux stream.
struct StreamState {
    send_window: usize,
    recv_window: usize,
    open_state: OpenState,
    outbound_buf: VecDeque<BufferedOutboundMessage>,
}

#[derive(Copy, Clone, Debug)]
enum OpenState {
    Open,
    FinByUs,
    FinByThem,
    Reset,
}

impl OpenState {
    fn set_fin_by_them(self) -> Self {
        match self {
            OpenState::Open | OpenState::FinByThem => OpenState::FinByThem,
            OpenState::Reset | OpenState::FinByUs => OpenState::Reset,
        }
    }
    fn set_fin_by_us(self) -> Self {
        match self {
            OpenState::Open | OpenState::FinByUs => OpenState::FinByUs,
            OpenState::Reset | OpenState::FinByThem => OpenState::Reset,
        }
    }
}

enum BufferedOutboundMessage {
    Accept,
    Open,
    Data(VecDeque<u8>),
    WindowUpdate(u32),
    Close,
    Reset,
}

impl StreamState {
    fn new() -> Self {
        StreamState {
            send_window: DEFAULT_WINDOW,
            recv_window: DEFAULT_WINDOW,
            outbound_buf: VecDeque::new(),
            open_state: OpenState::Open,
        }
    }
}

impl<R: AsyncRead + 'static, W: AsyncWrite + 'static> YamuxSession<R, W> {
    /// Create a new, empty Yamux session, given some internal read/write transport.
    pub fn new(reader: R, writer: W) -> Self {
        Self {
            reader: Rc::new(RefCell::new(reader)),
            writer: Rc::new(RefCell::new(writer)),
            read_write_join: ReadWriteJoin::new(),
            next_stream_id: YamuxStreamId::first(),
            // We rely on the compiler eliding the stack allocating and allocating
            // directly on the heap here to avoid possible stack overflows, but this
            // seems to be the case.
            inbound_buf: Rc::new(RefCell::new(Box::new([0u8; MAX_FRAME_SIZE]))),
            finished: false,
            // State held by read and write futures.
            shared_state: Rc::new(RefCell::new(SharedState {
                streams: BTreeMap::new(),
                write_buf: VecDeque::new(),
                output_buf: None,
            })),
            data_len: 0,
        }
    }

    /// Schedule a new stream to be opened, returning the ID. Run [`Self::next()`] to
    /// progress this.
    pub fn open_stream(&mut self) -> YamuxStreamId {
        let mut shared_state = self.shared_state.borrow_mut();

        let stream_id = self.next_stream_id;
        self.next_stream_id.increment();

        // Note: Right now we open streams and then can immediately push
        // data to them before any ACK from the other side. Yamux allows
        // data to be sent before ACK so right now we allow this.
        let stream = shared_state
            .streams
            .entry(stream_id)
            .or_insert_with(StreamState::new);
        stream.outbound_buf.push_back(BufferedOutboundMessage::Open);

        stream_id
    }

    /// Schedule some bytes to be sent on a given stream. Run [`Self::next()`] to
    /// progress this. This respects the window size and may be slow to send if the
    /// receiver is slow or keeps the window size small on some stream.
    pub fn send_data(&mut self, stream_id: YamuxStreamId, data: &[u8]) -> Result<(), Error> {
        let mut shared_state = self.shared_state.borrow_mut();

        let Some(stream) = shared_state.streams.get_mut(&stream_id) else {
            return Err(Error::StreamNotFound(stream_id));
        };

        match stream.outbound_buf.back_mut() {
            Some(BufferedOutboundMessage::Data(buffered_data)) => {
                buffered_data.extend(data);
            }
            Some(BufferedOutboundMessage::Accept)
            | Some(BufferedOutboundMessage::Open)
            | Some(BufferedOutboundMessage::WindowUpdate(_))
            | None => {
                let mut buf = VecDeque::with_capacity(data.len());
                buf.extend(data);
                stream
                    .outbound_buf
                    .push_back(BufferedOutboundMessage::Data(buf));
            }
            Some(BufferedOutboundMessage::Close | BufferedOutboundMessage::Reset) => {
                return Err(Error::StreamNotFound(stream_id));
            }
        }

        Ok(())
    }

    /// Schedule the stream to be closed. This waits for any other scheduled data to be
    /// sent before initiating the close. Run [`Self::next()`] to progress this. We can still
    /// be sent data because we have only closed our side.
    pub fn close_stream(&mut self, stream_id: YamuxStreamId) {
        let mut shared_state = self.shared_state.borrow_mut();

        let Some(stream) = shared_state.streams.get_mut(&stream_id) else {
            // If we can't find the stream, it's been closed anyway.
            return;
        };

        if let Some(BufferedOutboundMessage::Close) = stream.outbound_buf.back() {
            // Already scheduled to close so do nothing.
        } else {
            stream
                .outbound_buf
                .push_back(BufferedOutboundMessage::Close);
        }
    }

    /// Schedule the stream to be closed immediately. This ignores any data scheduled to be sent
    /// and will close the stream as soon as [`Self::next()`] is called. We can still be sent data
    /// because we have only closed our side.
    // Not used right now but kept here in case we decide to use it somewhere.
    #[allow(dead_code)]
    pub fn close_stream_immediately(&mut self, stream_id: YamuxStreamId) {
        let mut shared_state = self.shared_state.borrow_mut();

        let Some(stream) = shared_state.streams.get_mut(&stream_id) else {
            // If we can't find the stream, it's been closed anyway.
            return;
        };

        stream.open_state = stream.open_state.set_fin_by_us();
        stream.outbound_buf.clear();
        stream
            .outbound_buf
            .push_back(BufferedOutboundMessage::Close);
    }

    /// Schedule the stream to be closed immediately via the more aggressive RST flag. This ignores any
    /// data scheduled to be sent and will close the stream as soon as [`Self::next()`] is called. No further
    /// data will be seen for this stream.
    pub fn reset_stream_immediately(&mut self, stream_id: YamuxStreamId) {
        Self::reset_stream_immediately_with_shared_state(
            &mut self.shared_state.borrow_mut(),
            stream_id,
        )
    }

    /// Retrieve the output data. If the output from calling [`Self::next()`] contained [`OutputState::Data`]
    /// then this will correspond to the associated data bytes. Otherwise, this will return an empty slice.
    pub fn data(&self) -> OutputData<'_> {
        let buf = self.inbound_buf.borrow();
        OutputData {
            buf,
            len: self.data_len,
        }
    }

    fn reset_stream_immediately_with_shared_state(
        shared_state: &mut SharedState,
        stream_id: YamuxStreamId,
    ) {
        let Some(stream) = shared_state.streams.get_mut(&stream_id) else {
            // If we can't find the stream, it's been closed anyway.
            return;
        };

        stream.outbound_buf.clear();
        stream
            .outbound_buf
            .push_back(BufferedOutboundMessage::Reset);

        // Mark both sides as reset, so we ignore anything.
        stream.open_state = OpenState::Reset;
    }

    /// Drive our session, returning the next chunk of bytes on any given stream.
    /// - Returns None when the session is finished and no more data will be handed back
    /// - Returns Some(Ok(id, bytes)) for each yamux frame we receive
    /// - Returns An error (and )
    pub async fn next(&mut self) -> Option<Result<Output, Error>> {
        // No data available on the data buffer by default now.
        self.data_len = 0;

        // Don't progress if already errored or closed
        if self.finished {
            return None;
        }

        // Fetch the next output and handle errors
        let output = match self.next_inner().await {
            Err(e) => {
                self.finished = true;
                return Some(Err(e));
            }
            Ok(None) => {
                self.finished = true;
                return None;
            }
            Ok(Some(output)) => output,
        };

        // Store the number of data bytes available.
        if let OutputState::Data(len) = output.state {
            self.data_len = len;
        }

        Some(Ok(output))
    }

    // It's easier to return Result<Option> internally, but externally we want to look like
    // a stream and return Option<Result>, hence next vs next_inner.
    //
    // Reader/Writer things are Rc<RefCell<..>> because we need to hand ownership of them
    // into the future, such that if the future is dropped then YamuxSession still owns them too.
    // Only one future will ever use each and so it's ok if they pass over await points.
    // shared_state on the other hand is used in both futures and must NOT pass await points.
    #[allow(clippy::await_holding_refcell_ref)]
    async fn next_inner(&mut self) -> Result<Option<Output>, Error> {
        self.read_write_join
            .call(
                || {
                    let reader = self.reader.clone();
                    let read_buf = self.inbound_buf.clone();
                    let reader_state = self.shared_state.clone();
                    async move {
                        Self::read_next(
                            &mut reader.borrow_mut(),
                            &reader_state,
                            &mut read_buf.borrow_mut(),
                        )
                        .await
                    }
                },
                || {
                    let writer = self.writer.clone();
                    let writer_state = self.shared_state.clone();
                    async move { Self::write_next(&mut writer.borrow_mut(), &writer_state).await }
                },
            )
            .await
    }

    async fn read_next(
        reader: &mut R,
        shared_state: &RefCell<SharedState>,
        buf: &mut [u8; MAX_FRAME_SIZE],
    ) -> Result<Option<Output>, Error> {
        loop {
            // Check if a buffered output is waiting (e.g. Data queued after OpenedByRemote).
            if let Some(output) = shared_state.borrow_mut().output_buf.take() {
                return Ok(Some(output));
            }

            // We first download and decode the header:
            let hdr = {
                let mut hdr_buf = [0u8; YamuxHeader::SIZE];
                reader.read_exact(&mut hdr_buf).await?;
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
                    reader.read_exact(&mut buf[..data_len]).await?;

                    // Borrow after the await to avoid holding across await point.
                    let mut shared_state = shared_state.borrow_mut();

                    // Get hold of the stream details, opening a new stream if we need to.
                    let (stream, is_new) = if flags.is_open_new_stream() {
                        let Some(stream) =
                            Self::negotiate_new_stream_request(&hdr, &mut shared_state)?
                        else {
                            continue;
                        };
                        (stream, true)
                    } else if let Some(stream) = shared_state.streams.get_mut(&stream_id) {
                        (stream, false)
                    } else {
                        continue;
                    };

                    // If they sent Fin then error. If we closed then we'll remove later, but ignore
                    // anything else immediately.
                    match stream.open_state {
                        OpenState::FinByThem => {
                            // They sent fin so they shouldn't then send data.
                            return Err(Error::DataSentAfterFin(stream_id));
                        }
                        OpenState::Reset => {
                            // RST but we still know about stream so it hasn't kicked in yet.
                            // just ignore any data on the stream.
                            continue;
                        }
                        OpenState::FinByUs | OpenState::Open => {
                            // All good; we can still receive data.
                        }
                    }

                    // Decrement the receive window given the data. We don't care if they send more data
                    // (though we'll error if MAX_FRAME_SIZE is exceeded, above) but do ensure to send them
                    // window updates to allow them to keep sending data.
                    stream.recv_window = stream.recv_window.saturating_sub(data_len);

                    if flags.contains(FrameFlag::Rst) {
                        // If the stream is RST then we remove it immediately; they won't send any
                        // more but they also won't accept any more from us. We still must return any final data.
                        shared_state.streams.remove(&stream_id);
                        shared_state.output_buf = Some(Output {
                            stream_id,
                            state: OutputState::ClosedByRemote,
                        });
                    } else if flags.contains(FrameFlag::Fin) {
                        // If the stream is FIN then we mark that the remote won't send more.
                        // Deliver the data first, then ClosedByRemote on the next call.
                        stream.open_state = OpenState::FinByThem;
                        shared_state.output_buf = Some(Output {
                            stream_id,
                            state: OutputState::ClosedByRemote,
                        });
                    } else if stream.recv_window < MAX_FRAME_SIZE / 2 {
                        // We don't care if they send more bytes than our window size, but we do ensure the window
                        // size is always at least MAX_FRAME_SIZE and so if their window size gets to 1/2 then
                        // bump it up so that they keep sending.
                        let delta = MAX_FRAME_SIZE - stream.recv_window;
                        stream.recv_window += delta;
                        stream
                            .outbound_buf
                            .push_back(BufferedOutboundMessage::WindowUpdate(delta as u32));
                    }

                    if data_len == 0 && is_new {
                        // No data to send but new stream, so just send opened message
                        return Ok(Some(Output {
                            stream_id,
                            state: OutputState::OpenedByRemote,
                        }));
                    } else if data_len == 0 && !is_new {
                        // No data to send, and not a new stream, so nothing to send.
                        continue;
                    } else if data_len > 0 && is_new {
                        // Data to send and a new stream, so send opened and then data next
                        shared_state.output_buf = Some(Output {
                            stream_id,
                            state: OutputState::Data(data_len),
                        });
                        return Ok(Some(Output {
                            stream_id,
                            state: OutputState::OpenedByRemote,
                        }));
                    } else if data_len > 0 && !is_new {
                        // Data to send and not new stream so just send out the data.
                        return Ok(Some(Output {
                            stream_id,
                            state: OutputState::Data(data_len),
                        }));
                    }
                }
                FrameType::WindowUpdate => {
                    tracing::debug!(target: LOG_TARGET, "received WINDOW UPDATE on stream {stream_id} (flags: {flags}, delta: {length})");
                    let mut shared_state = shared_state.borrow_mut();

                    // Get hold of the stream details, opening a new stream if we need to.
                    let (stream, is_new) = if flags.is_open_new_stream() {
                        let Some(stream) =
                            Self::negotiate_new_stream_request(&hdr, &mut shared_state)?
                        else {
                            continue;
                        };
                        (stream, true)
                    } else if let Some(stream) = shared_state.streams.get_mut(&stream_id) {
                        (stream, false)
                    } else {
                        continue;
                    };

                    // Ignore/don't emit any messages if stream is fully closed already.
                    if matches!(stream.open_state, OpenState::Reset) {
                        continue;
                    }

                    // Update stream window size.
                    stream.send_window = stream.send_window.saturating_add(hdr.length as usize);

                    if flags.contains(FrameFlag::Rst) {
                        // If the stream is RST then we remove all knowledge of it as it is closed.
                        // It doesn't matter what the window update header says.
                        shared_state.streams.remove(&stream_id);
                        return Ok(Some(Output {
                            stream_id,
                            state: OutputState::ClosedByRemote,
                        }));
                    } else if flags.contains(FrameFlag::Fin) {
                        // If FIN was sent then they won't send more so we acknowledge,
                        // but we'll still accept window updates and can send to them.
                        // If the stream is SYN then it's just been opened; tell the user this.
                        stream.open_state = stream.open_state.set_fin_by_them();
                        return Ok(Some(Output {
                            stream_id,
                            state: OutputState::ClosedByRemote,
                        }));
                    } else if is_new {
                        // This is a new stream, so emit a message that it is opened. New streams
                        // will never conflict with RST/FIN flags.
                        return Ok(Some(Output {
                            stream_id,
                            state: OutputState::OpenedByRemote,
                        }));
                    }
                }
                FrameType::Ping => {
                    tracing::debug!(target: LOG_TARGET, "received PING on stream {stream_id} (flags: {flags})");
                    let mut shared_state = shared_state.borrow_mut();

                    // Only stream 0 (session stream) should send this. If another stream
                    // sends this then abort it as it did something wrong.
                    if !stream_id.is_session_id() {
                        Self::reset_stream_immediately_with_shared_state(
                            &mut shared_state,
                            stream_id,
                        );
                        continue;
                    }

                    // Return a pong to the ping.
                    tracing::debug!(target: LOG_TARGET, "sending PONG on stream {stream_id}");
                    shared_state
                        .write_buf
                        .extend(&YamuxHeader::pong(stream_id, hdr.length).encode());
                }
                FrameType::GoAway => {
                    tracing::debug!(target: LOG_TARGET, "received GO AWAY on stream {stream_id} (flags: {flags})");
                    let mut shared_state = shared_state.borrow_mut();

                    // Only stream 0 (session stream) should send this. If another stream
                    // sends this then abort it as it did something wrong.
                    if !stream_id.is_session_id() {
                        Self::reset_stream_immediately_with_shared_state(
                            &mut shared_state,
                            stream_id,
                        );
                        continue;
                    }

                    match GoAwayType::from_u32(hdr.length) {
                        // we're being told to go away due to an error:
                        Some(GoAwayType::InternalError) => {
                            return Err(Error::ServerInternalError);
                        }
                        Some(GoAwayType::ProtocolError) => {
                            return Err(Error::ServerProtocolError);
                        }
                        None => {
                            return Err(Error::ServerUnknownError(hdr.length));
                        }
                        // normal termination, all ok:
                        Some(GoAwayType::NormalTermination) => {
                            return Ok(None);
                        }
                    }
                }
            }
        }
    }

    /// Send as much of our buffered data as we can, draining any write buffers.
    async fn write_next(writer: &mut W, shared_state: &RefCell<SharedState>) -> Result<(), Error> {
        // Drain the global write buf first. This is for things like PONGs or
        // resetting streams we haven't accepted.
        let global_write_buf = core::mem::take(&mut shared_state.borrow_mut().write_buf);
        if !global_write_buf.is_empty() {
            let (a, b) = global_write_buf.as_slices();
            writer.write_all(a).await?;
            writer.write_all(b).await?;
        }

        // Find and handle all of our stream-specific messages. Make sure not to hold
        // shared_state across any await points.
        let mut bytes_to_write = Vec::new();
        let mut streams_to_remove = Vec::new();

        {
            let mut old_bytes_to_write_len = usize::MAX;
            let mut shared_state = shared_state.borrow_mut();
            let streams = &mut shared_state.streams;

            // Buffer as much as we possibly can to write, because when we are done here we need to wait for the
            // next read event to come in before we can write more. This might be an issue if we are waiting
            // a while for a read event but haven't actually written everything we can write yet.
            while bytes_to_write.len() != old_bytes_to_write_len {
                // Record how many bytes were written at the start of this loop. If we write
                // more bytes in this loop then we'll end up looping again. If we don't then
                // there is nothing more we can write yet so we end.
                old_bytes_to_write_len = bytes_to_write.len();

                for (&stream_id, stream) in streams.iter_mut() {
                    let Some(msg) = stream.outbound_buf.pop_front() else {
                        continue;
                    };

                    match msg {
                        BufferedOutboundMessage::Accept => {
                            tracing::debug!(target: LOG_TARGET, "accepting stream {stream_id}");
                            bytes_to_write.extend(YamuxHeader::accept_stream(stream_id).encode());
                        }
                        BufferedOutboundMessage::Open => {
                            tracing::debug!(target: LOG_TARGET, "opening stream {stream_id}");
                            bytes_to_write.extend(YamuxHeader::open_stream(stream_id).encode());
                        }
                        BufferedOutboundMessage::Close => {
                            tracing::debug!(target: LOG_TARGET, "closing stream {stream_id} (FIN)");
                            bytes_to_write.extend(YamuxHeader::close_stream(stream_id).encode());

                            // Note: we are sending FIN to the other side to close our half, but
                            // don't want to entirely close the stream because we may still be waiting to
                            // receive some data back. So, ensure the open_state is correct now but don't remove.
                            stream.open_state = stream.open_state.set_fin_by_us();
                        }
                        BufferedOutboundMessage::Reset => {
                            tracing::debug!(target: LOG_TARGET, "closing stream {stream_id} (RST)");
                            bytes_to_write.extend(YamuxHeader::reset_stream(stream_id).encode());
                            streams_to_remove.push(stream_id);
                        }
                        BufferedOutboundMessage::WindowUpdate(len) => {
                            tracing::debug!(target: LOG_TARGET, "window update for stream {stream_id} ({len} bytes)");
                            bytes_to_write
                                .extend(YamuxHeader::window_update(stream_id, len).encode());
                        }
                        BufferedOutboundMessage::Data(mut outbound_data) => {
                            // Ensure that the bytes we send are capped by the send window size and MAX_SEND_SIZE.
                            let bytes_to_send = outbound_data
                                .len()
                                .min(stream.send_window)
                                .min(MAX_SEND_SIZE);
                            tracing::debug!(target: LOG_TARGET, "sending {bytes_to_send} DATA bytes on stream {stream_id}");

                            // If we can't send anything on this stream, put the message back on the queue and break
                            // to stop pulling items from this streams queue. We need a window update before we can
                            // send more data on this stream.
                            if bytes_to_send == 0 {
                                stream
                                    .outbound_buf
                                    .push_back(BufferedOutboundMessage::Data(outbound_data));
                                continue;
                            }

                            // VecDeque is two slices internally, so we work out how many bytes of
                            // each slice we need to send to satisfy the above.
                            let (a, b) = outbound_data.as_slices();
                            let a_len = usize::min(bytes_to_send, a.len());
                            let b_len = bytes_to_send.saturating_sub(a.len());

                            // Send the appropriate header and then the corresponding bytes. Because
                            // we have two slices above, we break this into two sends if necessary.
                            bytes_to_write
                                .extend(YamuxHeader::send_data(stream_id, a_len as u32).encode());
                            bytes_to_write.extend(&a[..a_len]);
                            if b_len > 0 {
                                bytes_to_write.extend(
                                    YamuxHeader::send_data(stream_id, b_len as u32).encode(),
                                );
                                bytes_to_write.extend(&b[..b_len]);
                            }

                            // Decrement the send window. When this runs out we'll be forced to
                            // wait for a window update from them before we can send more.
                            stream.send_window = stream.send_window.saturating_sub(bytes_to_send);

                            // If we didn't send all of the bytes, then drain what we did send and put
                            // the message back onto the front of the queue to be tried again later.
                            if bytes_to_send != outbound_data.len() {
                                outbound_data.drain(..bytes_to_send);
                                stream
                                    .outbound_buf
                                    .push_front(BufferedOutboundMessage::Data(outbound_data));
                            }
                        }
                    }
                }
            }

            for stream_id in streams_to_remove {
                streams.remove(&stream_id);
            }
        }

        // Perform a single write at the end with everything, to:
        // a) avoid holding onto our shared state across an await point,
        // b) can be more efficient doing one write instead of many.
        if !bytes_to_write.is_empty() {
            writer.write_all(&bytes_to_write).await?;
        }

        Ok(())
    }

    /// Accept or reject a new stream. This should be called when the frame type is Data or WindowUpdate,
    /// and when the Syn flag is given.
    ///
    /// - If this returns Some(..), then the new session has been established and normal logic can continue
    ///   to consume the data for instance.
    /// - If this returns None, then we can ignore this frame and loop around to the next.
    /// - If this returns an error, then we are done and should stop immediately.
    fn negotiate_new_stream_request<'a>(
        hdr: &YamuxHeader,
        shared_state: &'a mut SharedState,
    ) -> Result<Option<&'a mut StreamState>, Error> {
        let stream_id = hdr.stream_id;

        // they should always send even stream ID numbers, and not the session ID number.
        if !stream_id.is_even() || stream_id.is_session_id() {
            tracing::debug!(target: LOG_TARGET, "error on new incoming stream {stream_id}: invalid stream ID");
            return Err(Error::InvalidStreamId(stream_id));
        }

        // if they try to open too many streams, reject it but all good protocol wise.
        if shared_state.streams.len() >= MAX_STREAMS {
            shared_state
                .write_buf
                .extend(&YamuxHeader::reset_stream(stream_id).encode());
            tracing::debug!(target: LOG_TARGET, "rejecting new incoming stream {stream_id}: too many open streams");
            return Ok(None);
        }

        // If they send a duplicate stream ID, that is a protocol error so bail.
        if shared_state.streams.contains_key(&stream_id) {
            tracing::debug!(target: LOG_TARGET, "error on new incoming stream {stream_id}: duplicate stream ID");
            return Err(Error::DuplicateStreamId(stream_id));
        }

        // All good; accept new stream. Don't process any data etc; that's for the main loop.
        tracing::debug!(target: LOG_TARGET, "accepting incoming stream {stream_id}");
        let stream = shared_state
            .streams
            .entry(stream_id)
            .or_insert_with(StreamState::new);

        stream
            .outbound_buf
            .push_back(BufferedOutboundMessage::Accept);

        Ok(Some(stream))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        layers::yamux::header::FrameFlags,
        utils::testing::{MockStream, MockStreamHandle, block_on},
    };

    /// Poll the [`YamuxSession`], expecting it to return an [`Output`].
    fn next_expecting_output<R: AsyncRead + 'static, W: AsyncWrite + 'static>(
        yamux: &mut YamuxSession<R, W>,
    ) -> Output {
        block_on(yamux.next())
            .expect("expecting Ready, not Pending, from YamuxSession::next()")
            .expect("output should not be None")
            .expect("output should not be Err")
    }

    /// Read a Yamux header from the [`MockStreamHandle`], consuming the bytes.
    fn read_header(handle: &mut MockStreamHandle) -> YamuxHeader {
        YamuxHeader::decode(&handle.drain(YamuxHeader::SIZE).try_into().unwrap()).unwrap()
    }

    fn yamux_session() -> (YamuxSession<MockStream, MockStream>, MockStreamHandle) {
        let stream = MockStream::new();
        let handle = stream.handle();
        let yamux = YamuxSession::new(stream.clone(), stream);
        (yamux, handle)
    }

    #[test]
    fn stack_overflows_avoided() {
        let y = || {
            let (s, _) = yamux_session();
            s
        };
        // 20 of these on the stack should be ok. We have this test because
        // it's easily possible to have large stack buffers to handle everything,
        // and this was causing issues earlier so we allocate a bit more to the heap.
        let _: [YamuxSession<MockStream, MockStream>; _] = [
            y(),
            y(),
            y(),
            y(),
            y(),
            y(),
            y(),
            y(),
            y(),
            y(),
            y(),
            y(),
            y(),
            y(),
            y(),
            y(),
            y(),
            y(),
            y(),
            y(),
        ];
    }

    #[test]
    fn new_streams_can_be_opened() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream.clone(), stream);

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
        assert_eq!(res.state, OutputState::Data(data.len()));
        assert_eq!(&*yamux.data(), data as &[u8]);

        // If we call next() again we'll get Pending back as we're waiting for more data
        assert!(block_on(yamux.next()).is_none());
    }

    #[test]
    fn new_streams_can_be_opened_with_data() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream.clone(), stream);

        // Open and send data in one frame
        let data = b"Hello world";
        let header = YamuxHeader {
            version: 0,
            frame_type: FrameType::Data,
            flags: FrameFlag::Syn.into(),
            stream_id: YamuxStreamId::new(2),
            length: data.len() as u32,
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
        assert_eq!(res.state, OutputState::Data(data.len()));
        assert_eq!(&*yamux.data(), data as &[u8]);

        // If we call next() again we'll get Pending back as we're waiting for more data
        assert!(block_on(yamux.next()).is_none());
    }

    #[test]
    fn ping_receives_pong() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream.clone(), stream);

        // Send a ping on the session ID (stream 0).
        let ping = YamuxHeader {
            version: 0,
            frame_type: FrameType::Ping,
            flags: FrameFlags::empty(),
            stream_id: YamuxStreamId::new(0),
            length: 0xDEADBEEF,
        };
        handle.extend(ping.encode());

        // Second drive: processes ping, sends pong, returns Pending.
        let _ = block_on(yamux.next());

        // We should have sent back a pong.
        let pong = read_header(&mut handle);
        assert_eq!(pong, YamuxHeader::pong(YamuxStreamId::new(0), 0xDEADBEEF));
    }

    #[test]
    fn remote_fin_closes_stream() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream.clone(), stream);

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
        assert_eq!(res.state, OutputState::Data(data.len()));
        assert_eq!(&*yamux.data(), data as &[u8]);

        // Third next() returns ClosedByRemote (buffered from FIN).
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(2));
        assert_eq!(res.state, OutputState::ClosedByRemote);
    }

    #[test]
    fn remote_rst_closes_stream() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream.clone(), stream);

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
        assert_eq!(res.state, OutputState::Data(data.len()));
        assert_eq!(&*yamux.data(), data as &[u8]);

        // Third next() returns ClosedByRemote (buffered from RST).
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(2));
        assert_eq!(res.state, OutputState::ClosedByRemote);
    }

    #[test]
    fn window_update_with_fin_returns_closed() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream.clone(), stream);

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
        let mut yamux = YamuxSession::new(stream.clone(), stream);

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
        let mut yamux = YamuxSession::new(stream.clone(), stream);

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
        let mut yamux = YamuxSession::new(stream.clone(), stream);

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
        let mut yamux = YamuxSession::new(stream.clone(), stream);

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

        assert!(matches!(res, Err(Error::DuplicateStreamId(id)) if id == YamuxStreamId::new(2)));
    }

    #[test]
    fn goaway_normal_termination_returns_none() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream.clone(), stream);

        // Open stream so GoAway finds it.
        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(2)).encode());
        let data = b"x";
        handle.extend(YamuxHeader::send_data(YamuxStreamId::new(2), data.len() as u32).encode());
        handle.extend(data.iter().copied());
        let _ = block_on(yamux.next()); // OpenedByRemote
        let _ = block_on(yamux.next()); // Data

        // Send GoAway with normal termination (must be on session stream 0).
        let goaway = YamuxHeader {
            version: 0,
            frame_type: FrameType::GoAway,
            flags: FrameFlags::empty(),
            stream_id: YamuxStreamId::new(0),
            length: GoAwayType::NormalTermination as u32,
        };
        handle.extend(goaway.encode());

        let res = block_on(yamux.next()).expect("expecting output");
        assert!(res.is_none(), "GoAway NormalTermination should yield None");
    }

    #[test]
    fn goaway_internal_error() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream.clone(), stream);

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
            stream_id: YamuxStreamId::new(0),
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
        let mut yamux = YamuxSession::new(stream.clone(), stream);

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
            stream_id: YamuxStreamId::new(0),
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
        let mut yamux = YamuxSession::new(stream.clone(), stream);

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
            stream_id: YamuxStreamId::new(0),
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
        let mut yamux = YamuxSession::new(stream.clone(), stream);

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
        handle
            .extend(YamuxHeader::send_data(YamuxStreamId::new(2), bad_data.len() as u32).encode());
        handle.extend(bad_data.iter().copied());

        // First call: returns OpenedByRemote.
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(2));
        assert_eq!(res.state, OutputState::OpenedByRemote);

        // Second call: returns the data from the FIN frame.
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(2));
        assert_eq!(res.state, OutputState::Data(data.len()));
        assert_eq!(&*yamux.data(), data as &[u8]);

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
        let mut yamux = YamuxSession::new(stream.clone(), stream);

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
    fn none_after_error() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream.clone(), stream);

        // Cause an error: odd stream ID from remote.
        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(3)).encode());
        let _ = block_on(yamux.next());

        // Subsequent calls should return None
        let res = block_on(yamux.next()).expect("expecting output");

        assert!(res.is_none());
    }

    #[test]
    fn client_open_stream_sends_syn() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream.clone(), stream);

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
        let mut yamux = YamuxSession::new(stream.clone(), stream);

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
        let mut yamux = YamuxSession::new(stream.clone(), stream);

        let res = yamux.send_data(YamuxStreamId::new(99), b"hello".as_slice());
        assert!(matches!(res, Err(Error::StreamNotFound(id)) if id == YamuxStreamId::new(99)));
    }

    #[test]
    fn client_sends_data_on_stream() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream.clone(), stream);

        let id = yamux.open_stream();
        yamux.send_data(id, b"hello".as_slice()).unwrap();

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
    fn close_stream_sends_fin() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream.clone(), stream);

        let id = yamux.open_stream();
        yamux.close_stream(id);

        // First drive sends the Open header.
        let _ = block_on(yamux.next());
        let open_hdr = read_header(&mut handle);
        assert_eq!(open_hdr, YamuxHeader::open_stream(id));

        // Second drive sends the Close (RST).
        let _ = block_on(yamux.next());
        let close_hdr = read_header(&mut handle);
        assert_eq!(close_hdr, YamuxHeader::close_stream(id));
    }

    #[test]
    fn close_stream_immediately_skips_buffered_data() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream.clone(), stream);

        let id = yamux.open_stream();
        yamux
            .send_data(id, b"this should be dropped".as_slice())
            .unwrap();
        yamux.close_stream_immediately(id);

        // Drive the session.
        let _ = block_on(yamux.next());

        // Should only see the FIN, not the open or data.
        let close_hdr = read_header(&mut handle);
        assert_eq!(close_hdr, YamuxHeader::close_stream(id));

        // Nothing else should have been written.
        let remaining = handle.drain_all();
        assert!(remaining.is_empty(), "no other frames should be sent");
    }

    #[test]
    fn multiple_streams_interleave() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream.clone(), stream);

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
        assert_eq!(res.state, OutputState::Data(data_a.len()));
        assert_eq!(&*yamux.data(), data_a as &[u8]);

        // Third next: stream 4 opened.
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(4));
        assert_eq!(res.state, OutputState::OpenedByRemote);

        // Fourth next: stream 4 data.
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(4));
        assert_eq!(res.state, OutputState::Data(data_b.len()));
        assert_eq!(&*yamux.data(), data_b as &[u8]);
    }

    #[test]
    fn zero_length_data_frame_is_skipped() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream.clone(), stream);

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
        assert_eq!(res.state, OutputState::Data(data.len()));
        assert_eq!(&*yamux.data(), data as &[u8]);
    }

    // --- Cancel-safety tests ---
    //
    // `next()` is cancel-safe: dropping the future returned by `next()` before it
    // resolves (i.e. while it is pending) leaves the `YamuxSession` in a consistent
    // state so that the *next* call to `next()` produces exactly the result that
    // would have been produced had the first call been allowed to run to completion.
    //
    // The mechanism: `ReadWriteJoin` stores the in-progress read future in
    // `self.read_fut` before returning `Poll::Pending`, so subsequent `call()`
    // invocations resume that same future rather than recreating it.
    //
    // The critical test is the mid-frame scenario below: we feed *only* the 12-byte
    // Yamux header to the stream and then cancel `next()`.  The header bytes are now
    // consumed from the buffer.  If `next()` were not cancel-safe it would recreate
    // the read future on the following call, see only the data bytes in the buffer,
    // try to parse them as a header, and produce garbage / an error.  A cancel-safe
    // implementation instead resumes the paused state-machine (which already holds
    // the decoded header) and simply waits for the missing data bytes.

    #[test]
    fn next_is_cancel_safe_mid_data_read() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream.clone(), stream);

        // Open a remote stream so there is an active stream to receive data on.
        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(2)).encode());
        let open_res = next_expecting_output(&mut yamux);
        assert_eq!(open_res.state, OutputState::OpenedByRemote);

        // Queue the DATA header only – no body bytes yet.
        let data = b"cancel safe test";
        handle.extend(YamuxHeader::send_data(YamuxStreamId::new(2), data.len() as u32).encode());

        // Call next(): the read future decodes the header then waits for the body
        // bytes which are not yet available.  block_on drops the future on Pending,
        // simulating a cancellation.
        let pending = block_on(yamux.next());
        assert!(
            pending.is_none(),
            "expected Pending: data bytes not yet in buffer"
        );

        // The header bytes are now gone from the read buffer.  If next() were not
        // cancel-safe a fresh read future would misinterpret the following data bytes
        // as a header.  Supply the body bytes now.
        handle.extend(data.iter().copied());

        // next() must resume from the paused state-machine (header already decoded)
        // and deliver the correct data without any error.
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(2));
        assert_eq!(res.state, OutputState::Data(data.len()));
        assert_eq!(&*yamux.data(), data as &[u8]);
    }

    #[test]
    fn next_is_cancel_safe_before_any_bytes() {
        // Cancelling next() repeatedly before any bytes are available must not
        // corrupt the session; it should behave identically to a single call once
        // data eventually arrives.
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream.clone(), stream);

        // Cancel three times with an empty read buffer.
        assert!(block_on(yamux.next()).is_none());
        assert!(block_on(yamux.next()).is_none());
        assert!(block_on(yamux.next()).is_none());

        // Supply a complete open + data frame.
        let data = b"hello after cancels";
        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(2)).encode());
        handle.extend(YamuxHeader::send_data(YamuxStreamId::new(2), data.len() as u32).encode());
        handle.extend(data.iter().copied());

        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.state, OutputState::OpenedByRemote);

        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.state, OutputState::Data(data.len()));
        assert_eq!(&*yamux.data(), data as &[u8]);
    }

    #[test]
    fn next_is_cancel_safe_repeated_mid_read_cancellations() {
        // Repeated cancellations after the header has been consumed but before
        // the body arrives must not accumulate bad state.
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream.clone(), stream);

        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(2)).encode());
        let _ = next_expecting_output(&mut yamux); // OpenedByRemote

        let data = b"resilient";

        // Header only – no body.
        handle.extend(YamuxHeader::send_data(YamuxStreamId::new(2), data.len() as u32).encode());

        // Cancel three times while the read future is suspended awaiting the body.
        assert!(block_on(yamux.next()).is_none());
        assert!(block_on(yamux.next()).is_none());
        assert!(block_on(yamux.next()).is_none());

        // Now supply the body.
        handle.extend(data.iter().copied());

        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.stream_id, YamuxStreamId::new(2));
        assert_eq!(res.state, OutputState::Data(data.len()));
        assert_eq!(&*yamux.data(), data as &[u8]);
    }

    #[test]
    fn next_is_cancel_safe_then_further_frames_work() {
        // After a mid-frame cancellation and successful resumption, the session
        // continues to operate correctly for subsequent frames.
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream.clone(), stream);

        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(2)).encode());
        let _ = next_expecting_output(&mut yamux); // OpenedByRemote

        // First frame: cancel mid-read.
        let data1 = b"first";
        handle.extend(YamuxHeader::send_data(YamuxStreamId::new(2), data1.len() as u32).encode());
        assert!(block_on(yamux.next()).is_none()); // cancel
        handle.extend(data1.iter().copied());
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.state, OutputState::Data(data1.len()));
        assert_eq!(&*yamux.data(), data1 as &[u8]);

        // Second frame: delivered normally, proving session state is intact.
        let data2 = b"second";
        handle.extend(YamuxHeader::send_data(YamuxStreamId::new(2), data2.len() as u32).encode());
        handle.extend(data2.iter().copied());
        let res = next_expecting_output(&mut yamux);
        assert_eq!(res.state, OutputState::Data(data2.len()));
        assert_eq!(&*yamux.data(), data2 as &[u8]);
    }

    #[test]
    fn window_update_is_processed() {
        let stream = MockStream::new();
        let mut handle = stream.handle();
        let mut yamux = YamuxSession::new(stream.clone(), stream);

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
        assert_eq!(res.state, OutputState::Data(data2.len()));
        assert_eq!(&*yamux.data(), data2 as &[u8]);
    }
}

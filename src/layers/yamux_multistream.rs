mod frame_buffer;

use crate::layers::yamux::{self, YamuxSession};
use crate::utils::{async_stream, varint};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;
use core::mem;
use frame_buffer::MultistreamFrameBuffer;

const LOG_TARGET: &str = "yamux_multistream";

// Re-export public parts of this API.
pub use yamux::Error as YamuxError;
pub use yamux::YamuxStreamId;

const MULTISTREAM_PROTOCOL_NAME_WITH_NEWLINE: &[u8] = b"/multistream/1.0.0\n";
const MULTISTREAM_PROTOCOL_MAX_LEN: usize = 1024;

pub struct YamuxMultistream<R, W> {
    inner: YamuxSession<R, W>,
    bufs: BTreeMap<YamuxStreamId, Multistream>,
    // If this is set, we should drain messages from here before we
    // read more data from the network:
    read_from_stream_buffer: Option<YamuxStreamId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub stream_id: YamuxStreamId,
    pub state: OutputState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputState {
    IncomingProtocol(String),
    OutgoingRejected,
    // We don't need the outgoing protocol name because at a higher level
    // we only try one protocol at a time, but at this level we should not
    // ignore it since many protocols could be given and we need to know
    // which one was accepted.
    OutgoingAccepted(#[allow(dead_code)] String),
    Data(Vec<u8>),
    Closed(CloseReason),
}

/// Why was the channel closed?
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloseReason {
    ClosedByRemote,
    IncomingMessageTooLarge,
}

#[derive(Debug)]
struct Multistream {
    buffer: MultistreamFrameBuffer,
    state: MultistreamState,
    /// The maximum size allowed for incoming messages.
    ///
    /// When the buffer would be grown beyond this size, stop
    /// pushing data to it close this stream.
    max_buffer_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MultistreamState {
    NewIncoming,
    NewIncomingProtocol,
    NewIncomingProtocolWaitingForAccept(String),
    OutgoingProtocolWaitingForAccept {
        /// Have we seen the /multistream/1.0.0 header yet? Need this first.
        seen_header: bool,
        /// name of the current protocol we're trying.
        current: String,
        /// Other protocols we will fall back to trying next.
        rest: VecDeque<String>,
    },
    Open,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("yamux error: {0}")]
    Yamux(#[from] YamuxError),
    #[error("failed to decode varint at the front of the next multistream frame")]
    VarintOutOfRange,
    #[error("could not find stream with ID {0}")]
    StreamNotFound(YamuxStreamId),
    #[error("we called accept_stream on stream {0} which is not waiting to be accepted")]
    StreamNotWaitingForAccept(YamuxStreamId),
    #[error(
        "we called send_data on stream {0} which is not ready for data yet (still negotiating protocol)"
    )]
    StreamNotOpen(YamuxStreamId),
    #[error("we called open_stream and provided an empty list of protocols")]
    NoProtocolsGiven,
}

impl<R: async_stream::AsyncRead + 'static, W: async_stream::AsyncWrite + 'static>
    YamuxMultistream<R, W>
{
    pub fn new(yamux_session: YamuxSession<R, W>) -> Self {
        Self {
            inner: yamux_session,
            bufs: BTreeMap::new(),
            read_from_stream_buffer: None,
        }
    }

    /// Try to open a new outgoing stream, listing the protocols in order that we want to try.
    pub fn open_stream<P: Into<String>>(
        &mut self,
        protocols: impl IntoIterator<Item = P>,
        max_buffer_size: usize,
    ) -> Result<YamuxStreamId, Error> {
        let mut protocols: VecDeque<String> = protocols.into_iter().map(|p| p.into()).collect();
        let stream_id = self.inner.open_stream();

        // Kick off the process with the first protocol, so that we can wait
        // for appropriate messages and try the others. If no protocols were
        // given then error immediately.
        let Some(protocol) = protocols.pop_front() else {
            return Err(Error::NoProtocolsGiven);
        };
        self.send_multistream_data(stream_id, MULTISTREAM_PROTOCOL_NAME_WITH_NEWLINE)?;
        self.send_multistream_data_with_newline(stream_id, protocol.as_bytes())?;

        self.bufs.insert(
            stream_id,
            Multistream {
                buffer: MultistreamFrameBuffer::new(),
                max_buffer_size,
                state: MultistreamState::OutgoingProtocolWaitingForAccept {
                    seen_header: false,
                    current: protocol,
                    rest: protocols,
                },
            },
        );
        Ok(stream_id)
    }

    /// Send some data on the given stream. Errors if the protocol negotiation has not been
    /// completed (ie if we have not yet seen [`OutputState::OutgoingAccepted`] for the given stream).
    pub fn send_data(&mut self, stream_id: YamuxStreamId, data: &[u8]) -> Result<(), Error> {
        let Some(stream) = self.bufs.get_mut(&stream_id) else {
            return Err(Error::StreamNotFound(stream_id));
        };
        let MultistreamState::Open = &stream.state else {
            return Err(Error::StreamNotOpen(stream_id));
        };
        self.send_multistream_data(stream_id, data)
    }

    /// Accept a stream for which [`OutputState::IncomingProtocol`] was emitted.
    /// Errors if we call this for a stream that is not waiting to be accepted / rejected.
    pub fn accept_protocol(
        &mut self,
        stream_id: YamuxStreamId,
        max_buffer_size: usize,
    ) -> Result<(), Error> {
        let Some(stream) = self.bufs.get_mut(&stream_id) else {
            return Err(Error::StreamNotFound(stream_id));
        };
        let MultistreamState::NewIncomingProtocolWaitingForAccept(protocol_name) = &stream.state
        else {
            return Err(Error::StreamNotWaitingForAccept(stream_id));
        };

        // TODO: We can move send_multistream* fns to an inner object to avoid needing this clone.
        let protocol_name = protocol_name.clone();

        // Accepted; now we are "open" on this incoming stream
        tracing::debug!(target: LOG_TARGET, "protocol {protocol_name} accepted on stream {stream_id}");
        stream.state = MultistreamState::Open;
        // Set the buffer size (it'll be super small initially until protocol is accepted):
        stream.max_buffer_size = max_buffer_size;
        self.send_multistream_data_with_newline(stream_id, protocol_name.as_bytes())?;
        Ok(())
    }

    /// Reject a stream for which [`OutputState::IncomingProtocol`] was emitted.
    /// Errors if we call this for a stream that is not waiting to be accepted / rejected.
    pub fn reject_protocol(&mut self, stream_id: YamuxStreamId) -> Result<(), Error> {
        let Some(stream) = self.bufs.get_mut(&stream_id) else {
            return Err(Error::StreamNotFound(stream_id));
        };
        let MultistreamState::NewIncomingProtocolWaitingForAccept(protocol_name) = &stream.state
        else {
            return Err(Error::StreamNotWaitingForAccept(stream_id));
        };

        // Rejected; wait for another protocol suggestion on this stream and send the reject message.
        tracing::debug!(target: LOG_TARGET, "protocol {protocol_name} rejected on stream {stream_id}");
        stream.state = MultistreamState::NewIncomingProtocol;
        self.send_multistream_data_with_newline(stream_id, b"na")?;
        Ok(())
    }

    /// Close a stream.
    pub fn close_stream(&mut self, stream_id: YamuxStreamId) {
        self.bufs.remove(&stream_id);
        self.inner.close_stream(stream_id);
    }

    /// Close a stream immediately, unbuffering any messages buffered to send prior to this call.
    pub fn close_stream_immediately(&mut self, stream_id: YamuxStreamId) {
        self.bufs.remove(&stream_id);
        self.inner.close_stream_immediately(stream_id);
    }

    /// Close a stream immediately, unbuffering any messages buffered to send prior to this call.
    /// This works via the more aggressive RST flag to abort a stream and should be used in error
    /// cases rather than general close cases.
    pub fn reset_stream_immediately(&mut self, stream_id: YamuxStreamId) {
        self.bufs.remove(&stream_id);
        self.inner.reset_stream_immediately(stream_id);
    }

    /// Drive our yamux multistream machine, returning output messages as they come in
    /// and pushing inputs out.
    ///
    /// # Cancel Safety
    ///
    /// This function is cancel-safe.
    //
    // Dev note: The cancel-safety is easily verifiable because next() calls next_inner() which
    // has only one `.await` which calls the cancel-safe YamusSession::next(). Since no harm is done
    // if we were to cancel and restart at this point (which is anyway at the start of the function),
    // we can be confident that it is cancel-safe.
    pub async fn next(&mut self) -> Option<Result<Output, Error>> {
        self.next_inner().await.transpose()
    }

    async fn next_inner(&mut self) -> Result<Option<Output>, Error> {
        loop {
            // If we have recently taken some bytes in on a stream, we try to parse/drain more messages
            // from the same buffer until it's empty. Else, we ask for more bytes from our Yamux layer below.
            let (stream_id, entry) = if let Some(stream_id) = self.read_from_stream_buffer.take() {
                // We may try to rea from a stream that was closed already due to an invalid
                // message or something, so ignore and loop if stream isn't found
                let Some(entry) = self.bufs.get_mut(&stream_id) else {
                    continue;
                };

                (stream_id, entry)
            } else {
                let yamux::Output { stream_id, state } = match self.inner.next().await {
                    Some(Ok(out)) => out,
                    Some(Err(e)) => return Err(Error::Yamux(e)),
                    None => return Ok(None),
                };

                let entry = match state {
                    yamux::OutputState::OpenedByRemote => {
                        // New stream opened; add it to our map.
                        tracing::debug!(target: LOG_TARGET, "stream {stream_id} opened by remote");
                        self.bufs.entry(stream_id).or_insert_with(|| Multistream {
                            buffer: MultistreamFrameBuffer::new(),
                            state: MultistreamState::NewIncoming,
                            // Only allow enough for protocol negotiation initially.
                            // This is "upgraded" when the user accepts a protocol.
                            max_buffer_size: MULTISTREAM_PROTOCOL_MAX_LEN,
                        })
                    }
                    yamux::OutputState::Data(_len) => {
                        // Data on new stream; buffer the data and ignore if we don't know the stream.
                        let Some(entry) = self.bufs.get_mut(&stream_id) else {
                            continue;
                        };

                        let data = self.inner.data();

                        // Abort if buffer length exceeded.
                        if entry.buffer.len() + data.len() > entry.max_buffer_size {
                            drop(data);
                            self.reset_stream_immediately(stream_id);
                            return Ok(Some(Output {
                                stream_id,
                                state: OutputState::Closed(CloseReason::IncomingMessageTooLarge),
                            }));
                        }

                        entry.buffer.feed(&data);
                        entry
                    }
                    yamux::OutputState::ClosedByRemote => {
                        tracing::debug!(target: LOG_TARGET, "stream {stream_id} closed by remote");
                        // Only emit a `Closed` message if this stream progressed far enough to
                        // actually emit some other message (eg OutputState::IncomingProtocol). If it
                        // didn't get this far then nothing knows about it yet anyway.
                        if let Some(removed) = self.bufs.remove(&stream_id)
                            && !matches!(
                                removed.state,
                                MultistreamState::NewIncoming
                                    | MultistreamState::NewIncomingProtocol
                            )
                        {
                            return Ok(Some(Output {
                                stream_id,
                                state: OutputState::Closed(CloseReason::ClosedByRemote),
                            }));
                        } else {
                            continue;
                        }
                    }
                };

                (stream_id, entry)
            };

            // Pull the next message from the message buffer, looping if nothing ready yet.
            let byte_iter = match entry.buffer.next() {
                Some(Ok(iter)) => {
                    // We've seen a message! This means there could be other messages
                    // to follow. So, set `read_from_stream_buffer` to ensure that, if
                    // this is the case, we will read them all before taking more input
                    // from the network.
                    self.read_from_stream_buffer = Some(stream_id);
                    iter
                }
                Some(Err(_)) => return Err(Error::VarintOutOfRange),
                None => continue,
            };

            // Handle the message depending on the stream state.
            match &mut entry.state {
                // New incoming stream, so do the initial multistream protocol handshake.
                MultistreamState::NewIncoming => {
                    if bytes_equal_iter(MULTISTREAM_PROTOCOL_NAME_WITH_NEWLINE, byte_iter) {
                        tracing::debug!(target: LOG_TARGET, "new incoming stream {stream_id} awaiting protocol suggestion");
                        entry.state = MultistreamState::NewIncomingProtocol;
                        self.send_multistream_data(
                            stream_id,
                            MULTISTREAM_PROTOCOL_NAME_WITH_NEWLINE,
                        )?;
                    } else {
                        tracing::debug!(target: LOG_TARGET, "new incoming stream {stream_id} invalid protocol suggestion: closing");
                        self.reset_stream_immediately(stream_id);
                    }
                }
                // We've done the initial handshake and need to accept some protocol suggestion.
                // Hand back the relevant details to the user and wait for them to accept the stream.
                MultistreamState::NewIncomingProtocol => {
                    let mut protocol_bytes: Vec<u8> = byte_iter.collect();
                    if protocol_bytes.pop() != Some(b'\n') {
                        tracing::debug!(target: LOG_TARGET, "invalid multistream protocol (no trailing newline): request to close stream {stream_id}");
                        self.reset_stream_immediately(stream_id);
                        continue;
                    }
                    let Ok(protocol_name) = String::from_utf8(protocol_bytes) else {
                        tracing::debug!(target: LOG_TARGET, "invalid multistream protocol (not utf8): request to close stream {stream_id}");
                        self.reset_stream_immediately(stream_id);
                        continue;
                    };

                    tracing::debug!(target: LOG_TARGET, "incoming protocol {protocol_name} proposed on stream {stream_id}");
                    entry.state = MultistreamState::NewIncomingProtocolWaitingForAccept(
                        protocol_name.clone(),
                    );
                    return Ok(Some(Output {
                        stream_id,
                        state: OutputState::IncomingProtocol(protocol_name),
                    }));
                }
                // We got bytes on the stream, but we're still waiting for the user to
                // accept it. So, just close the stream immediately and ignore the bytes.
                MultistreamState::NewIncomingProtocolWaitingForAccept(_) => {
                    tracing::debug!(target: LOG_TARGET, "invalid multistream protocol (got bytes on stream waiting to be accepted): request to close stream {stream_id}");
                    drop(byte_iter);
                    self.reset_stream_immediately(stream_id);
                    continue;
                }
                // We initiated an outgoing stream and are waiting for them to accept/reject
                // the protocol we proposed. They either accepted or they returned "na\n" to
                // signal rejection
                MultistreamState::OutgoingProtocolWaitingForAccept {
                    seen_header,
                    current,
                    rest,
                } => {
                    if !*seen_header {
                        // expect the multistream header first
                        if bytes_equal_iter(MULTISTREAM_PROTOCOL_NAME_WITH_NEWLINE, byte_iter) {
                            *seen_header = true;
                        } else {
                            tracing::debug!(target: LOG_TARGET, "invalid multistream header (2): request to close stream {stream_id}");
                            self.reset_stream_immediately(stream_id);
                        }
                    } else {
                        // multistream header seen so we are just negotiating the protocol name
                        let current_with_newline =
                            current.as_bytes().iter().copied().chain(Some(b'\n'));
                        if iters_equal(current_with_newline, byte_iter) {
                            tracing::debug!(target: LOG_TARGET, "protocol {current} accepted by remote on stream {stream_id}");
                            let current = mem::take(current);
                            entry.state = MultistreamState::Open;
                            return Ok(Some(Output {
                                stream_id,
                                state: OutputState::OutgoingAccepted(current),
                            }));
                        } else {
                            // Try the next protocol, rejecting if no protocols left to try
                            if let Some(next) = rest.pop_front() {
                                tracing::debug!(target: LOG_TARGET, "protocol {current} rejected by remote, trying {next}, on stream {stream_id}");
                                *current = next.clone();
                                self.send_multistream_data_with_newline(
                                    stream_id,
                                    next.as_bytes(),
                                )?;
                            } else {
                                tracing::debug!(target: LOG_TARGET, "protocol {current} rejected by remote, request to close stream {stream_id}");
                                self.close_stream_immediately(stream_id);
                                return Ok(Some(Output {
                                    stream_id,
                                    state: OutputState::OutgoingRejected,
                                }));
                            }
                        }
                    }
                }
                // Emit any data received from a stream once multistream negotiations are complete.
                MultistreamState::Open => {
                    let data: Vec<u8> = byte_iter.collect();
                    return Ok(Some(Output {
                        stream_id,
                        state: OutputState::Data(data),
                    }));
                }
            }
        }
    }

    /// Send data prefixed with a varint length to follow the multistream protocol.
    /// This does **not** append a newline, which must be given for protocol negotiation messages.
    /// Use [`Self::send_multistream_data_with_newline`] to append a newline.
    fn send_multistream_data(
        &mut self,
        stream_id: YamuxStreamId,
        data: &[u8],
    ) -> Result<(), Error> {
        let mut data_len = [0u8; 10];
        let varint_len = varint::encode(data.len() as u64, &mut data_len);

        self.inner
            .send_data(stream_id, data_len[..varint_len].iter().copied())?;
        self.inner.send_data(stream_id, data.iter().copied())?;
        Ok(())
    }

    /// Send data prefixed with a varint length and suffixed with a newline to follow the multistream protocol
    /// when sending the basic negotiation + multistream protocol strings.
    fn send_multistream_data_with_newline(
        &mut self,
        stream_id: YamuxStreamId,
        data: &[u8],
    ) -> Result<(), Error> {
        let mut data_len = [0u8; 10];
        // Add 1 for the newline we'll append.
        let varint_len = varint::encode(data.len() as u64 + 1, &mut data_len);

        self.inner
            .send_data(stream_id, data_len[..varint_len].iter().copied())?;
        self.inner.send_data(stream_id, data.iter().copied())?;
        self.inner.send_data(stream_id, b"\n".iter().copied())?;
        Ok(())
    }
}

/// Do two iterators have identical contents?
fn iters_equal(mut a: impl Iterator<Item = u8>, mut b: impl Iterator<Item = u8>) -> bool {
    loop {
        match (a.next(), b.next()) {
            // False if items don't match.
            (Some(a1), Some(b1)) => {
                if a1 != b1 {
                    return false;
                }
            }
            // True if we get to the end of both together.
            (None, None) => return true,
            // False otherwise (1 iter has remaining items and other does not).
            _ => return false,
        }
    }
}

/// Does some iterator of bytes equal the given slice?
fn bytes_equal_iter(value: &[u8], iter: impl ExactSizeIterator<Item = u8>) -> bool {
    if value.len() != iter.len() {
        return false;
    }
    iters_equal(value.iter().copied(), iter)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::layers::yamux::header::{FrameType, YamuxHeader};
    use crate::utils::testing::{MockStream, MockStreamHandle, block_on};
    use alloc::vec;

    fn yamux_multistream() -> (YamuxMultistream<MockStream, MockStream>, MockStreamHandle) {
        let stream = MockStream::new();
        let handle = stream.handle();
        let yamux = YamuxSession::new(stream.clone(), stream);
        (YamuxMultistream::new(yamux), handle)
    }

    fn open_stream(handle: &mut MockStreamHandle, n: u32) {
        handle.extend(YamuxHeader::open_stream(YamuxStreamId::new(n)).encode());
    }

    /// Send some multistream frames (which will be prefixed with their varint length) in a yamux data frame.
    fn send_data(handle: &mut MockStreamHandle, n: u32, messages: &[&[u8]]) {
        // First encode our messages so that we know the yamux frame length
        let mut data = Vec::new();
        for msg in messages {
            varint::encode_to_vec(msg.len() as u64, &mut data);
            data.extend(*msg);
        }

        // Now, push a yamux frame with the correct data length
        handle.extend(YamuxHeader::send_data(YamuxStreamId::new(n), data.len() as u32).encode());
        // Then push the data
        handle.extend(data);
    }

    fn next_expecting_output(yamux: &mut YamuxMultistream<MockStream, MockStream>) -> Output {
        block_on(yamux.next())
            .expect("expecting Ready, not Pending, from YamuxMultistream::next()")
            .expect("output should not be None")
            .expect("output should not be Err")
    }

    fn next_yamux_header(handle: &mut MockStreamHandle) -> YamuxHeader {
        YamuxHeader::decode(&handle.drain(YamuxHeader::SIZE).try_into().unwrap()).unwrap()
    }

    fn next_multistream_frames(handle: &mut MockStreamHandle) -> impl Iterator<Item = Vec<u8>> {
        let header =
            YamuxHeader::decode(&handle.drain(YamuxHeader::SIZE).try_into().unwrap()).unwrap();
        if header.frame_type != FrameType::Data {
            // Skip over non-data frames.
            return next_multistream_frames(handle);
        }

        // Maybe multiple multistream frames in one yamux frame, so return
        // an iterator over all of them.
        let mut data = handle.drain(header.length as usize);
        core::iter::from_fn(move || {
            // Nothing left to iterate.
            if data.is_empty() {
                return None;
            }

            // Decode multistream frame length
            let data_cursor = &mut &*data;
            let multistream_len = match varint::decode(data_cursor) {
                Ok(len) => len as usize,
                Err(e) => panic!("Could not decode mulitstream varint: {e}. Data: {data:?}"),
            };

            // Take this frame and keep the rest
            let output = data_cursor[..multistream_len].to_vec();
            data = data_cursor[multistream_len..].to_vec();

            Some(output)
        })
    }

    #[test]
    fn accept_new_stream() {
        // tracing_subscriber::fmt().with_max_level(tracing_subscriber::filter::LevelFilter::DEBUG).init();
        let (mut stream, mut handle) = yamux_multistream();

        // First the remote proposes a new protocol on some stream:
        open_stream(&mut handle, 2);
        send_data(&mut handle, 2, &[b"/multistream/1.0.0\n", b"/foo/bar\n"]);
        assert_eq!(
            next_expecting_output(&mut stream),
            Output {
                stream_id: YamuxStreamId::new(2),
                state: OutputState::IncomingProtocol("/foo/bar".into())
            }
        );

        // We accept!
        stream
            .accept_protocol(YamuxStreamId::new(2), usize::MAX)
            .unwrap();
        block_on(stream.next());

        // Now the remote should receive an accept message.
        let frames: Vec<_> = next_multistream_frames(&mut handle).collect();
        assert_eq!(
            frames,
            vec![b"/multistream/1.0.0\n".to_vec(), b"/foo/bar\n".to_vec(),]
        );

        // The remote now can send some data.
        send_data(&mut handle, 2, &[b"hello world", b"and more"]);

        // We should now receive it unchanged.
        assert_eq!(
            next_expecting_output(&mut stream),
            Output {
                stream_id: YamuxStreamId::new(2),
                state: OutputState::Data(b"hello world".to_vec())
            }
        );
        assert_eq!(
            next_expecting_output(&mut stream),
            Output {
                stream_id: YamuxStreamId::new(2),
                state: OutputState::Data(b"and more".to_vec())
            }
        );
    }

    #[test]
    fn reject_new_stream_and_then_accept_next_proposal() {
        // tracing_subscriber::fmt().with_max_level(tracing_subscriber::filter::LevelFilter::DEBUG).init();
        let (mut stream, mut handle) = yamux_multistream();

        // First the remote proposes a new protocol on some stream:
        open_stream(&mut handle, 2);
        send_data(&mut handle, 2, &[b"/multistream/1.0.0\n", b"/foo/bar\n"]);
        assert_eq!(
            next_expecting_output(&mut stream),
            Output {
                stream_id: YamuxStreamId::new(2),
                state: OutputState::IncomingProtocol("/foo/bar".into())
            }
        );

        // We reject the protocol.
        stream.reject_protocol(YamuxStreamId::new(2)).unwrap();
        block_on(stream.next());

        // Now the remote should receive a reject message.
        let frames: Vec<_> = next_multistream_frames(&mut handle).collect();
        assert_eq!(
            frames,
            vec![b"/multistream/1.0.0\n".to_vec(), b"na\n".to_vec(),]
        );

        // The remote can propose a new protocol
        send_data(&mut handle, 2, &[b"/foo/wibble\n"]);
        assert_eq!(
            next_expecting_output(&mut stream),
            Output {
                stream_id: YamuxStreamId::new(2),
                state: OutputState::IncomingProtocol("/foo/wibble".into())
            }
        );

        // We can then accept it
        stream
            .accept_protocol(YamuxStreamId::new(2), usize::MAX)
            .unwrap();
        block_on(stream.next());

        // Now the remote should receive an accept message.
        let frames: Vec<_> = next_multistream_frames(&mut handle).collect();
        assert_eq!(frames, vec![b"/foo/wibble\n".to_vec()]);
    }

    #[test]
    fn reject_invalid_multistream_header() {
        //tracing_subscriber::fmt().with_max_level(tracing_subscriber::filter::LevelFilter::DEBUG).init();
        let (mut stream, mut handle) = yamux_multistream();

        // The remote proposes a new protocol on some stream, but using an invalid header
        open_stream(&mut handle, 2);
        send_data(&mut handle, 2, &[b"/multistream/z.z.z\n", b"/foo/bar\n"]);

        // We see nothing back (but drive progress)
        assert!(block_on(stream.next()).is_none());

        // The remote gets an ack to acknowledge the new stream,
        // then a window update header,
        // then a close because invalid header.
        assert_eq!(
            next_yamux_header(&mut handle),
            YamuxHeader::accept_stream(YamuxStreamId::new(2))
        );
        next_yamux_header(&mut handle);
        assert_eq!(
            next_yamux_header(&mut handle),
            YamuxHeader::reset_stream(YamuxStreamId::new(2))
        );
    }

    #[test]
    fn max_buffer_len_is_honoured_for_protocol_agreeing() {
        //tracing_subscriber::fmt().with_max_level(tracing_subscriber::filter::LevelFilter::DEBUG).init();
        let (mut stream, mut handle) = yamux_multistream();

        // Add up the bytes so that we are just 1 byte over the 1024 byte buffer length when
        // combining all of our messages.
        let long_name: Vec<u8> = core::iter::repeat_n(b'a', 1002)
            .chain(Some(b'\n'))
            .collect();

        // Try to do initial protocol negotiating with a too-long protocol name:
        open_stream(&mut handle, 2);
        send_data(&mut handle, 2, &[b"/multistream/1.0.0\n", &long_name]);
        let output = next_expecting_output(&mut stream);

        assert_eq!(
            output,
            Output {
                stream_id: YamuxStreamId::new(2),
                state: OutputState::Closed(CloseReason::IncomingMessageTooLarge)
            }
        );
    }

    #[test]
    fn accepts_large_payloads_split_across_yamux_frames() {
        //tracing_subscriber::fmt().with_max_level(tracing_subscriber::filter::LevelFilter::DEBUG).init();
        let (mut stream, mut handle) = yamux_multistream();

        // Open and accept a stream first. This all tested so keep it brief.
        open_stream(&mut handle, 2);
        send_data(&mut handle, 2, &[b"/multistream/1.0.0\n", b"/foo/bar\n"]);
        next_expecting_output(&mut stream); // IncomingProtocol
        stream
            .accept_protocol(YamuxStreamId::new(2), usize::MAX)
            .unwrap();
        block_on(stream.next()); // Drive things forward after accept
        let _ = next_multistream_frames(&mut handle); // Pull accept frames.

        // First, build our data packet. a varint at the front and then 10MB of 123u8.
        let mut data = vec![];
        let ten_mb = 10 * 1024 * 1024;
        varint::encode_to_vec(ten_mb, &mut data);
        data.extend(core::iter::repeat_n(123u8, ten_mb as usize));

        // Now, chunk and send this as many yamux frames
        for bytes in data.chunks(10 * 1024) {
            handle
                .extend(YamuxHeader::send_data(YamuxStreamId::new(2), bytes.len() as u32).encode());
            handle.extend(bytes.iter().copied());
        }

        // The next message we get back should be this single large data packet
        assert_eq!(
            next_expecting_output(&mut stream),
            Output {
                stream_id: YamuxStreamId::new(2),
                state: OutputState::Data(vec![123u8; 10 * 1024 * 1024])
            }
        );
    }

    #[test]
    fn sends_large_payloads_split_across_yamux_frames() {
        //tracing_subscriber::fmt().with_max_level(tracing_subscriber::filter::LevelFilter::DEBUG).init();
        let (mut stream, mut handle) = yamux_multistream();

        // Open and accept a stream first. This all tested so keep it brief.
        open_stream(&mut handle, 2);
        send_data(&mut handle, 2, &[b"/multistream/1.0.0\n", b"/foo/bar\n"]);
        next_expecting_output(&mut stream); // IncomingProtocol
        stream
            .accept_protocol(YamuxStreamId::new(2), usize::MAX)
            .unwrap();
        block_on(stream.next()); // Drive things forward after accept
        let _ = next_multistream_frames(&mut handle); // Pull accept frames.

        // Send 10MB of data to the remote.
        let ten_mb = 10 * 1024 * 1024usize;
        stream
            .send_data(YamuxStreamId::new(2), &vec![123u8; ten_mb])
            .unwrap();
        block_on(stream.next());

        // Queue a bunch of window updates to be applied as they are needed. Each adds just 10kb
        for _ in 0..2000 {
            handle.extend(YamuxHeader::window_update(YamuxStreamId::new(2), 10 * 1024).encode());
        }

        // Take yamux data frames from the output, appending them together
        // and driving the stream as needed to absorb new window updates to
        // allow progress to continue.
        let mut response = vec![];
        let mut frame_count = 0usize;
        while response.len() < ten_mb {
            let header = next_yamux_header(&mut handle);

            assert_eq!(
                header.frame_type,
                FrameType::Data,
                "frame {frame_count} should be a Data frame"
            );
            assert_eq!(
                header.stream_id,
                YamuxStreamId::new(2),
                "frame {frame_count} should be on stream 2"
            );

            let data_segment = handle.drain(header.length as usize);
            response.extend_from_slice(&data_segment);

            // We'll hit times where we need window updates; this allows
            // such progress to be made, since we buffered a bunch up to
            // be consumed above.
            block_on(stream.next());
            frame_count += 1;
        }

        // Now decode the length from the response and check everything matches.
        let cursor = &mut &*response;
        let len = varint::decode(cursor).expect("valid varint");
        assert_eq!(len, ten_mb as u64, "length should be 10MB");
        assert_eq!(*cursor, vec![123u8; ten_mb], "data should match input");
    }
}

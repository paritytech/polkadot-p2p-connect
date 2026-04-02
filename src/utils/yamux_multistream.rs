mod frame_buffer;

use alloc::string::String;
use alloc::vec::Vec;
use crate::utils::yamux::{self, YamuxSession};
use crate::utils::{async_stream, varint};
use alloc::collections::{BTreeMap, VecDeque};
use core::mem;
use frame_buffer::{MultistreamFrameBuffer, MultistreamFrameBufferOutput};

// Re-export public parts of this API.
pub use yamux::YamuxStreamId;
pub use yamux::Error as YamuxError;

const MULTISTREAM_PROTOCOL_NAME_WITH_NEWLINE: &[u8] = b"/multistream/1.0.0\n";

pub struct YamuxMultistream<S> {
    inner: YamuxSession<S>,
    bufs: BTreeMap<YamuxStreamId, Multistream>,
}

pub struct Output {
    pub stream_id: YamuxStreamId,
    pub state: OutputState
}

pub enum OutputState {
    IncomingProtocol(String),
    OutgoingRejected,
    // We don't need the outgoing protocol name because at a higher level
    // we only try one protocol at a time, but at this level we should not
    // ignore it since many protocols could be given and we need to know
    // which one was accepted.
    OutgoingAccepted(#[allow(dead_code)] String),
    Data(Vec<u8>),
    Closed,
}

struct Multistream {
    buffer: MultistreamFrameBuffer,
    state: MultistreamState
}

#[derive(Clone, PartialEq, Eq)]
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
        rest: VecDeque<String> 
    },
    Open,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("yamux error reading stream: {0}")]
    Yamux(#[from] YamuxError),
    #[error("failed to decode varint at the front of the next multistream frame")]
    VarintOutOfRange,
    #[error("could not find stream with ID {0}")]
    StreamNotFound(YamuxStreamId),
    #[error("we called accept_stream on stream {0} which is not waiting to be accepted")]
    StreamNotWaitingForAccept(YamuxStreamId),
    #[error("we called send_data on stream {0} which is not ready for data yet (still negotiating protocol)")]
    StreamNotOpen(YamuxStreamId),
    #[error("we called open_stream and provided an empty list of protocols")]
    NoProtocolsGiven,
}

impl <S: async_stream::AsyncStream> YamuxMultistream<S> {
    pub fn new(yamux_session: YamuxSession<S>) -> Self {
        Self {
            inner: yamux_session,
            bufs: BTreeMap::new(),
        }
    }

    /// Try to open a new outgoing stream, listing the protocols in order that we want to try.
    pub fn open_stream<P: Into<String>>(&mut self, protocols: impl IntoIterator<Item=P>) -> Result<YamuxStreamId, Error> {
        let mut protocols: VecDeque<String> = protocols.into_iter().map(|p| p.into()).collect();
        let stream_id = self.inner.open_stream()?;

        // Kick off the process with the first protocol, so that we can wait
        // for appropriate messages and try the others. If no protocols were
        // given then error immediately.
        let Some(protocol) = protocols.pop_front() else {
            return Err(Error::NoProtocolsGiven)
        };
        self.send_multistream_data(stream_id, MULTISTREAM_PROTOCOL_NAME_WITH_NEWLINE)?;
        self.send_multistream_data_with_newline(stream_id, protocol.as_bytes())?;

        self.bufs.insert(stream_id, Multistream { 
            buffer: MultistreamFrameBuffer::new(), 
            state: MultistreamState::OutgoingProtocolWaitingForAccept { 
                seen_header: false,
                current: protocol, 
                rest: protocols 
            },
        });
        Ok(stream_id)
    }

    /// Send some data on the given stream. Errors if the protocol negotiation has not been
    /// completed (ie if we have not yet seen [`OutputState::OutgoingAccepted`] for the given stream).
    pub fn send_data(&mut self, stream_id: YamuxStreamId, data: &[u8]) -> Result<(), Error> {
        let Some(stream) = self.bufs.get_mut(&stream_id) else {
            return Err(Error::StreamNotFound(stream_id))
        };
        let MultistreamState::Open = &stream.state else {
            return Err(Error::StreamNotOpen(stream_id))
        };

        self.send_multistream_data(stream_id, data)
    }

    /// Accept a stream for which [`OutputState::IncomingProtocol`] was emitted.
    /// Errors if we call this for a stream that is not waiting to be accepted / rejected.
    pub fn accept_protocol(&mut self, stream_id: YamuxStreamId) -> Result<(), Error> {
        let Some(stream) = self.bufs.get_mut(&stream_id) else {
            return Err(Error::StreamNotFound(stream_id))
        };
        let MultistreamState::NewIncomingProtocolWaitingForAccept(protocol_name) = &stream.state else {
            return Err(Error::StreamNotWaitingForAccept(stream_id))
        };

        // TODO: We can move send_multistream* fns to an inner object to avoid needing this clone.
        let protocol_name = protocol_name.clone();

        // Accepted; now we are "open" on this incoming stream
        stream.state = MultistreamState::Open;
        self.send_multistream_data_with_newline(stream_id, protocol_name.as_bytes())?;
        Ok(())
    }

    /// Reject a stream for which [`OutputState::IncomingProtocol`] was emitted.
    /// Errors if we call this for a stream that is not waiting to be accepted / rejected.
    pub fn reject_protocol(&mut self, stream_id: YamuxStreamId) -> Result<(), Error> {
        let Some(stream) = self.bufs.get_mut(&stream_id) else {
            return Err(Error::StreamNotFound(stream_id))
        };
        let MultistreamState::NewIncomingProtocolWaitingForAccept(_) = &stream.state else {
            return Err(Error::StreamNotWaitingForAccept(stream_id))
        };

        // Rejected; wait for another protocol suggestion on this stream and send the reject message.
        stream.state = MultistreamState::NewIncomingProtocol;
        self.send_multistream_data_with_newline(stream_id, b"na")?;
        Ok(())
    }

    /// Close a stream.
    pub fn close_stream(&mut self, stream_id: YamuxStreamId) -> Result<(), Error> {
        self.bufs.remove(&stream_id);
        self.inner.close_stream(stream_id)?;
        Ok(())
    }

    /// Close a stream immediately, unbuffering any messages buffered to send prior to this call.
    pub fn close_stream_immediately(&mut self, stream_id: YamuxStreamId) -> Result<(), Error> {
        self.bufs.remove(&stream_id);
        self.inner.close_stream_immediately(stream_id)?;
        Ok(())
    }

    /// Drive our yamux multistream machine, returning output messages as they come in
    /// and pushing inputs out.
    pub async fn next(&mut self) -> Option<Result<Output, Error>> {
        self.next_inner().await.transpose()
    }

    async fn next_inner(&mut self) -> Result<Option<Output>, Error> {
        loop {
            // Get the next output from some yamux stream.
            let output = match self.inner.next().await {
                Some(Ok(out)) => out,
                Some(Err(e)) => return Err(Error::Yamux(e)),
                None => return Ok(None)
            };

            let stream_id = output.stream_id;
            let bytes = match output.state {
                yamux::OutputState::Data(bytes) => bytes,
                yamux::OutputState::OpenedByRemote => {
                    // This is a new stream, so add an entry for it.
                    self.bufs.insert(stream_id, Multistream {
                        buffer: MultistreamFrameBuffer::new(),
                        state: MultistreamState::NewIncoming
                    });
                },
                yamux::OutputState::ClosedByRemote => {
                    // Technically the stream may have been "half closed" (ie we can still send but they won't)
                    // or "full closed" (ie they won't send and we aren't allowed to), but I don't think we care
                    // here we so we just keep it simple and close all or nothing.
                    self.bufs.remove(&stream_id);
                    return Ok(Some(Output { stream_id, state: OutputState::Closed }));
                },
            };
    
            // Fetch the stream details.
            // ignore any messages on a stream we don't know about (they could be messages sent after
            // we sent a close request for instance)
            let Some(entry) = self.bufs.get_mut(&stream_id) else {
                continue
            }

            // Feed bytes to the stream buffer, returning multistream frames as they are available.
            let byte_iter = match entry.buffer.feed(bytes) {
                MultistreamFrameBufferOutput::Ready(iter) => {
                    iter
                },
                MultistreamFrameBufferOutput::NeedsMoreBytes => {
                    continue
                },
                MultistreamFrameBufferOutput::VarintOutOfRange => {
                    return Err(Error::VarintOutOfRange)
                },
            };

            // Handle the bytes depending on the stream state.
            match &mut entry.state {
                // New incoming stream, so do the initial multistream protocol handshake.
                MultistreamState::NewIncoming => {
                    if bytes_equal_iter(MULTISTREAM_PROTOCOL_NAME_WITH_NEWLINE, byte_iter) {
                        entry.state = MultistreamState::NewIncomingProtocol;
                        self.send_multistream_data(stream_id, MULTISTREAM_PROTOCOL_NAME_WITH_NEWLINE)?;
                    } else {
                        self.close_stream_immediately(stream_id)?;
                    }
                }
                // We've done the initial handshake and need to accept some protocol suggestion.
                // Hand back the relevant details to the user and wait for them to accept the stream.
                MultistreamState::NewIncomingProtocol => {
                    let mut protocol_bytes: Vec<u8> = byte_iter.collect();
                    if protocol_bytes.pop() != Some(b'\n') {
                        self.close_stream_immediately(stream_id)?;
                        continue
                    }
                    let Ok(protocol_name) = String::from_utf8(protocol_bytes) else {
                        self.close_stream_immediately(stream_id)?;
                        continue;
                    };

                    entry.state = MultistreamState::NewIncomingProtocolWaitingForAccept(protocol_name.clone());
                    return Ok(Some(Output {
                        stream_id,
                        state: OutputState::IncomingProtocol(protocol_name)
                    }))
                },
                // We got bytes on the stream, but we're still waiting for the user to
                // accept it. So, just close the stream immediately and ignore the bytes.
                MultistreamState::NewIncomingProtocolWaitingForAccept(_) => {
                    drop(byte_iter);
                    self.close_stream_immediately(stream_id)?;
                    continue;
                },
                // We initiated an outgoing stream and are waiting for them to accept/reject
                // the protocol we proposed. They either accepted or they returned "na\n" to
                // signal rejection
                MultistreamState::OutgoingProtocolWaitingForAccept { seen_header, current, rest } => {
                    if !*seen_header {
                        // expect the multistream header first
                        if bytes_equal_iter(MULTISTREAM_PROTOCOL_NAME_WITH_NEWLINE, byte_iter) {
                            *seen_header = true;
                        } else {
                            self.close_stream_immediately(stream_id)?;
                        }
                    } else {
                        // multistream header seen so we are just negotiating the protocol name
                        let current_with_newline = current.as_bytes().iter().copied().chain(Some(b'\n'));
                        if iters_equal(current_with_newline, byte_iter) {
                            // Protocol matches response; all good!
                            let current = mem::take(current);
                            entry.state = MultistreamState::Open;
                            return Ok(Some(Output {
                                stream_id,
                                state: OutputState::OutgoingAccepted(current),
                            }))
                        } else {
                            // Try the next protocol, rejecting if no protocols left to try
                            if let Some(next) = rest.pop_front() {
                                *current = next.clone();
                                self.send_multistream_data_with_newline(stream_id, next.as_bytes())?;
                            } else {
                                self.close_stream_immediately(stream_id)?;
                                return Ok(Some(Output {
                                    stream_id,
                                    state: OutputState::OutgoingRejected,
                                }))
                            }
                        }
                    }
                },
                // Emit any data received from a stream once multistream negotiations are complete.
                MultistreamState::Open => {
                    let data = byte_iter.collect();
                    return Ok(Some(Output {
                        stream_id,
                        state: OutputState::Data(data)
                    }))
                }
            }
        }
    }

    /// Send data prefixed with a varint length to follow the multistream protocol.
    /// This does **not** append a newline, which must be given for protocol negotiation messages.
    /// Use [`Self::send_multistream_data_with_newline`] to append a newline.
    fn send_multistream_data(&mut self, stream_id: YamuxStreamId, data: &[u8]) -> Result<(), Error> {
        let mut data_len = [0u8; 10];
        let varint_len = varint::encode(data.len() as u64, &mut data_len);

        self.inner.send_data(stream_id, data_len[..varint_len].iter().copied())?;
        self.inner.send_data(stream_id, data.iter().copied())?;
        Ok(())
    }

    /// Send data prefixed with a varint length and suffixed with a newline to follow the multistream protocol
    /// when sending the basic negotiation + multistream protocol strings.
    fn send_multistream_data_with_newline(&mut self, stream_id: YamuxStreamId, data: &[u8]) -> Result<(), Error> {
        let mut data_len = [0u8; 10];
        // Add 1 for the newline we'll append.
        let varint_len = varint::encode(data.len() as u64 + 1, &mut data_len);

        self.inner.send_data(stream_id, data_len[..varint_len].iter().copied())?;
        self.inner.send_data(stream_id, data.iter().copied())?;
        self.inner.send_data(stream_id, b"\n".iter().copied())?;
        Ok(())
    }
}

/// Do two iterators have identical contents?
fn iters_equal(mut a: impl Iterator<Item=u8>, mut b: impl Iterator<Item=u8>) -> bool {
    loop {
        match (a.next(), b.next()) {
            // False if items don't match.
            (Some(a1), Some(b1)) => {
                if a1 != b1 {
                    return false
                }
            },
            // True if we get to the end of both together.
            (None, None) => {
                return true
            },
            // False otherwise (1 iter has remaining items and other does not).
            _ => {
                return false
            }
        }
    }
}

/// Does some iterator of bytes equal the given slice?
fn bytes_equal_iter(value: &[u8], iter: impl ExactSizeIterator<Item=u8>) -> bool {
    if value.len() != iter.len() {
        return false
    }
    iters_equal(value.iter().copied(), iter)
}
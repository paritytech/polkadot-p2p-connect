mod frame_buffer;

use crate::utils::yamux::{self, YamuxSession, YamuxStreamId};
use crate::utils::{async_stream, varint};
use std::collections::HashMap;

use frame_buffer::{MultistreamFrameBuffer, MultistreamFrameBufferOutput};

pub struct YamuxMultistream<S> {
    inner: YamuxSession<S>,
    bufs: HashMap<YamuxStreamId, Multistream>
}

pub struct Output {
    pub stream_id: YamuxStreamId,
    pub state: OutputState
}

pub enum OutputState {
    IncomingProtocolNeedsAccepting(String),
    IncomingHandshakeNeedsAccepting(Vec<u8>),
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
    NewIncomingProtocolWaitingForProtocolAccept(String),
    NewIncomingProtocolWaitingForHandshake,
    NewIncomingProtocolWaitingForHandshakeAccept(Vec<u8>),
    Open,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("yamux error reading stream: {0}")]
    Yamux(#[from] yamux::Error),
    #[error("failed to decode varint at the front of the next multistream frame")]
    VarintOutOfRange,
    #[error("could not find stream with ID {0}")]
    StreamNotFound(YamuxStreamId),
    #[error("we called accept_stream on stream {0} which is not waiting to be accepted")]
    StreamNotWaitingForAccept(YamuxStreamId),
    #[error("we called accept_handshake on stream {0} which is not waiting for a handshake to be accepted")]
    StreamNotWaitingForHandshakeAccept(YamuxStreamId),
}

impl <S: async_stream::AsyncStream> YamuxMultistream<S> {
    pub fn new(yamux_session: YamuxSession<S>) -> Self {
        Self {
            inner: yamux_session,
            bufs: HashMap::new(),
        }
    }

    pub fn open_notification_stream(&mut self, protocol: &str, handshake: &[u8]) -> Result<(), Error> {
        self.inner.
    }

    pub fn open_request_response_stream(&mut self, protocol: &str, request: &[u8]) -> Result<(), Error> {

    }

    // /// Accept a stream for which [`OutputState::IncomingStreamNeedsAccepting`] was emitted.
    // /// Errors if we call this for a stream that is not waiting to be accepted / rejected.
    // pub fn accept_protocol(&mut self, stream_id: YamuxStreamId, handshake: &[u8]) -> Result<(), Error> {
    //     let Some(stream) = self.bufs.get_mut(&stream_id) else {
    //         return Err(Error::StreamNotFound(stream_id))
    //     };
    //     let MultistreamState::NewIncomingProtocolWaitingForProtocolAccept(protocol_name) = &stream.state else {
    //         return Err(Error::StreamNotWaitingForAccept(stream_id))
    //     };

    //     // TODO: We can move send_multistream* fns to an inner object to avoid needing this clone.
    //     let protocol_name = protocol_name.clone();

    //     // Accepted; now we wait for handshake to come in and send out own handshake
    //     stream.state = MultistreamState::NewIncomingProtocolWaitingForHandshake;
    //     self.send_multistream_data_with_newline(stream_id, protocol_name.as_bytes())?;
    //     self.send_multistream_data(stream_id, handshake)?;
    //     Ok(())
    // }

    // /// Reject a stream for which [`OutputState::IncomingStreamNeedsAccepting`] was emitted.
    // /// Errors if we call this for a stream that is not waiting to be accepted / rejected.
    // pub fn reject_protocol(&mut self, stream_id: YamuxStreamId) -> Result<(), Error> {
    //     let Some(stream) = self.bufs.get_mut(&stream_id) else {
    //         return Err(Error::StreamNotFound(stream_id))
    //     };
    //     let MultistreamState::NewIncomingProtocolWaitingForProtocolAccept(_) = &stream.state else {
    //         return Err(Error::StreamNotWaitingForAccept(stream_id))
    //     };

    //     // Rejected; wait for another protocol suggestion on this stream and send the reject message.
    //     stream.state = MultistreamState::NewIncomingProtocol;
    //     self.send_multistream_data_with_newline(stream_id, b"na")?;
    //     Ok(())
    // }

    // /// Accept an incoming streams handshake when [`OutputState::IncomingHandshakeNeedsAccepting`]. 
    // /// This opens the incoming stream and from now we can begin receiving data on it.
    // pub fn accept_handshake(&mut self, stream_id: YamuxStreamId) -> Result<(), Error> {
    //     let Some(stream) = self.bufs.get_mut(&stream_id) else {
    //         return Err(Error::StreamNotFound(stream_id))
    //     };
    //     let MultistreamState::NewIncomingProtocolWaitingForHandshakeAccept(_) = &stream.state else {
    //         return Err(Error::StreamNotWaitingForHandshakeAccept(stream_id))
    //     };

    //     stream.state = MultistreamState::Open;
    //     Ok(())
    // }

    // /// Reject an incoming streams handshake. This closes the stream.
    // pub fn reject_handshake(&mut self, stream_id: YamuxStreamId) -> Result<(), Error> {
    //     let Some(stream) = self.bufs.get_mut(&stream_id) else {
    //         return Err(Error::StreamNotFound(stream_id))
    //     };
    //     let MultistreamState::NewIncomingProtocolWaitingForHandshakeAccept(_) = &stream.state else {
    //         return Err(Error::StreamNotWaitingForHandshakeAccept(stream_id))
    //     };

    //     // Rejected; close stream
    //     self.inner.close_stream(stream_id)?;
    //     Ok(())
    // }

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
                yamux::OutputState::ClosedByRemote => {
                    // Technically the stream may have been "half closed" (ie we can still send but they won't)
                    // or "full closed" (ie they won't send and we aren't allowed to), but I don't think we care
                    // here we so we just keep it simple and close all or nothing.
                    self.bufs.remove(&stream_id);
                    return Ok(Some(Output { stream_id, state: OutputState::Closed }));
                },
            };
    
            // Fetch the stream details.
            let entry = self.bufs.entry(stream_id).or_insert_with(|| {
                Multistream {
                    buffer: MultistreamFrameBuffer::new(),
                    state: MultistreamState::NewIncoming
                }
            });

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
            match entry.state {
                // New incoming stream, so do the initial multistream protocol handshake.
                MultistreamState::NewIncoming => {
                    if bytes_equal_iter(b"/multistream/1.0.0\n", byte_iter) {
                        entry.state = MultistreamState::NewIncomingProtocol;
                        self.send_multistream_data_with_newline(stream_id, b"/multistream/1.0.0")?;
                    } else {
                        self.close_and_remove_stream_immediately(stream_id);
                    }
                }
                // We've done the initial handshake and need to accept some protocol suggestion.
                // Hand back the relevant details to the user and wait for them to accept the stream.
                MultistreamState::NewIncomingProtocol => {
                    let mut protocol_bytes: Vec<u8> = byte_iter.collect();
                    if protocol_bytes.pop() != Some(b'\n') {
                        self.close_and_remove_stream_immediately(stream_id);
                        continue
                    }
                    let Ok(protocol_name) = String::from_utf8(protocol_bytes) else {
                        self.close_and_remove_stream_immediately(stream_id);
                        continue;
                    };

                    entry.state = MultistreamState::NewIncomingProtocolWaitingForProtocolAccept(protocol_name.clone());
                    return Ok(Some(Output {
                        stream_id,
                        state: OutputState::IncomingProtocolNeedsAccepting(protocol_name)
                    }))
                },
                // We got bytes on the stream, but we're still waiting for the user to
                // accept it. So, just close the stream immediately and ignore the bytes.
                MultistreamState::NewIncomingProtocolWaitingForProtocolAccept(_) => {
                    drop(byte_iter);
                    self.close_and_remove_stream_immediately(stream_id);
                    continue;
                },
                // We've received handshake bytes now 
                MultistreamState::NewIncomingProtocolWaitingForHandshake => {
                    let handshake: Vec<u8> = byte_iter.collect();
                    entry.state = MultistreamState::NewIncomingProtocolWaitingForHandshakeAccept(handshake.clone());
                    return Ok(Some(Output {
                        stream_id,
                        state: OutputState::IncomingHandshakeNeedsAccepting(handshake)
                    }))
                },
                // We got bytes on the stream, but we're still waiting for the user to
                // accept the handshake. So, just close the stream immediately and ignore the bytes.
                MultistreamState::NewIncomingProtocolWaitingForHandshakeAccept(_) => {
                    drop(byte_iter);
                    self.close_and_remove_stream_immediately(stream_id);
                    continue;
                },
                // Emit data from a stream.
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

        self.inner.send_data(stream_id, &data_len[..varint_len])?;
        self.inner.send_data(stream_id, data)?;
        Ok(())
    }

    /// Send data prefixed with a varint length and suffixed with a newline to follow the multistream protocol
    /// when sending the basic negotiation + multistream protocol strings.
    fn send_multistream_data_with_newline(&mut self, stream_id: YamuxStreamId, data: &[u8]) -> Result<(), Error> {
        let mut data_len = [0u8; 10];
        // Add 1 for the newline we'll append.
        let varint_len = varint::encode(data.len() as u64 + 1, &mut data_len);

        self.inner.send_data(stream_id, &data_len[..varint_len])?;
        self.inner.send_data(stream_id, data)?;
        self.inner.send_data(stream_id, b"\n")?;
        Ok(())
    }

    /// Best effort close and remove a stream immediately.
    fn close_and_remove_stream_immediately(&mut self, stream_id: YamuxStreamId) {
        self.bufs.remove(&stream_id);
        let _ = self.inner.close_stream_immediately(stream_id);
    }
}

/// Does some iterator of bytes equal the given slice?
fn bytes_equal_iter(value: &[u8], iter: impl ExactSizeIterator<Item=u8>) -> bool {
    if value.len() != iter.len() {
        return false
    }

    for (a, b) in value.iter().zip(iter) {
        if *a != b {
            return false
        }
    }

    true
}
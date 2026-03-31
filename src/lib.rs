mod utils;

pub mod error;

use core::marker::PhantomData;
use core::future::Future;
use std::collections::HashMap;
use error::{ ConnectionError, StreamError, ProtocolError };
use utils::{
    async_stream,
    multistream,
    peer_id,
    noise,
    yamux,
    yamux_multistream,
};

// -----------------------------------------------------------
// Platform
// -----------------------------------------------------------

pub trait PlatformT {
    /// Fill the given bytes with random values.
    fn fill_with_random_values(bytes: &mut [u8]);
    /// Returns Err(()) if the given future times out, else returns the output from the future.
    fn timeout<F: core::future::Future<Output = R>, R>(ms: usize, fut: F) -> impl Future<Output = Result<R, ()>>;
}

// -----------------------------------------------------------
// Configuration
// -----------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Configuration<Platform> {
    identity_secret: Option<[u8; 32]>,
    marker: PhantomData<(Platform,)>
}

impl <Platform: PlatformT> Configuration<Platform> {
    /// Create some new connection configuration.
    pub fn new() -> Self {
        Self {
            identity_secret: None,
            marker: PhantomData,
        }
    }

    pub fn with_generated_identity(mut self) -> Self {
        let mut random_bytes = [0u8; 32]; 
        Platform::fill_with_random_values(&mut random_bytes);
        self.identity_secret = Some(random_bytes);
        self
    }

    pub fn with_identity(mut self, secret_bytes: [u8; 32]) -> Self {
        self.identity_secret = Some(secret_bytes);
        self
    }

    pub async fn connect<Stream: async_stream::AsyncStream>(&self, stream: Stream) -> Result<Connection<Stream, Platform>, ConnectionError> {
        Connection::from_stream(stream, self.identity_secret, None).await
    }

    pub async fn connect_to_peer<Stream: async_stream::AsyncStream>(&self, stream: Stream, peer_id: peer_id::PeerId) -> Result<Connection<Stream, Platform>, ConnectionError> {
        Connection::from_stream(stream, self.identity_secret, Some(peer_id)).await
    }
}

// -----------------------------------------------------------
// Connection
// -----------------------------------------------------------

pub struct Connection<Stream, Platform> {
    yamux: yamux_multistream::YamuxMultistream<noise::NoiseStream<Stream>>,
    remote_id: peer_id::PeerId,
    request_response_streams: HashMap<yamux_multistream::YamuxStreamId, Request>,
    marker: PhantomData<(Platform,)>
}

pub enum Output {
    RequestResponse {
        id: RequestId,
        res: RequestResponse,
    },
    Notification {
        id: NotificationId,
        res: NotificationResponse,
    }
}

pub enum RequestResponse {
    Data(Vec<u8>),
    ProtocolRejected,
    PayloadRejected,
    MultistreamProtocolError,
}

pub enum NotificationResponse {

}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(yamux_multistream::YamuxStreamId);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NotificationId {
    outbound: yamux_multistream::YamuxStreamId,
    inbound: yamux_multistream::YamuxStreamId,
}

enum Request {
    AwaitingPayloadConfirmation(Vec<u8>),
    AwaitingResponsePayload,
}

impl <Stream: async_stream::AsyncStream, Platform: PlatformT> Connection<Stream, Platform> {
    async fn from_stream(
        mut stream: Stream, 
        identity_secret: Option<[u8; 32]>,
        remote_peer_id: Option<peer_id::PeerId>
    ) -> Result<Self, ConnectionError> {
        const NEGOTIATE_TIMEOUT_MS: usize = 10_000;
        const NOISE_HANDSHAKE_TIMEOUT_MS: usize = 30_000;

        // Agree to use the noise protocol.
        Platform::timeout(NEGOTIATE_TIMEOUT_MS, multistream::negotiate_dialer(&mut stream, "/noise"))
            .await
            .map_err(|()| ConnectionError::NoiseNegotiationTimeout)??;

        // Generate/use an identity for ourselves.
        let identity = match identity_secret {
            Some(key) => peer_id::Identity::from_random_bytes(key),
            None => {
                let mut random_bytes = [0u8; 32]; 
                Platform::fill_with_random_values(&mut random_bytes);
                peer_id::Identity::from_random_bytes(random_bytes)
            }
        };

        // Establish our encrypted noise session and find the remote Peer ID
        let (mut noise_stream, remote_id) = Platform::timeout(NOISE_HANDSHAKE_TIMEOUT_MS, noise::handshake_dialer(stream, &identity, remote_peer_id.as_ref()))
            .await
            .map_err(|()| ConnectionError::NoiseHandshakeTimeout)??;

        // Agree to use the yamux protocol in this noise stream.
        Platform::timeout(NEGOTIATE_TIMEOUT_MS, multistream::negotiate_dialer(&mut noise_stream, "/yamux/1.0.0"))
            .await
            .map_err(|()| ConnectionError::YamuxNegotiationTimeout)??;
            
        // Wrap our noise stream in a yamux session (we'll be using yamux substreams), and wrap
        // that in a YamuxMultistream adaptor to handle multistream negotiation on top of these
        // substreams.
        let yamux_session = yamux::YamuxSession::new(noise_stream);
        let yamux_multistream = yamux_multistream::YamuxMultistream::new(yamux_session);

        Ok(Connection {
            yamux: yamux_multistream,
            remote_id,
            request_response_streams: Default::default(),
            marker: PhantomData
        })
    }

    pub fn request<P: Into<String>>(&mut self, protocol: &str, request: Vec<u8>) -> Result<RequestId, ConnectionError> {
        // Open a stream and buffer data to be sent on it
        let stream_id = self.yamux.open_stream(Some(protocol))?;

        // Save the request to send once the stream is open.
        self.request_response_streams.insert(stream_id, Request::AwaitingPayloadConfirmation(request));

        Ok(RequestId(stream_id))
    }

    pub async fn next(&mut self) -> Option<Result<Output, StreamError>> {
        self.next_inner().await.transpose()
    }

    async fn next_inner(&mut self) -> Result<Option<Output>, StreamError> {
        loop {
            let output = match self.yamux.next().await {
                Some(Ok(output)) => output,
                Some(Err(e)) => return Err(e.into()),
                None => return Ok(None)
            };

            let stream_id = output.stream_id;

            use yamux_multistream::OutputState;

            // Is this a message on a request-response stream?
            if let Some(info) = self.request_response_streams.get_mut(&stream_id) {
                match info {
                    Request::AwaitingPayloadConfirmation(request) => {
                        match output.state {
                            // The protocol has been accepted, so send the request payload and
                            // start waiting for the response.
                            OutputState::OutgoingAccepted(_) => {
                                self.yamux.send_data(stream_id, &core::mem::take(request))?;
                                *info = Request::AwaitingResponsePayload;
                                continue
                            },
                            // Else if the protocol is invalid we'll relay that to the user.
                            OutputState::OutgoingRejected => {
                                self.request_response_streams.remove(&stream_id);
                                return Ok(Some(Output::RequestResponse {
                                    id: RequestId(stream_id),
                                    res: RequestResponse::ProtocolRejected,
                                }))
                            },
                            // If we see anything else then protocol is not being followed.
                            // Close the stream and return the error to the user.
                            _ => {
                                self.request_response_streams.remove(&stream_id);
                                self.yamux.close_stream_immediately(stream_id)?;
                                return Ok(Some(Output::RequestResponse {
                                    id: RequestId(stream_id),
                                    res: RequestResponse::MultistreamProtocolError,
                                }))
                            },
                        }
                    },
                    Request::AwaitingResponsePayload => {
                        match output.state {
                            // We got a response back! Give it to the user.
                            OutputState::Data(bytes) => {
                                self.request_response_streams.remove(&stream_id);
                                return Ok(Some(Output::RequestResponse {
                                    id: RequestId(stream_id),
                                    res: RequestResponse::Data(bytes),
                                }))
                            }
                            // If the payload is invalid, we will either get a valid
                            // application-level response (ie above), or the substream 
                            // will simply be closed.
                            OutputState::Closed => {
                                self.request_response_streams.remove(&stream_id);
                                return Ok(Some(Output::RequestResponse {
                                    id: RequestId(stream_id),
                                    res: RequestResponse::PayloadRejected,
                                }))
                            },
                            // If we see anything else then protocol is not being followed.
                            // Close the stream and return the error to the user.
                            _ => {
                                self.request_response_streams.remove(&stream_id);
                                self.yamux.close_stream_immediately(stream_id)?;
                                return Ok(Some(Output::RequestResponse {
                                    id: RequestId(stream_id),
                                    res: RequestResponse::MultistreamProtocolError,
                                }))
                            },
                        }
                    }
                }
            }


        }
    }

    // pub fn id(&mut self) -> Id {
    //     todo!("Return an available opaque ID to use for the next stream")
    // }

    // pub fn request<F: FnOnce(Vec<u8>) -> Event>(&mut self, id: Id, stream: impl AsRef<str>, transform: F) {
    //     todo!("Send a request on the given request-response stream and transform the response to our event type.")
    // }

    // pub fn subscribe<V: FnOnce(Vec<u8>) -> bool, F: FnOnce(Vec<u8>) -> Event>(&mut self, id: Id, stream: impl AsRef<str>, handshake: Vec<u8>, validate: V, transform: F) {
    //     todo!("Subscribe to a notification stream, validating their handshake and transforming responses to our event type.")
    // }

    // pub async fn next(&mut self) -> Option<Event> {
    //     todo!("Return the next event, or None if no connection has been closed.")
    // }
}


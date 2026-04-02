#![no_std]

extern crate alloc;

mod utils;

pub mod error;

use core::marker::PhantomData;
use core::future::Future;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::boxed::Box;
use error::{ ConnectionError, StreamError };
use utils::{
    async_stream,
    multistream,
    peer_id,
    noise,
    yamux,
    yamux_multistream::{self, YamuxStreamId},
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
    requests: BTreeMap<YamuxStreamId, RequestState>,
    subscriptions: Vec<SubscriptionDetails>,
    marker: PhantomData<(Platform,)>
}

struct SubscriptionDetails {
    protocol_name: String,
    outgoing_stream: YamuxStreamId,
    validation_function: Box<dyn FnMut(Vec<u8>) -> bool>,
    state: SubscriptionState,
}

enum SubscriptionState {
    AwaitingOutboundProtocolConfirmation { 
        our_handshake: Vec<u8>
    },
    AwaitingOutboundHandshakeValidation {
        // We need to keep our handshake around to send again for inbound
        our_handshake: Vec<u8>,
    },
    AwaitingInboundConnection {
        our_handshake: Vec<u8>,
        their_first_handshake: Vec<u8>,
    },
    AwaitingInboundHandshake {
        inbound_stream_id: YamuxStreamId,
        our_handshake: Vec<u8>,
        their_first_handshake: Vec<u8>,
    },
    InboundWaitingForData {
        inbound_stream_id: YamuxStreamId
    },
}

impl SubscriptionState {
    fn inbound_stream_id(&self) -> Option<YamuxStreamId> {
        match self {
            Self::InboundWaitingForData { inbound_stream_id} |
            Self::AwaitingInboundHandshake { inbound_stream_id, .. } => {
                Some(*inbound_stream_id)
            },
            _ => None
        }
    }
}

pub enum Output {
    Request {
        id: RequestId,
        res: RequestResponse,
    },
    Subscription {
        id: SubscriptionId,
        res: SubscriptionResponse,
    }
}

pub enum RequestResponse {
    Data(Vec<u8>),
    ProtocolRejected,
    PayloadRejected,
    MultistreamProtocolError,
}

pub enum SubscriptionResponse {
    Data(Vec<u8>),
    ProtocolRejected,
    OurHandshakeRejected,
    TheirHandshakeRejected,
    Closed,
    MultistreamProtocolError,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(YamuxStreamId);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubscriptionId {
    outgoing_stream: YamuxStreamId
}

enum RequestState {
    AwaitingProtocolConfirmation(Vec<u8>),
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
            requests: Default::default(),
            subscriptions: Default::default(),
            marker: PhantomData
        })
    }

    pub fn request(&mut self, protocol: &str, request: Vec<u8>) -> Result<RequestId, ConnectionError> {
        // Open a stream.
        let stream_id = self.yamux.open_stream(Some(protocol))?;

        // Save the request to send once the stream is open.
        self.requests.insert(stream_id, RequestState::AwaitingProtocolConfirmation(request));

        Ok(RequestId(stream_id))
    }

    pub fn subscribe<F: FnMut(Vec<u8>) -> bool + 'static>(&mut self, protocol: impl Into<String>, handshake: Vec<u8>, validate: F) -> Result<SubscriptionId, ConnectionError> {
        let protocol = protocol.into();
        if let Some(details) = self.subscriptions.iter().find(|s| &s.protocol_name == &protocol) {
            return Err(ConnectionError::AlreadySubscribed(SubscriptionId { outgoing_stream: details.outgoing_stream }))
        }
        
        // Open an outbound stream if one doesn't exist already.
        let stream_id = self.yamux.open_stream(Some(&protocol))?;
        // Attach the details.
        self.subscriptions.push(SubscriptionDetails { 
            protocol_name: protocol, 
            outgoing_stream: stream_id,
            validation_function: Box::new(validate),
            state: SubscriptionState::AwaitingOutboundProtocolConfirmation { our_handshake: handshake },
        });

        Ok(SubscriptionId { outgoing_stream: stream_id })
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

            // ----------------------------------
            // Is this a message on a request stream that we are expecting a single response on?
            // ----------------------------------
            if let Some(info) = self.requests.get_mut(&stream_id) {
                match info {
                    RequestState::AwaitingProtocolConfirmation(request) => {
                        match output.state {
                            // The protocol has been accepted, so send the request payload and
                            // start waiting for the response.
                            OutputState::OutgoingAccepted(_) => {
                                self.yamux.send_data(stream_id, &core::mem::take(request))?;
                                *info = RequestState::AwaitingResponsePayload;
                                continue
                            },
                            // Else if the protocol is invalid we'll relay that to the user.
                            OutputState::OutgoingRejected => {
                                self.requests.remove(&stream_id);
                                return Ok(Some(Output::Request {
                                    id: RequestId(stream_id),
                                    res: RequestResponse::ProtocolRejected,
                                }))
                            },
                            // If we see anything else then protocol is not being followed.
                            // Close the stream and return the error to the user.
                            _ => {
                                self.requests.remove(&stream_id);
                                self.yamux.close_stream_immediately(stream_id)?;
                                return Ok(Some(Output::Request {
                                    id: RequestId(stream_id),
                                    res: RequestResponse::MultistreamProtocolError,
                                }))
                            },
                        }
                    },
                    RequestState::AwaitingResponsePayload => {
                        match output.state {
                            // We got a response back! Give it to the user.
                            OutputState::Data(bytes) => {
                                self.requests.remove(&stream_id);
                                return Ok(Some(Output::Request {
                                    id: RequestId(stream_id),
                                    res: RequestResponse::Data(bytes),
                                }))
                            }
                            // If the payload is invalid, we will either get a valid
                            // application-level response (ie above), or the substream 
                            // will simply be closed.
                            OutputState::Closed => {
                                self.requests.remove(&stream_id);
                                return Ok(Some(Output::Request {
                                    id: RequestId(stream_id),
                                    res: RequestResponse::PayloadRejected,
                                }))
                            },
                            // If we see anything else then protocol is not being followed.
                            // Close the stream and return the error to the user.
                            _ => {
                                self.requests.remove(&stream_id);
                                self.yamux.close_stream_immediately(stream_id)?;
                                return Ok(Some(Output::Request {
                                    id: RequestId(stream_id),
                                    res: RequestResponse::MultistreamProtocolError,
                                }))
                            },
                        }
                    }
                }
            }

            // ----------------------------------
            // Is this a message back on an outgoing subscription stream that we opened.
            // ----------------------------------
            if let Some(index) = self.subscriptions.iter().position(|s| s.outgoing_stream == stream_id) {
                let sub = &mut self.subscriptions[index];
                let id = SubscriptionId { outgoing_stream: sub.outgoing_stream };
                match &mut sub.state {
                    // We are waiting for the protocol to be confirmed so we can send our handshake.
                    SubscriptionState::AwaitingOutboundProtocolConfirmation { our_handshake } => {
                        match output.state {
                            // They accepted our handshake, yay! Send our handshake.
                            OutputState::OutgoingAccepted(_) => {
                                let our_handshake = core::mem::take(our_handshake);
                                self.yamux.send_data(id.outgoing_stream, &our_handshake)?;
                                sub.state = SubscriptionState::AwaitingOutboundHandshakeValidation { our_handshake };
                                continue
                            },
                            // They rejected our handshake. Tell the user and close.
                            OutputState::OutgoingRejected => {
                                self.yamux.close_stream_immediately(id.outgoing_stream)?;
                                self.subscriptions.swap_remove(index);
                                return Ok(Some(Output::Subscription {
                                    id,
                                    res: SubscriptionResponse::ProtocolRejected,
                                }))
                            }
                            // Anything else is invalid and is a protocol error.
                            _ => {
                                self.yamux.close_stream_immediately(id.outgoing_stream)?;
                                self.subscriptions.swap_remove(index);
                                return Ok(Some(Output::Subscription {
                                    id,
                                    res: SubscriptionResponse::MultistreamProtocolError,
                                }))
                            }
                        }
                    },
                    // We are waiting for their handshake so we can verify it.
                    SubscriptionState::AwaitingOutboundHandshakeValidation { our_handshake } => {
                        match output.state {
                            // They sent their handshake! Keep it for later (we validate on the inbound stream)
                            OutputState::Data(their_first_handshake) => {
                                let our_handshake = core::mem::take(our_handshake);
                                sub.state = SubscriptionState::AwaitingInboundConnection { 
                                    our_handshake, 
                                    their_first_handshake,
                                };
                                continue
                            }
                            // They closed the stream; our handshake was rejected.
                            OutputState::Closed => {
                                self.subscriptions.swap_remove(index);
                                return Ok(Some(Output::Subscription {
                                    id,
                                    res: SubscriptionResponse::OurHandshakeRejected,
                                }))
                            },
                            // Anything else is invalid and is a protocol error.
                            _ => {
                                self.yamux.close_stream_immediately(id.outgoing_stream)?;
                                self.subscriptions.swap_remove(index);
                                return Ok(Some(Output::Subscription {
                                    id,
                                    res: SubscriptionResponse::MultistreamProtocolError,
                                }))
                            }
                        }
                    },
                    // Once we are waiting on the inbound stream we shouldn't get anything else on this outbound stream.
                    SubscriptionState::AwaitingInboundConnection { .. } | SubscriptionState::AwaitingInboundHandshake { .. } => {
                        self.yamux.close_stream_immediately(sub.outgoing_stream)?;
                        self.subscriptions.swap_remove(index);
                        return Ok(Some(Output::Subscription {
                            id,
                            res: SubscriptionResponse::MultistreamProtocolError,
                        }))
                    },
                    SubscriptionState::InboundWaitingForData { inbound_stream_id } => {
                        self.yamux.close_stream_immediately(sub.outgoing_stream)?;
                        self.yamux.close_stream_immediately(*inbound_stream_id)?;
                        self.subscriptions.swap_remove(index);
                        return Ok(Some(Output::Subscription {
                            id,
                            res: SubscriptionResponse::MultistreamProtocolError,
                        }))
                    },
                }
            }

            // ----------------------------------
            // Is this a message on an incoming subscription stream that we are interested in
            // ----------------------------------
            let iter = self
                .subscriptions
                .iter()
                .position(|s| {
                    // If the inbound stream ID matches then this lines up
                    s.state.inbound_stream_id() == Some(stream_id) 
                    // OR if the protocol matches
                    || matches!(&output.state, OutputState::IncomingProtocol(p) if p == &s.protocol_name)
                });

            if let Some(index) = iter {
                let sub = &mut self.subscriptions[index];
                let id = SubscriptionId { outgoing_stream: sub.outgoing_stream };
                match &mut sub.state {
                    // We are waiting for an inbound stream with this protocol.
                    SubscriptionState::AwaitingInboundConnection { our_handshake, their_first_handshake } => {
                        match output.state {
                            // We got an inbound stream with the matching protocol
                            OutputState::IncomingProtocol(_) => {
                                let our_handshake = core::mem::take(our_handshake);
                                let their_first_handshake = core::mem::take(their_first_handshake);
                                sub.state = SubscriptionState::AwaitingInboundHandshake { 
                                    inbound_stream_id: stream_id,
                                    our_handshake, 
                                    their_first_handshake 
                                };
                                continue
                            },
                            // Everything else is unexpected.
                            _ => {
                                self.yamux.close_stream_immediately(sub.outgoing_stream)?;
                                self.yamux.close_stream_immediately(output.stream_id)?;
                                self.subscriptions.swap_remove(index);
                                return Ok(Some(Output::Subscription {
                                    id,
                                    res: SubscriptionResponse::MultistreamProtocolError,
                                }))
                            },
                        }
                    },
                    // We are waiting for a handshake on the inbound stream
                    SubscriptionState::AwaitingInboundHandshake { inbound_stream_id, our_handshake, their_first_handshake } => {
                        match output.state {
                            // They gave us handshake bytes and they match their first handshake; good.
                            // If it's valid then send ours to them on this inbound stream.
                            OutputState::Data(their_second_handshake) if their_first_handshake == &their_second_handshake => {
                                if !(sub.validation_function)(their_second_handshake) {
                                    return Ok(Some(Output::Subscription { 
                                        id, 
                                        res: SubscriptionResponse::TheirHandshakeRejected
                                    }));
                                }

                                let inbound_stream_id = *inbound_stream_id;
                                self.yamux.send_data(inbound_stream_id, &our_handshake)?;
                                sub.state = SubscriptionState::InboundWaitingForData { inbound_stream_id };
                                continue
                            },
                            // Everything else is unexpected.
                            _ => {
                                self.yamux.close_stream_immediately(sub.outgoing_stream)?;
                                self.yamux.close_stream_immediately(*inbound_stream_id)?;
                                self.subscriptions.swap_remove(index);
                                return Ok(Some(Output::Subscription {
                                    id,
                                    res: SubscriptionResponse::MultistreamProtocolError,
                                }))
                            },
                        }
                    },
                    // We are waiting for data (or for them to reject our handshake)
                    SubscriptionState::InboundWaitingForData { inbound_stream_id } => {
                        match output.state {
                            // Emit any data we receive on this stream.
                            OutputState::Data(bytes) => {
                                return Ok(Some(Output::Subscription { 
                                    id, 
                                    res: SubscriptionResponse::Data(bytes)
                                }))
                            },
                            // Close the stream when the remote closes, also closing
                            // our outbound stream.
                            OutputState::Closed => {
                                self.yamux.close_stream_immediately(sub.outgoing_stream)?;
                                self.yamux.close_stream_immediately(*inbound_stream_id)?;
                                self.subscriptions.swap_remove(index);
                                return Ok(Some(Output::Subscription {
                                    id,
                                    res: SubscriptionResponse::Closed,
                                }))
                            },
                            // Unexpected; protocol error
                            _ => {
                                self.yamux.close_stream_immediately(sub.outgoing_stream)?;
                                self.yamux.close_stream_immediately(*inbound_stream_id)?;
                                self.subscriptions.swap_remove(index);
                                return Ok(Some(Output::Subscription {
                                    id,
                                    res: SubscriptionResponse::MultistreamProtocolError,
                                }))
                            }
                        }
                    },
                    // Everything else shouldn't be possible. Just return protocol error
                    _ => {
                        self.yamux.close_stream_immediately(sub.outgoing_stream)?;
                        self.yamux.close_stream_immediately(output.stream_id)?;
                        self.subscriptions.swap_remove(index);
                        return Ok(Some(Output::Subscription {
                            id,
                            res: SubscriptionResponse::MultistreamProtocolError,
                        }))
                    }
                }
            }

            // ----------------------------------
            // Is this a message that doesn't relate to any stream we are expecting/interested in?
            // ----------------------------------

            // For now we just close any stream we don't know about and ignore it.
            self.yamux.close_stream_immediately(output.stream_id)?;
            continue
        }
    }
}


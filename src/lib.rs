//! This crate is used to establish a peer-to-peer connection with a node on the Polkadot network.

#![no_std]
#![deny(missing_docs)]

extern crate alloc;

mod layers;
mod utils;
mod error;

use core::marker::PhantomData;
use core::future::Future;
use alloc::collections::{BTreeMap, vec_deque::VecDeque};
use alloc::vec::Vec;
use alloc::string::String;
use alloc::boxed::Box;
use utils::peer_id;
use layers::{
    multistream,
    noise,
    yamux,
    yamux_multistream::{self, YamuxStreamId},
};

// Re-export anything that is part of the public APIs.
pub use crate::utils::peer_id::PeerId;
pub use crate::error::{ ConnectionError, StreamError, ProtocolError };
pub use crate::utils::async_stream::{AsyncStream, Error as AsyncStreamError};

// -----------------------------------------------------------
// Platform
// -----------------------------------------------------------

/// This trait provides any core features that we need which may vary by platform.
pub trait PlatformT {
    /// Fill the given buffer with random bytes.
    fn fill_with_random_bytes(bytes: &mut [u8]);
    /// Returns Err(()) if the given future times out, else returns the output from the future.
    fn timeout<F: core::future::Future<Output = R>, R>(ms: usize, fut: F) -> impl Future<Output = Result<R, ()>>;
}

// -----------------------------------------------------------
// Configuration
// -----------------------------------------------------------

/// Configuration for connections.
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

    /// Set a static identity that will be used for all connections using this configuration.
    /// If this is not provided then a unique random identity will be created for each connection.
    pub fn with_identity(mut self, secret_bytes: [u8; 32]) -> Self {
        self.identity_secret = Some(secret_bytes);
        self
    }

    /// Connect to a peer given some read/write byte stream that has already been established with it.
    /// If we know the expected peer ID then we can use [`Self::connect_to_peer`] to provide this ID,
    /// which will then check that it is correct.
    pub async fn connect<Stream: AsyncStream>(&self, stream: Stream) -> Result<Connection<Stream, Platform>, ConnectionError> {
        Connection::from_stream(stream, self.identity_secret, None).await
    }

    /// Connect to a peer given some read/write byte stream that has already been established with it,
    /// and the expected identity of the peer. If the identity does not match then the connection will be rejected.
    pub async fn connect_to_peer<Stream: AsyncStream>(&self, stream: Stream, peer_id: PeerId) -> Result<Connection<Stream, Platform>, ConnectionError> {
        Connection::from_stream(stream, self.identity_secret, Some(peer_id)).await
    }
}

// -----------------------------------------------------------
// Connection
// -----------------------------------------------------------

/// A connection to a single peer.
pub struct Connection<Stream, Platform> {
    yamux: yamux_multistream::YamuxMultistream<noise::NoiseStream<Stream>>,
    remote_id: PeerId,
    our_id: PeerId,
    requests: BTreeMap<YamuxStreamId, RequestState>,
    subscriptions: Vec<SubscriptionDetails>,
    next_buf: VecDeque<Message>,
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

/// Some message received from the connected peer. We'll get back a single [`Message::Response`] for any
/// [`Connection::request()`] that we call, and a stream of [`Message::Notification`]s for any
/// [`Connection::subscribe()`] subscription that we create.
pub enum Message {
    /// A response to some [`Connection::request()`].
    Response {
        /// The [`RequestId`] that this message is for.
        id: RequestId,
        /// A response for this request.
        res: RequestResponse,
    },
    /// A notification for some [`Connection::subscribe()`] subscription.
    Notification {
        /// The [`SubscriptionId`] that this notification is for.
        id: SubscriptionId,
        /// A response for this subscription.
        res: SubscriptionResponse,
    }
}

/// A response to some [`Connection::request()`], found in a [`Message::Response`].
/// We receive back exactly response 1 per request.
pub enum RequestResponse {
    /// The response value.
    Value(Vec<u8>),
    /// The request was cancelled.
    Cancelled,
    /// Something went wrong.
    Error(RequestResponseError)
}

/// An error making a request.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum RequestResponseError {
    #[error("the remote rejected the protocol we handed it")]
    ProtocolRejected,
    #[error("the remote rejected the payload we handed it")]
    PayloadRejected,
    #[error("the remote did not follow our multistream request-response protocol")]
    MultistreamProtocolError,
}

/// A response to some [`Connection::request()`], found in a [`Message::Response`].
/// We receive back exactly response 1 per request.
pub enum SubscriptionResponse {
    /// A value received back on the given subscription.
    Value(Vec<u8>),
    /// The subscription was closed or cancelled. No more values will be handed back for it.
    Closed,
    /// Something went wrong with this subcription. No more values will be handed back for it.
    Error(SubscriptionResponseError),
}

/// An error subscribing or receiving subscription responses.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum SubscriptionResponseError {
    #[error("the remote rejected the protocol we handed it")]
    ProtocolRejected,
    #[error("the remote rejected our handshake")]
    OurHandshakeRejected,
    #[error("our handshake validation function rejected the remote handshake")]
    TheirHandshakeRejected,
    #[error("the remote did not follow our multistream notification protocol")]
    MultistreamProtocolError,
}

/// An ID which identifies some [`Connection::request`] call. The response related to this 
/// request will be returned with a matching ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(YamuxStreamId);

/// An ID which identifies some [`Connection::subscribe`] call. All responses related to this 
/// subscription will be returned with a matching ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubscriptionId {
    outgoing_stream: YamuxStreamId
}

enum RequestState {
    AwaitingProtocolConfirmation(Vec<u8>),
    AwaitingResponsePayload,
}

impl <Stream: AsyncStream, Platform: PlatformT> Connection<Stream, Platform> {
    async fn from_stream(
        mut stream: Stream, 
        identity_secret: Option<[u8; 32]>,
        remote_peer_id: Option<PeerId>
    ) -> Result<Self, ConnectionError> {
        // TODO: Make these configurable.
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
                Platform::fill_with_random_bytes(&mut random_bytes);
                peer_id::Identity::from_random_bytes(random_bytes)
            }
        };

        // Establish our encrypted noise session and find the remote Peer ID
        let (mut noise_stream, remote_id) = Platform::timeout(NOISE_HANDSHAKE_TIMEOUT_MS, noise::handshake_dialer::<_, Platform>(stream, &identity, remote_peer_id.as_ref()))
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
            our_id: identity.peer_id(),
            requests: Default::default(),
            subscriptions: Default::default(),
            next_buf: Default::default(),
            marker: PhantomData
        })
    }

    /// The peer ID that we have used for this connection.
    pub fn our_id(&self) -> &PeerId {
        &self.our_id
    }

    /// The connected peer's ID.
    pub fn their_id(&self) -> &PeerId {
        &self.remote_id
    }

    /// Make a request to some protocol name (essentially the unique ID/path for the request) and request body.
    /// This returns a [`RequestId`]. We will get back exactly one response using this ID from [`Self::next`].
    pub fn request(&mut self, protocol: &str, request: Vec<u8>) -> Result<RequestId, ConnectionError> {
        // Open a stream.
        let stream_id = self.yamux.open_stream(Some(protocol))?;

        // Save the request to send once the stream is open.
        self.requests.insert(stream_id, RequestState::AwaitingProtocolConfirmation(request));

        Ok(RequestId(stream_id))
    }

    /// Cancel a request. This makes a best-effort attempt to cancel an in-flight request when driven by [`Self::next`], 
    /// and will lead to a [`RequestResponse::Cancelled`] message being emitted for the given request ID.
    pub fn cancel_request(&mut self, id: RequestId) {
        self.requests.remove(&id.0);
        let _ = self.yamux.close_stream(id.0);
        self.next_buf.push_back(Message::Response { 
            id, 
            res: RequestResponse::Cancelled,
        });
    }

    /// Subscribe to some protocol name (essentially the unique ID/path for the subscription) and a handshake.
    /// This returns a [`SubscriptionId`]. We will get back a stream of notification messages against this ID when
    /// call [`Self::next`], until the subscription is closed, cancelled or returns an error.
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

    /// Cancel a subscription. This makes a best-effort attempt to cancel an in-flight subscription when driven by [`Self::next`], 
    /// and will lead to a [`SubscriptionResponse::Closed`] message being emitted for the given subscription ID.
    pub fn cancel_subscription(&mut self, id: SubscriptionId) {
        let Some(index) = self.subscriptions.iter().position(|s| s.outgoing_stream == id.outgoing_stream) else {
            return
        };

        // Close the subscription streams associated with this:
        let sub = &self.subscriptions[index];
        let _ = self.yamux.close_stream(sub.outgoing_stream);
        if let Some(inbound_id) = sub.state.inbound_stream_id() {
            let _ = self.yamux.close_stream(inbound_id);
        }

        // Remove our knowledge of the subscription
        self.subscriptions.swap_remove(index);

        self.next_buf.push_back(Message::Notification { 
            id, 
            res: SubscriptionResponse::Closed,
        });
    }

    /// Drive this connection, making progress and returning messages as they are received.
    pub async fn next(&mut self) -> Option<Result<Message, StreamError>> {
        self.next_inner().await.transpose()
    }

    async fn next_inner(&mut self) -> Result<Option<Message>, StreamError> {
        loop {
            // Drain any local messages we need to emit first
            while let Some(message) = self.next_buf.pop_front() {
                return Ok(Some(message))
            }

            // Pull the next message from our yamux multistreams.
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
                                return Ok(Some(Message::Response {
                                    id: RequestId(stream_id),
                                    res: RequestResponse::Error(RequestResponseError::ProtocolRejected),
                                }))
                            },
                            // If we see anything else then protocol is not being followed.
                            // Close the stream and return the error to the user.
                            _ => {
                                self.requests.remove(&stream_id);
                                self.yamux.close_stream_immediately(stream_id)?;
                                return Ok(Some(Message::Response {
                                    id: RequestId(stream_id),
                                    res: RequestResponse::Error(RequestResponseError::MultistreamProtocolError),
                                }))
                            },
                        }
                    },
                    RequestState::AwaitingResponsePayload => {
                        match output.state {
                            // We got a response back! Give it to the user.
                            OutputState::Data(bytes) => {
                                self.requests.remove(&stream_id);
                                return Ok(Some(Message::Response {
                                    id: RequestId(stream_id),
                                    res: RequestResponse::Value(bytes),
                                }))
                            }
                            // If the payload is invalid, we will either get a valid
                            // application-level response (ie above), or the substream 
                            // will simply be closed.
                            OutputState::Closed => {
                                self.requests.remove(&stream_id);
                                return Ok(Some(Message::Response {
                                    id: RequestId(stream_id),
                                    res: RequestResponse::Error(RequestResponseError::PayloadRejected),
                                }))
                            },
                            // If we see anything else then protocol is not being followed.
                            // Close the stream and return the error to the user.
                            _ => {
                                self.requests.remove(&stream_id);
                                self.yamux.close_stream_immediately(stream_id)?;
                                return Ok(Some(Message::Response {
                                    id: RequestId(stream_id),
                                    res: RequestResponse::Error(RequestResponseError::MultistreamProtocolError),
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
                                return Ok(Some(Message::Notification {
                                    id,
                                    res: SubscriptionResponse::Error(SubscriptionResponseError::ProtocolRejected),
                                }))
                            }
                            // Anything else is invalid and is a protocol error.
                            _ => {
                                self.yamux.close_stream_immediately(id.outgoing_stream)?;
                                self.subscriptions.swap_remove(index);
                                return Ok(Some(Message::Notification {
                                    id,
                                    res: SubscriptionResponse::Error(SubscriptionResponseError::MultistreamProtocolError),
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
                                return Ok(Some(Message::Notification {
                                    id,
                                    res: SubscriptionResponse::Error(SubscriptionResponseError::OurHandshakeRejected),
                                }))
                            },
                            // Anything else is invalid and is a protocol error.
                            _ => {
                                self.yamux.close_stream_immediately(id.outgoing_stream)?;
                                self.subscriptions.swap_remove(index);
                                return Ok(Some(Message::Notification {
                                    id,
                                    res: SubscriptionResponse::Error(SubscriptionResponseError::MultistreamProtocolError),
                                }))
                            }
                        }
                    },
                    // Once we are waiting on the inbound stream we shouldn't get anything else on this outbound stream.
                    SubscriptionState::AwaitingInboundConnection { .. } | SubscriptionState::AwaitingInboundHandshake { .. } => {
                        self.yamux.close_stream_immediately(sub.outgoing_stream)?;
                        self.subscriptions.swap_remove(index);
                        return Ok(Some(Message::Notification {
                            id,
                            res: SubscriptionResponse::Error(SubscriptionResponseError::MultistreamProtocolError),
                        }))
                    },
                    SubscriptionState::InboundWaitingForData { inbound_stream_id } => {
                        self.yamux.close_stream_immediately(sub.outgoing_stream)?;
                        self.yamux.close_stream_immediately(*inbound_stream_id)?;
                        self.subscriptions.swap_remove(index);
                        return Ok(Some(Message::Notification {
                            id,
                            res: SubscriptionResponse::Error(SubscriptionResponseError::MultistreamProtocolError),
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
                                self.yamux.accept_protocol(stream_id)?;
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
                                return Ok(Some(Message::Notification {
                                    id,
                                    res: SubscriptionResponse::Error(SubscriptionResponseError::MultistreamProtocolError),
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
                                    return Ok(Some(Message::Notification { 
                                        id, 
                                        res: SubscriptionResponse::Error(SubscriptionResponseError::TheirHandshakeRejected)
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
                                return Ok(Some(Message::Notification {
                                    id,
                                    res: SubscriptionResponse::Error(SubscriptionResponseError::MultistreamProtocolError),
                                }))
                            },
                        }
                    },
                    // We are waiting for data (or for them to reject our handshake)
                    SubscriptionState::InboundWaitingForData { inbound_stream_id } => {
                        match output.state {
                            // Emit any data we receive on this stream.
                            OutputState::Data(bytes) => {
                                return Ok(Some(Message::Notification { 
                                    id, 
                                    res: SubscriptionResponse::Value(bytes)
                                }))
                            },
                            // Close the stream when the remote closes, also closing
                            // our outbound stream.
                            OutputState::Closed => {
                                self.yamux.close_stream_immediately(sub.outgoing_stream)?;
                                self.yamux.close_stream_immediately(*inbound_stream_id)?;
                                self.subscriptions.swap_remove(index);
                                return Ok(Some(Message::Notification {
                                    id,
                                    res: SubscriptionResponse::Closed,
                                }))
                            },
                            // Unexpected; protocol error
                            _ => {
                                self.yamux.close_stream_immediately(sub.outgoing_stream)?;
                                self.yamux.close_stream_immediately(*inbound_stream_id)?;
                                self.subscriptions.swap_remove(index);
                                return Ok(Some(Message::Notification {
                                    id,
                                    res: SubscriptionResponse::Error(SubscriptionResponseError::MultistreamProtocolError),
                                }))
                            }
                        }
                    },
                    // Everything else shouldn't be possible. Just return protocol error
                    _ => {
                        self.yamux.close_stream_immediately(sub.outgoing_stream)?;
                        self.yamux.close_stream_immediately(output.stream_id)?;
                        self.subscriptions.swap_remove(index);
                        return Ok(Some(Message::Notification {
                            id,
                            res: SubscriptionResponse::Error(SubscriptionResponseError::MultistreamProtocolError),
                        }))
                    }
                }
            }

            // ----------------------------------
            // Is this a message that doesn't relate to any stream we are expecting/interested in?
            // ----------------------------------

            // For now we just close/reject any streams we don't know about or want. The request/subscription
            // may have been cancelled while a response was inbound.
            match output.state {
                OutputState::IncomingProtocol(_) => {
                    self.yamux.reject_protocol(stream_id)?;
                },
                OutputState::OutgoingRejected | OutputState::OutgoingAccepted(_) | OutputState::Data(_) => {
                    self.yamux.close_stream_immediately(output.stream_id)?;
                },
                OutputState::Closed => {
                    // Nothing to do; the now-unknown stream has closed.
                },
            }
        }
    }
}


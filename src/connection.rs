use alloc::collections::{BTreeMap, vec_deque::VecDeque};
use alloc::vec::Vec;
use core::pin::pin;
use crate::layers::{
    multistream, noise, yamux,
    yamux_multistream::{self, YamuxStreamId},
};
use crate::configuration::Configuration;
use crate::utils::peer_id;
use crate::utils::timers::Timers;
use crate::layers::yamux_multistream::CloseReason;
use crate::platform::PlatformT;
use crate::protocol::{RequestProtocol, RequestProtocolId, SubscriptionProtocol, SubscriptionProtocolId};
use crate::error::{ConnectionError, StreamError};
use crate::utils::async_stream::{AsyncRead, AsyncWrite};
use crate::utils::peer_id::PeerId;
use crate::platform;

/// A connection to a single peer.
pub struct Connection<R, W, Platform: PlatformT> {
    yamux: yamux_multistream::YamuxMultistream<noise::NoiseReadStream<R>, noise::NoiseWriteStream<W>>,
    remote_id: PeerId,
    our_id: PeerId,
    subscription_details: Vec<SubscriptionDetails>,
    request_details: Vec<RequestDetails<Platform>>,
    incoming_requests: BTreeMap<YamuxStreamId, RequestProtocolId>,
    inflight_requests: BTreeMap<YamuxStreamId, (RequestProtocolId, RequestState)>,
    next_buf: VecDeque<Message>,
    finished: bool,
}

// SAFETY: `Connection` is not `Send` by default because some `Rc<RefCell<..>>`
// Types exist internally. 
//
// We would have an issue if it were possible to get hold of any clones of `Rc`s and then send 
// `Connection` to a different thread, leaving an Rc split across two threads. (This is an issue
// because the Rc cannot atomically update its reference count, and the inner RefCell cannot 
// atomically set its borrowed flag or atomically share the inner data).
//
// HOWEVER, since no Rc/RefCell type is exposed in the public API of `Connection`, it is 
// impossible to end up in a position where any Rc type is split across two threads: they are
// all entirely contained in whichever thread the `Connection` is on.
unsafe impl<R: Send, W: Send, Platform: Send + PlatformT> Send
    for Connection<R, W, Platform> {}

enum RequestState {
    AwaitingProtocolConfirmation(Vec<u8>),
    AwaitingResponsePayload,
}

struct RequestDetails<Platform: PlatformT> {
    protocol_id: RequestProtocolId,
    protocol: RequestProtocol,
    timeouts: Option<Timers<YamuxStreamId, Platform>>,
}

struct SubscriptionDetails {
    protocol_id: SubscriptionProtocolId,
    protocol: SubscriptionProtocol,
    our_stream: SubscriptionStreamState,
    their_stream: SubscriptionStreamState,
}

impl SubscriptionDetails {
    fn inbound_stream_id(&self) -> Option<YamuxStreamId> {
        self.their_stream.stream_id()
    }
    fn outbound_stream_id(&self) -> Option<YamuxStreamId> {
        self.our_stream.stream_id()
    }
}

enum SubscriptionStreamState {
    Closed,
    Handshake { stream_id: YamuxStreamId },
    Open { stream_id: YamuxStreamId },
}

impl SubscriptionStreamState {
    fn is_closed(&self) -> bool {
        matches!(self, SubscriptionStreamState::Closed)
    }
    fn is_open(&self) -> bool {
        matches!(self, SubscriptionStreamState::Open { .. })
    }
    fn stream_id(&self) -> Option<YamuxStreamId> {
        match self {
            Self::Handshake { stream_id } | Self::Open { stream_id } => Some(*stream_id),
            _ => None,
        }
    }
}

/// Some message received from the connected peer. We'll get back a single [`Message::Response`] for any
/// [`Connection::request()`] that we call, and a stream of [`Message::Notification`]s for any
/// [`Connection::subscribe()`] subscription that we create.
#[derive(Debug, Clone)]
pub enum Message {
    /// An incoming request. Respond with [`Connection::respond()`].
    Request {
        /// The ID to use to respond to this request.
        id: ResponseId,
        /// The protocol that this request is for.
        protocol_id: RequestProtocolId,
        /// The request bytes.
        req: Request,
    },
    /// A response to some [`Connection::request()`].
    Response {
        /// The [`RequestId`] that this message is for.
        id: RequestId,
        /// The protocol that this message is for.
        protocol_id: RequestProtocolId,
        /// A response for this request.
        res: RequestResponse,
    },
    /// A notification for some [`Connection::subscribe()`] subscription.
    Notification {
        /// The [`SubscriptionProtocolId`] that this notification is for.
        protocol_id: SubscriptionProtocolId,
        /// A response for this subscription.
        res: SubscriptionResponse,
    },
}

/// An ID to use to respond to some incoming request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResponseId(YamuxStreamId);

/// An incoming request.
#[derive(Debug, Clone)]
pub enum Request {
    /// The incoming request payload.
    Value(Vec<u8>),
    /// The remote cancelled their request.
    Cancelled,
    /// The remote payload was too large so the request was dropped.
    ErrorPayloadTooLarge,
}

/// An ID which identifies some [`Connection::request`] call. The response related to this
/// request will be returned with a matching ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(YamuxStreamId);

/// A response to some [`Connection::request()`], found in a [`Message::Response`].
/// We receive back exactly response 1 per request.
#[derive(Debug, Clone)]
pub enum RequestResponse {
    /// The response value.
    Value(Vec<u8>),
    /// The request was cancelled.
    Cancelled,
    /// Something went wrong.
    Error(RequestResponseError),
}

/// An error making a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[allow(missing_docs)]
pub enum RequestResponseError {
    #[error("the request timed out waiting for a response")]
    Timeout,
    #[error("the remote rejected the protocol we handed it")]
    ProtocolRejected,
    #[error("the remote rejected the payload we handed it")]
    PayloadRejected,
    #[error("the remote payload is too large")]
    RemotePayloadTooLarge,
    #[error("the remote did not follow our multistream request-response protocol")]
    MultistreamProtocolError,
}

/// A response to some [`Connection::subscribe()`], found in a [`Message::Notification`].
#[derive(Debug, Clone)]
pub enum SubscriptionResponse {
    /// the subscription stream has been opened and is ready for sending and receiving.
    /// Sending can now be done using [`Connection::send_notification()`].
    Opened,
    /// A value received back on the given subscription.
    Value(Vec<u8>),
    /// The subscription was closed or cancelled. No more values will be handed back for it.
    Closed,
    /// Something went wrong with this subcription. No more values will be handed back for it.
    Error(SubscriptionResponseError),
}

/// An error subscribing or receiving subscription responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[allow(missing_docs)]
pub enum SubscriptionResponseError {
    #[error("the remote rejected the protocol we handed it")]
    ProtocolRejected,
    #[error("the remote rejected our handshake")]
    OurHandshakeRejected,
    #[error("our handshake validation function rejected the remote handshake")]
    TheirHandshakeRejected,
    #[error("a remote message payload is too large")]
    RemotePayloadTooLarge,
    #[error("the remote did not follow our multistream notification protocol")]
    MultistreamProtocolError,
}

impl<R: AsyncRead + 'static, W: AsyncWrite + 'static, Platform: PlatformT> Connection<R, W, Platform> {
    pub (crate) async fn from_stream(
        config: &Configuration<Platform>,
        mut reader: R,
        mut writer: W,
        remote_peer_id: Option<PeerId>,
    ) -> Result<Self, ConnectionError> {
        // Agree to use the noise protocol.
        {
            let negotiate_fut = multistream::negotiate_dialer(
                &mut reader, 
                &mut writer, 
                "/noise"
            );
            let negotiate_fut = pin!(negotiate_fut);
            platform::timeout::<Platform, _, _>(config.multistream_timeout, negotiate_fut)
                .await
                .map_err(|()| ConnectionError::NoiseNegotiationTimeout)??;
        }

        // Generate/use an identity for ourselves.
        let identity = match config.identity_secret {
            Some(key) => peer_id::Identity::from_random_bytes(key),
            None => {
                let mut random_bytes = [0u8; 32];
                Platform::fill_with_random_bytes(&mut random_bytes);
                peer_id::Identity::from_random_bytes(random_bytes)
            }
        };

        // Establish our encrypted noise session and find the remote Peer ID
        let handshake_fut = noise::handshake_dialer::<R, W, Platform>(
            reader,
            writer, 
            &identity, 
            remote_peer_id.as_ref()
        );
        let handshake_fut = pin!(handshake_fut);
        let (mut noise_read_stream, mut noise_write_stream, remote_id) =
            platform::timeout::<Platform, _, _>(config.noise_timeout, handshake_fut)
                .await
                .map_err(|()| ConnectionError::NoiseHandshakeTimeout)??;

        // Agree to use the yamux protocol in this noise stream.
        {
            let yamux_fut = multistream::negotiate_dialer(
                &mut noise_read_stream, 
                &mut noise_write_stream,
                "/yamux/1.0.0"
            );
            let yamux_fut = pin!(yamux_fut);
            platform::timeout::<Platform, _, _>(config.multistream_timeout, yamux_fut)
                .await
                .map_err(|()| ConnectionError::YamuxNegotiationTimeout)??;
        }

        // Wrap our noise stream in a yamux session (we'll be using yamux substreams), and wrap
        // that in a YamuxMultistream adaptor to handle multistream negotiation on top of these
        // substreams.
        let yamux_session = yamux::YamuxSession::new(noise_read_stream, noise_write_stream);
        let yamux_multistream = yamux_multistream::YamuxMultistream::new(yamux_session);

        // Save our subscription details.
        let subscriptions = config
            .protocols
            .iter()
            .filter_map(|(id, p)| p.as_subscription().map(|p| (id, p)))
            .map(|(id, p)| SubscriptionDetails {
                protocol_id: SubscriptionProtocolId(id.get()),
                protocol: p.clone(),
                our_stream: SubscriptionStreamState::Closed,
                their_stream: SubscriptionStreamState::Closed,
            })
            .collect();

        // And our request protocol details
        let requests = config
            .protocols
            .iter()
            .filter_map(|(id, p)| p.as_request().map(|p| (id, p)))
            .map(|(id, p)| RequestDetails {
                protocol_id: RequestProtocolId(id.get()),
                protocol: p.clone(),
                timeouts: p.timeout.map(|d| Timers::new(d)),
            })
            .collect();

        Ok(Connection {
            yamux: yamux_multistream,
            remote_id,
            our_id: identity.peer_id(),
            request_details: requests,
            incoming_requests: Default::default(),
            inflight_requests: Default::default(),
            subscription_details: subscriptions,
            next_buf: Default::default(),
            finished: false,
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

    /// Make a request to some protocol by providing the ID for that protocol and request body. 
    /// 
    /// The required [`RequestProtocolId`] is handed back from calling [`Configuration::add_protocol()`]
    /// with a [`RequestProtocol`].
    /// 
    /// This returns a [`RequestId`]. We will eventually get back exactly one [`Message::Response`] 
    /// with this [`RequestId`] from [`Self::next`].
    pub fn request(
        &mut self,
        protocol_id: RequestProtocolId,
        request: Vec<u8>,
    ) -> Result<RequestId, ConnectionError> {
        // Find the protocol details
        let Some(p) = self
            .request_details
            .iter_mut()
            .find(|p| p.protocol_id == protocol_id)
        else {
            return Err(ConnectionError::RequestProtocolNotFound(protocol_id));
        };

        // Open a stream.
        let stream_id = self.yamux.open_stream(
            Some(&p.protocol.name),
            p.protocol.max_response_size_in_bytes,
        )?;

        // If there is a timeout configured then add it.
        if let Some(timeouts) = &mut p.timeouts {
            timeouts.add(stream_id);
        }

        // Save the request to send once the stream is open.
        self.inflight_requests.insert(
            stream_id,
            (
                protocol_id,
                RequestState::AwaitingProtocolConfirmation(request),
            ),
        );

        Ok(RequestId(stream_id))
    }

    /// Cancel a request. This makes a best-effort attempt to cancel an in-flight request when 
    /// [`Self::next`] is called, and will lead to a [`RequestResponse::Cancelled`] message being 
    /// emitted for the given request ID.
    pub fn cancel_request(&mut self, id: RequestId) {
        let Some((protocol_id, _)) = self.inflight_requests.remove(&id.0) else {
            return;
        };

        // RST the stream here because we want to abort and for the peer to not
        // send anything back (which they are free to still do if FIN)
        let _ = self.yamux.reset_stream_immediately(id.0);
        self.next_buf.push_back(Message::Response {
            id,
            protocol_id,
            res: RequestResponse::Cancelled,
        });
    }

    /// Make a best effort to respond to an incoming request. If they close the stream (ie cancel the 
    /// request) before we manage to send our response then the response is silently dropped.
    pub fn respond(&mut self, id: ResponseId, response: &[u8]) {
        let _ = self.yamux.send_data(id.0, response);
        let _ = self.yamux.close_stream(id.0);
    }

    /// Begin the subscription on one of our subscription protocols. 
    /// 
    /// The required [`SubscriptionProtocolId`] is handed back from calling [`Configuration::add_protocol()`]
    /// with a [`SubscriptionProtocol`].
    /// 
    /// We will get back a stream of notification messages against the provided [`SubscriptionProtocolId`] 
    /// when [`Self::next`] is called, until the subscription is closed, cancelled or returns an error.
    pub fn subscribe(
        &mut self,
        protocol_id: SubscriptionProtocolId,
    ) -> Result<(), ConnectionError> {
        // Find the protocol
        let Some(p) = self
            .subscription_details
            .iter_mut()
            .find(|p| p.protocol_id == protocol_id)
        else {
            return Err(ConnectionError::SubscriptionProtocolNotFound(protocol_id));
        };

        // If already open then we've already kicked this off so complain.
        if !p.our_stream.is_closed() {
            return Err(ConnectionError::AlreadySubscribed(p.protocol_id));
        }

        // Open an outbound stream.
        let stream_id = self.yamux.open_stream(
            Some(&p.protocol.name),
            p.protocol.max_response_size_in_bytes,
        )?;
        p.our_stream = SubscriptionStreamState::Handshake { stream_id };

        Ok(())
    }

    /// Send a notification on a subscription. 
    ///
    /// The required [`SubscriptionProtocolId`] is handed back from calling [`Configuration::add_protocol()`]
    /// with a [`SubscriptionProtocol`].
    ///  
    /// The subscription must have already been opened by calling [`Connection::subscribe`] (or the remote
    /// opening it if we allow this), and then waiting for a [`SubscriptionResponse::Opened`] event from
    /// [`Self::next`] which indicates that it has been successfully opened. Else, we will get an error back
    /// from calling this.
    pub fn send_notification(
        &mut self,
        protocol_id: SubscriptionProtocolId,
        notif: &[u8],
    ) -> Result<(), ConnectionError> {
        // Find the protocol
        let Some(p) = self
            .subscription_details
            .iter_mut()
            .find(|p| p.protocol_id == protocol_id)
        else {
            return Err(ConnectionError::SubscriptionProtocolNotFound(protocol_id));
        };

        match p.our_stream {
            SubscriptionStreamState::Closed => {
                Err(ConnectionError::SubscriptionClosed(protocol_id))
            }
            SubscriptionStreamState::Handshake { .. } => {
                Err(ConnectionError::SubscriptionNotReady(protocol_id))
            }
            SubscriptionStreamState::Open { stream_id } => {
                self.yamux.send_data(stream_id, notif)?;
                Ok(())
            }
        }
    }

    /// Cancel a subscription. This makes a best-effort attempt to cancel an in-flight subscription when driven by [`Self::next`],
    /// and will lead to a [`SubscriptionResponse::Closed`] message being emitted for the given subscription ID.
    pub fn cancel_subscription(&mut self, id: SubscriptionProtocolId) {
        if self.cancel_subscription_silently(id) {
            self.next_buf.push_back(Message::Notification {
                protocol_id: id,
                res: SubscriptionResponse::Closed,
            });
        }
    }

    // Silently cancel a subscription (ie don't emit any messages). 
    // Returns true if a subscription was cancelled, and false if not.
    fn cancel_subscription_silently(&mut self, id: SubscriptionProtocolId) -> bool {
        // Find the protocol
        let Some(p) = self
            .subscription_details
            .iter_mut()
            .find(|p| p.protocol_id == id)
        else {
            return false;
        };

        // Immediately abort any open streams here to tell the peer to also
        // not send any further messages on them.
        if let Some(outgoing_stream_id) = p.our_stream.stream_id() {
            let _ = self.yamux.reset_stream_immediately(outgoing_stream_id);
        };
        if let Some(incoming_stream_id) = p.their_stream.stream_id() {
            let _ = self.yamux.reset_stream_immediately(incoming_stream_id);
        };

        p.our_stream = SubscriptionStreamState::Closed;
        p.their_stream = SubscriptionStreamState::Closed;
        true
    }

    /// Drive this connection, concurrently writing and reading from our read and write streams
    /// and returning once the next message is available on the read stream.
    /// 
    /// # Cancel safety
    /// 
    /// This method is cancel safe and the resulting future can be safely dropped.
    pub async fn next(&mut self) -> Option<Result<Message, StreamError>> {
        if self.finished {
            return None;
        }

        match self.next_inner().await {
            Ok(None) => {
                self.finished = true;
                None
            }
            Err(e) => {
                self.finished = true;
                Some(Err(e))
            }
            Ok(Some(msg)) => Some(Ok(msg)),
        }
    }

    async fn next_inner(&mut self) -> Result<Option<Message>, StreamError> {
        loop {
            // Drain any local messages we need to emit first
            while let Some(message) = self.next_buf.pop_front() {
                return Ok(Some(message));
            }

            // Look for and handle any timed out requests next
            if let Some(message) = self.handle_request_timeouts() {
                return Ok(Some(message));
            }

            // Pull the next message from our yamux multistreams.
            let output = match self.yamux.next().await {
                Some(Ok(output)) => output,
                Some(Err(e)) => return Err(e.into()),
                None => return Ok(None),
            };

            let stream_id = output.stream_id;

            use yamux_multistream::OutputState;

            if let Some((protocol_id, info)) = self.inflight_requests.get_mut(&stream_id) {
                // ----------------------------------
                // Is this a message on a request stream that we are expecting a single response on?
                // ----------------------------------

                let protocol_id = *protocol_id;
                match info {
                    RequestState::AwaitingProtocolConfirmation(request) => {
                        match output.state {
                            // The protocol has been accepted, so send the request payload and
                            // start waiting for the response.
                            OutputState::OutgoingAccepted(_) => {
                                self.yamux.send_data(stream_id, &core::mem::take(request))?;
                                *info = RequestState::AwaitingResponsePayload;
                            }
                            // Else if the protocol is invalid we'll relay that to the user.
                            OutputState::OutgoingRejected => {
                                self.inflight_requests.remove(&stream_id);
                                return Ok(Some(Message::Response {
                                    id: RequestId(stream_id),
                                    protocol_id,
                                    res: RequestResponse::Error(
                                        RequestResponseError::ProtocolRejected,
                                    ),
                                }));
                            }
                            // If we see anything else then protocol is not being followed.
                            // Close the stream and return the error to the user.
                            _ => {
                                self.inflight_requests.remove(&stream_id);
                                self.yamux.reset_stream_immediately(stream_id);
                                return Ok(Some(Message::Response {
                                    id: RequestId(stream_id),
                                    protocol_id,
                                    res: RequestResponse::Error(
                                        RequestResponseError::MultistreamProtocolError,
                                    ),
                                }));
                            }
                        }
                    }
                    RequestState::AwaitingResponsePayload => {
                        match output.state {
                            // We got a response back! Give it to the user.
                            OutputState::Data(bytes) => {
                                self.inflight_requests.remove(&stream_id);
                                self.yamux.close_stream_immediately(stream_id);
                                return Ok(Some(Message::Response {
                                    id: RequestId(stream_id),
                                    protocol_id,
                                    res: RequestResponse::Value(bytes),
                                }));
                            }
                            // If the payload is invalid, we will either get a valid
                            // application-level response (ie above), or the substream
                            // will simply be closed. Interpret the close reason as either
                            // the remot rejecting the request, or the payload being too big.
                            OutputState::Closed(reason) => {
                                self.inflight_requests.remove(&stream_id);
                                let error = match reason {
                                    CloseReason::ClosedByRemote => RequestResponseError::PayloadRejected,
                                    CloseReason::IncomingMessageTooLarge => RequestResponseError::RemotePayloadTooLarge,
                                };
                                return Ok(Some(Message::Response {
                                    id: RequestId(stream_id),
                                    protocol_id,
                                    res: RequestResponse::Error(error),
                                }));
                            }
                            // If we see anything else then protocol is not being followed.
                            // Close the stream and return the error to the user.
                            _ => {
                                self.inflight_requests.remove(&stream_id);
                                self.yamux.reset_stream_immediately(stream_id);
                                return Ok(Some(Message::Response {
                                    id: RequestId(stream_id),
                                    protocol_id,
                                    res: RequestResponse::Error(
                                        RequestResponseError::MultistreamProtocolError,
                                    ),
                                }));
                            }
                        }
                    }
                }
            } else if let Some(protocol_id) = self.incoming_requests.remove(&stream_id) {
                // ----------------------------------
                // Is this data on a known incoming request stream that we can respond to?
                // ----------------------------------

                match output.state {
                    OutputState::Data(payload) => {
                        return Ok(Some(Message::Request {
                            id: ResponseId(stream_id),
                            protocol_id,
                            req: Request::Value(payload),
                        }))
                    },
                    OutputState::Closed(CloseReason::ClosedByRemote) => {
                        return Ok(Some(Message::Request {
                            id: ResponseId(stream_id),
                            protocol_id,
                            req: Request::Cancelled,
                        }))
                    },
                    OutputState::Closed(CloseReason::IncomingMessageTooLarge) => {
                        return Ok(Some(Message::Request {
                            id: ResponseId(stream_id),
                            protocol_id,
                            req: Request::ErrorPayloadTooLarge,
                        }))
                    },
                    _ => {
                        // Anything else is a protocol error. Just close and ignore
                        // this. We've removed the request from our map anyway.
                        self.yamux.reset_stream_immediately(stream_id);
                    }
                }
            } else if let Some(p) = self
                .subscription_details
                .iter_mut()
                .find(|p| p.outbound_stream_id() == Some(stream_id))
            {
                // ----------------------------------
                // Is this a message back on an outgoing subscription stream that we opened.
                // ----------------------------------

                let protocol_id = p.protocol_id;
                match p.our_stream {
                    SubscriptionStreamState::Handshake { stream_id } => {
                        match output.state {
                            // They accepted our protocol, yay! Send our handshake.
                            OutputState::OutgoingAccepted(_) => {
                                self.yamux.send_data(stream_id, &p.protocol.our_handshake)?;
                            },
                            // They rejected our protocol, oh no! Emit a failed message and tidy up.
                            OutputState::OutgoingRejected => {
                                self.cancel_subscription_silently(protocol_id);
                                return Ok(Some(Message::Notification {
                                    protocol_id,
                                    res: SubscriptionResponse::Error(
                                        SubscriptionResponseError::ProtocolRejected,
                                    ),
                                }));
                            },
                            // Any data at this point must be their handshake.
                            OutputState::Data(their_handshake) => {
                                if (p.protocol.validate_their_handshake)(their_handshake) {
                                    // If their handshake is valid, our outbound is now open.
                                    p.our_stream = SubscriptionStreamState::Open { stream_id };
                                    // If both sides are open then we notify the user that
                                    // the subscription is open and ready now.
                                    if p.our_stream.is_open() && p.their_stream.is_open() {
                                        return Ok(Some(Message::Notification {
                                            protocol_id,
                                            res: SubscriptionResponse::Opened,
                                        }))
                                    }
                                } else {
                                    // Else it's all gone wrong, close and tidy.
                                    self.cancel_subscription_silently(protocol_id);
                                    return Ok(Some(Message::Notification {
                                        protocol_id,
                                        res: SubscriptionResponse::Error(
                                            SubscriptionResponseError::TheirHandshakeRejected,
                                        ),
                                    }));
                                }
                            },
                            // Closing at this stage means they rejected our handshake.
                            OutputState::Closed(CloseReason::ClosedByRemote) => {
                                self.cancel_subscription_silently(protocol_id);
                                return Ok(Some(Message::Notification {
                                    protocol_id,
                                    res: SubscriptionResponse::Error(
                                        SubscriptionResponseError::OurHandshakeRejected,
                                    ),
                                }));
                            },
                            // .. Or that the protocol message was too large.
                            OutputState::Closed(CloseReason::IncomingMessageTooLarge) => {
                                self.cancel_subscription_silently(protocol_id);
                                return Ok(Some(Message::Notification {
                                    protocol_id,
                                    res: SubscriptionResponse::Error(SubscriptionResponseError::RemotePayloadTooLarge),
                                }));
                            },
                            // This would make no sense given we initiated the stream.
                            OutputState::IncomingProtocol(_) => {
                                self.cancel_subscription_silently(protocol_id);
                                return Ok(Some(Message::Notification {
                                    protocol_id,
                                    res: SubscriptionResponse::Error(
                                        SubscriptionResponseError::MultistreamProtocolError,
                                    ),
                                }));
                            }
                        }
                    },
                    SubscriptionStreamState::Open { .. } => {
                        match output.state {
                            OutputState::Closed(CloseReason::ClosedByRemote) => {
                                self.cancel_subscription_silently(protocol_id);
                                return Ok(Some(Message::Notification {
                                    protocol_id,
                                    res: SubscriptionResponse::Closed,
                                }));
                            },
                            OutputState::Closed(CloseReason::IncomingMessageTooLarge) => {
                                self.cancel_subscription_silently(protocol_id);
                                return Ok(Some(Message::Notification {
                                    protocol_id,
                                    res: SubscriptionResponse::Error(SubscriptionResponseError::RemotePayloadTooLarge),
                                }));
                            },
                            // Any other output at this stage is a protocol error.
                            _ => {
                                self.cancel_subscription_silently(protocol_id);
                                return Ok(Some(Message::Notification {
                                    protocol_id,
                                    res: SubscriptionResponse::Error(
                                        SubscriptionResponseError::MultistreamProtocolError,
                                    ),
                                }));
                            }
                        }
                    },
                    SubscriptionStreamState::Closed => {
                        // Impossible for it to be closed when we found it; ignore
                    }
                }
            } else if let Some(p) = self
                .subscription_details
                .iter_mut()
                .find(|p| {
                    // If the inbound stream ID matches then this lines up
                    p.inbound_stream_id() == Some(stream_id)
                    // OR if the protocol matches
                    || matches!(&output.state, OutputState::IncomingProtocol(n) if n == &p.protocol.name)
                })
            {
                // ----------------------------------
                // Is this a message on an incoming subscription stream that we are interested in
                // ----------------------------------

                let protocol_id = p.protocol_id;
                match p.their_stream {
                    SubscriptionStreamState::Closed => {
                        // Only allow the inbound stream if we have opened ours
                        // already, or if we set allow_inbound to true.
                        if !p.protocol.allow_inbound && p.our_stream.is_closed() {
                            self.yamux.reset_stream_immediately(stream_id);
                            continue
                        }

                        // This is always the initial state; if we get here then we simply
                        // need to accept their incoming protocol (see the .find() above)
                        // and transition to waiting for their handshake.
                        self.yamux.accept_protocol(stream_id, p.protocol.max_response_size_in_bytes)?;
                        p.their_stream = SubscriptionStreamState::Handshake { stream_id };

                        // If we haven't started opening our end yet then do this. We need
                        // their_stream and our_stream to be Open for the subscription to be open.
                        if p.our_stream.is_closed() {
                            let stream_id = self.yamux.open_stream(Some(&p.protocol.name), p.protocol.max_response_size_in_bytes)?;
                            p.our_stream = SubscriptionStreamState::Handshake { stream_id };
                        }
                    },
                    SubscriptionStreamState::Handshake { stream_id } => {
                        match output.state {
                            OutputState::Data(their_handshake) => {
                                if (p.protocol.validate_their_handshake)(their_handshake) {
                                    // If their handshake is valid, send ours and wait for data.
                                    self.yamux.send_data(stream_id, &p.protocol.our_handshake)?;
                                    p.their_stream = SubscriptionStreamState::Open { stream_id };

                                    // If both sides are open then we notify the user that
                                    // the subscription is open and ready now.
                                    if p.our_stream.is_open() && p.their_stream.is_open() {
                                        return Ok(Some(Message::Notification {
                                            protocol_id,
                                            res: SubscriptionResponse::Opened,
                                        }))
                                    }
                                } else {
                                    // Else it's all gone wrong, close and tidy.
                                    self.cancel_subscription_silently(protocol_id);
                                    return Ok(Some(Message::Notification {
                                        protocol_id,
                                        res: SubscriptionResponse::Error(
                                            SubscriptionResponseError::TheirHandshakeRejected,
                                        ),
                                    }));
                                }
                            },
                            OutputState::Closed(CloseReason::ClosedByRemote) => {
                                self.cancel_subscription_silently(protocol_id);
                                return Ok(Some(Message::Notification {
                                    protocol_id,
                                    res: SubscriptionResponse::Closed,
                                }));
                            },
                            OutputState::Closed(CloseReason::IncomingMessageTooLarge) => {
                                self.cancel_subscription_silently(protocol_id);
                                return Ok(Some(Message::Notification {
                                    protocol_id,
                                    res: SubscriptionResponse::Error(SubscriptionResponseError::RemotePayloadTooLarge),
                                }));
                            },
                            // Any other output at this stage is a protocol error.
                            _ => {
                                self.cancel_subscription_silently(protocol_id);
                                return Ok(Some(Message::Notification {
                                    protocol_id,
                                    res: SubscriptionResponse::Error(
                                        SubscriptionResponseError::MultistreamProtocolError,
                                    ),
                                }));
                            }
                        }
                    },
                    SubscriptionStreamState::Open { .. } => {
                        match output.state {
                            OutputState::Data(data) => {
                                return Ok(Some(Message::Notification {
                                    protocol_id,
                                    res: SubscriptionResponse::Value(data)
                                }))
                            },
                            OutputState::Closed(CloseReason::ClosedByRemote) => {
                                self.cancel_subscription_silently(protocol_id);
                                return Ok(Some(Message::Notification {
                                    protocol_id,
                                    res: SubscriptionResponse::Closed,
                                }));
                            },
                            OutputState::Closed(CloseReason::IncomingMessageTooLarge) => {
                                self.cancel_subscription_silently(protocol_id);
                                return Ok(Some(Message::Notification {
                                    protocol_id,
                                    res: SubscriptionResponse::Error(SubscriptionResponseError::RemotePayloadTooLarge),
                                }));
                            },
                            // Any other output at this stage is a protocol error.
                            _ => {
                                self.cancel_subscription_silently(protocol_id);
                                return Ok(Some(Message::Notification {
                                    protocol_id,
                                    res: SubscriptionResponse::Error(
                                        SubscriptionResponseError::MultistreamProtocolError,
                                    ),
                                }));
                            }
                        }
                    },
                }
            } else if let Some(request_details) = self.request_details
                .iter()
                .find(|r| {
                    r.protocol.allow_inbound &&
                    matches!(&output.state, OutputState::IncomingProtocol(n) if n == &r.protocol.name)
                })
            {
                // ----------------------------------
                // Is this an incoming request on a protocol that we are allowing incoming requests on?
                // ----------------------------------

                self.yamux.accept_protocol(stream_id, request_details.protocol.max_response_size_in_bytes)?;
                self.incoming_requests.insert(stream_id, request_details.protocol_id);
            } else {
                // ----------------------------------
                // Is this a message that doesn't relate to any stream we are expecting/interested in?
                // ----------------------------------

                // For now we just close/reject any streams we don't know about or want. The request/subscription
                // may have been cancelled while a response was inbound.
                match output.state {
                    OutputState::IncomingProtocol(_) => {
                        self.yamux.reject_protocol(stream_id)?;
                    }
                    OutputState::OutgoingRejected
                    | OutputState::OutgoingAccepted(_)
                    | OutputState::Data(_) => {
                        self.yamux.reset_stream_immediately(output.stream_id);
                    }
                    OutputState::Closed(_) => {
                        // Nothing to do; the now-unknown stream has closed.
                    }
                }
            }
        }
    }

    /// Work through any request timeouts, returning a message if there is something we should
    /// hand back to the user, and returning `None`` if nothing further to do.
    fn handle_request_timeouts(&mut self) -> Option<Message> {
        for details in &mut self.request_details {
            let Some(timeouts) = &mut details.timeouts else {
                continue;
            };
            let Some(stream_id) = timeouts.try_next() else {
                continue;
            };
            let Some((protocol_id, _)) = self.inflight_requests.remove(&stream_id) else {
                continue;
            };
            // Abort the timed-out request stream, and emit a message.
            self.yamux.reset_stream_immediately(stream_id);
            return Some(Message::Response {
                id: RequestId(stream_id),
                protocol_id,
                res: RequestResponse::Error(RequestResponseError::Timeout),
            });
        }
        None
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use core::future::Future;
    use core::time::Duration;
    use crate::utils::async_stream::{AsyncRead, AsyncReadError, AsyncWrite, AsyncWriteError};

    // Just assert at compile time that a Connection impls Send
    // so long as the Platform + AsyncRead + AsyncWrite impls do.
    #[allow(unused)]
    fn is_connection_send() {
        struct TestPlatformStub;
        impl PlatformT for TestPlatformStub {
            type Sleep = core::future::Pending<()>;

            fn fill_with_random_bytes(_bytes: &mut [u8]) {
                unimplemented!()
            }
            fn sleep(duration: Duration) -> Self::Sleep {
                core::future::pending()
            }
        }

        struct TestStreamStub;
        impl AsyncRead for TestStreamStub {
            fn read_exact(
                &mut self,
                _buf: &mut [u8],
            ) -> impl Future<Output = Result<(), AsyncReadError>> {
                core::future::pending()
            }
        }
        impl AsyncWrite for TestStreamStub {
            fn write_all(
                &mut self,
                _data: &[u8],
            ) -> impl Future<Output = Result<(), AsyncWriteError>> {
                core::future::pending()
            }
        }

        fn assert_send<T: Send>() {}
        assert_send::<Connection<TestStreamStub, TestStreamStub, TestPlatformStub>>();
    }


}

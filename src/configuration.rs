use core::time::Duration;
use core::marker::PhantomData;
use alloc::vec::Vec;
use crate::protocol::{AnyProtocol, Protocol};
use crate::platform::PlatformT;
use crate::utils::opaque_id::OpaqueId;
use crate::utils::async_stream::AsyncStream;
use crate::utils::peer_id::PeerId;
use crate::connection::Connection;
use crate::error::ConnectionError;

/// Configuration for connections.
#[derive(Debug, Clone)]
pub struct Configuration<Platform> {
    pub (crate) identity_secret: Option<[u8; 32]>,
    pub (crate) noise_timeout: Duration,
    pub (crate) multistream_timeout: Duration,
    pub (crate) marker: PhantomData<(Platform,)>,
    pub (crate) protocols: Vec<(OpaqueId, AnyProtocol)>,
}

impl<Platform: PlatformT> Configuration<Platform> {
    /// Create some new connection configuration.
    pub fn new() -> Self {
        Self {
            identity_secret: None,
            noise_timeout: Duration::from_secs(30),
            multistream_timeout: Duration::from_secs(10),
            marker: PhantomData,
            protocols: Default::default(),
        }
    }

    /// Add a [`RequestProtocol`] or a [`SubscriptionProtocol`], returning a unique
    /// ID for this protocol that can be used to interact with it.
    pub fn add_protocol<P: Protocol>(&mut self, protocol: P) -> P::Id {
        let next_id = OpaqueId::new();
        self.protocols.push((next_id, protocol.into_any_protocol()));
        P::Id::from(next_id)
    }

    /// Set a static identity that will be used for all connections using this configuration.
    /// If this is not provided then a unique random identity will be created for each connection.
    pub fn with_identity(mut self, secret_bytes: [u8; 32]) -> Self {
        self.identity_secret = Some(secret_bytes);
        self
    }

    /// Configure the timeout to establishing noise encryption with a peer. Defaults to 30 seconds.
    pub fn with_noise_timeout(mut self, timeout: Duration) -> Self {
        self.noise_timeout = timeout;
        self
    }

    /// Configure the timeouts to negotiating multistream protocols with a peer. Defaults to 10 seconds.
    pub fn with_multistream_timeout(mut self, timeout: Duration) -> Self {
        self.multistream_timeout = timeout;
        self
    }

    /// Connect to a peer given some read/write byte stream that has already been established with it.
    /// If we know the expected peer ID then we can use [`Self::connect_to_peer`] to provide this ID,
    /// which will then check that it is correct.
    /// 
    /// # Cancel safety
    /// 
    /// This method is not cancel safe.
    pub async fn connect<Stream: AsyncStream>(
        &self,
        stream: Stream,
    ) -> Result<Connection<Stream, Platform>, ConnectionError> {
        Connection::from_stream(self, stream, None).await
    }

    /// Connect to a peer given some read/write byte stream that has already been established with it,
    /// and the expected identity of the peer. If the identity does not match then the connection will be rejected.
    /// 
    /// # Cancel safety
    /// 
    /// This method is not cancel safe.
    pub async fn connect_to_peer<Stream: AsyncStream>(
        &self,
        stream: Stream,
        peer_id: PeerId,
    ) -> Result<Connection<Stream, Platform>, ConnectionError> {
        Connection::from_stream(self, stream, Some(peer_id)).await
    }
}
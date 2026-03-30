mod utils;

use core::future::Future;
use utils::{
    async_stream,
    multistream,
    peer_id,
    noise
};

pub struct Id;

pub struct Connection<Event, Platform> {
    marker: core::marker::PhantomData<(Event, Platform)>
}

impl <Event, Platform: PlatformT> Connection<Event, Platform> {
    pub async fn from_stream<S: async_stream::AsyncStream>(mut stream: S, remote_peer_id: Option<peer_id::PeerId>) -> Result<Self, Error> {
        const NEGOTIATE_TIMEOUT_MS: usize = 10_000;
        const NOISE_HANDSHAKE_TIMEOUT_MS: usize = 30_000;

        // Agree to use the noise protocol.
        Platform::timeout(NEGOTIATE_TIMEOUT_MS, multistream::negotiate_dialer(&mut stream, "/noise"))
            .await
            .map_err(|()| Error::NoiseNegotiationTimeout)?
            .map_err(Error::Multistream)?;

        // Generate an identity for ourselves.
        let identity = {
            let mut random_bytes = [0u8; 32]; 
            Platform::fill_with_random_values(&mut random_bytes);
            peer_id::Identity::from_random_bytes(random_bytes)
        };

        // Establish our encypted noise session and find the remote Peer ID
        let (mut noise_stream, remote_id) = Platform::timeout(NOISE_HANDSHAKE_TIMEOUT_MS, noise::handshake_dialer(stream, &identity, remote_peer_id.as_ref()))
            .await
            .map_err(|()| Error::NoiseHandshakeTimeout)?
            .map_err(Error::Noise)?;

        // Agree to use the yamux protocol in this noise stream.
        Platform::timeout(NEGOTIATE_TIMEOUT_MS, multistream::negotiate_dialer(&mut noise_stream, "/yamux/1.0.0"))
            .await
            .map_err(|()| Error::YamuxNegotiationTimeout)?
            .map_err(Error::Multistream)?;
            
        // Now we will be sending and receiving yamux messages.

        todo!()
    }

    pub fn id(&mut self) -> Id {
        todo!("Return an available opaque ID to use for the next stream")
    }

    pub fn request<F: FnOnce(Vec<u8>) -> Event>(&mut self, id: Id, stream: impl AsRef<str>, transform: F) {
        todo!("Send a request on the given request-response stream and transform the response to our event type.")
    }

    pub fn subscribe<V: FnOnce(Vec<u8>) -> bool, F: FnOnce(Vec<u8>) -> Event>(&mut self, id: Id, stream: impl AsRef<str>, handshake: Vec<u8>, validate: V, transform: F) {
        todo!("Subscribe to a notification stream, validating their handshake and transforming responses to our event type.")
    }

    pub async fn next(&mut self) -> Option<Event> {
        todo!("Return the next event, or None if no connection has been closed.")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("timeout negotiating noise stream")]
    NoiseNegotiationTimeout,
    #[error("timeout negotiating yamux stream")]
    YamuxNegotiationTimeout,
    #[error("timeout exchanging noise handshakes")]
    NoiseHandshakeTimeout,
    #[error("error negotiating multistream: {0}")]
    Multistream(#[from] multistream::Error),
    #[error("error establish noise encrypted stream: {0}")]
    Noise(#[from] noise::Error)
}

pub trait PlatformT {
    /// Fill the given bytes with random values.
    fn fill_with_random_values(bytes: &mut [u8]);
    /// Returns Err(()) if the given future times out, else returns the output from the future.
    fn timeout<F: core::future::Future<Output = R>, R>(ms: usize, fut: F) -> impl Future<Output = Result<R, ()>>;
}

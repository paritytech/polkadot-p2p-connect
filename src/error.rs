use crate::utils::{
    multistream,
    noise,
    yamux_multistream,
};

/// An error that can occur establishing a connection with some peer.
#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error("timeout negotiating noise stream")]
    NoiseNegotiationTimeout,
    #[error("timeout negotiating yamux stream")]
    YamuxNegotiationTimeout,
    #[error("timeout exchanging noise handshakes")]
    NoiseHandshakeTimeout,
    #[error("internal protocol error: {0}")]
    ProtocolError(#[from] ProtocolError),
}

/// An error that can occur processing messages to/from a peer.
#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    #[error("internal protocol error: {0}")]
    ProtocolError(#[from] ProtocolError),
}

/// An opaque internal protocol error.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ProtocolError(ProtocolErrorKind);

/// Errors that happen at the protocol level. Nothing that
/// the user can address, so this is kept opaque and not exported.
#[derive(Debug, thiserror::Error)]
enum ProtocolErrorKind {
    #[error("error negotiating multistream: {0}")]
    Multistream(multistream::Error),
    #[error("error establish noise encrypted stream: {0}")]
    Noise(noise::Error),
    #[error("yamux multistream error: {0}")]
    YamuxMultistream(yamux_multistream::Error)
}

// Impls to make converitng between internal errors and our opaque ProtocolError variants easy:

impl From<multistream::Error> for ConnectionError {
    fn from(value: multistream::Error) -> Self {
        ConnectionError::ProtocolError(ProtocolError(ProtocolErrorKind::Multistream(value)))
    }
}
impl From<noise::Error> for ConnectionError {
    fn from(value: noise::Error) -> Self {
        ConnectionError::ProtocolError(ProtocolError(ProtocolErrorKind::Noise(value)))
    }
}
impl From<yamux_multistream::Error> for ConnectionError {
    fn from(value: yamux_multistream::Error) -> Self {
        ConnectionError::ProtocolError(ProtocolError(ProtocolErrorKind::YamuxMultistream(value)))
    }
}

impl From<multistream::Error> for StreamError {
    fn from(value: multistream::Error) -> Self {
        StreamError::ProtocolError(ProtocolError(ProtocolErrorKind::Multistream(value)))
    }
}
impl From<noise::Error> for StreamError {
    fn from(value: noise::Error) -> Self {
        StreamError::ProtocolError(ProtocolError(ProtocolErrorKind::Noise(value)))
    }
}
impl From<yamux_multistream::Error> for StreamError {
    fn from(value: yamux_multistream::Error) -> Self {
        StreamError::ProtocolError(ProtocolError(ProtocolErrorKind::YamuxMultistream(value)))
    }
}
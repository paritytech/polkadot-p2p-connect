use alloc::boxed::Box;

/// Async byte-stream trait. The underlying peer connection (for instance TCP or WebSocket) 
/// should implement this, and then it can be passed to [`crate::Configuration::connect`]
/// or similar to establish a connection to the peer.
pub trait AsyncStream {
    /// Read enough bytes from the stream to fill the given buffer.
    fn read_exact(
        &mut self,
        buf: &mut [u8],
    ) -> impl core::future::Future<Output = Result<(), Error>>;
    /// Write the entirity of the given bytes to the stream.
    fn write_all(
        &mut self,
        data: &[u8],
    ) -> impl core::future::Future<Output = Result<(), Error>>;
}

/// Some error that has occurred reading or writing bytes from an implementation of [`AsyncStream`].
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("cannot read from stream: {0}")]
    ReadExact(Box<dyn core::error::Error + Send + Sync + 'static>),
    #[error("cannot write to stream: {0}")]
    WriteAll(Box<dyn core::error::Error + Send + Sync + 'static>),
}

impl Error {
    /// Create an error relating to [`AsyncStream::read_exact`].
    pub fn read_exact<E: core::error::Error + Send + Sync + 'static>(e: E) -> Error {
        Error::ReadExact(Box::new(e))
    }
    /// Create an error relating to [`AsyncStream::write_all`].
    pub fn write_all<E: core::error::Error + Send + Sync + 'static>(e: E) -> Error {
        Error::WriteAll(Box::new(e))
    }
}
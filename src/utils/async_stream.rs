use alloc::boxed::Box;

/// Async byte-stream trait used by each layer of the protocol stack.
/// WebSocket, Noise, and Yamux stream adapters all implement this.
pub trait AsyncStream {
    fn read_exact(
        &mut self,
        buf: &mut [u8],
    ) -> impl core::future::Future<Output = Result<(), Error>>;
    fn write_all(
        &mut self,
        data: &[u8],
    ) -> impl core::future::Future<Output = Result<(), Error>>;
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cannot read from stream: {0}")]
    ReadExact(Box<dyn core::error::Error + Send + Sync + 'static>),
    #[error("cannot write to stream: {0}")]
    WriteAll(Box<dyn core::error::Error + Send + Sync + 'static>),
}

impl Error {
    pub fn read_exact<E: core::error::Error + Send + Sync + 'static>(e: E) -> Error {
        Error::ReadExact(Box::new(e))
    }
    pub fn write_all<E: core::error::Error + Send + Sync + 'static>(e: E) -> Error {
        Error::WriteAll(Box::new(e))
    }
}
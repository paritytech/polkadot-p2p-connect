use crate::utils::async_stream::{AsyncRead, AsyncReadError, AsyncWrite, AsyncWriteError};
use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

/// A Mock stream implementation which implements [`AsyncStream`] and can
/// be used in single threaded contexts for exampels and testing.
#[derive(Debug, Default, Clone)]
pub struct MockStream {
    inner: Rc<RefCell<MockStreamInner>>,
}

/// The handle to a [`MockStream`]. This can write data to the buffer that is
/// read when [`MockStream::read_exact`] is called, and can read data from the
/// buffer that is written too when [`MockStream::write_all`] is called.
#[derive(Debug, Clone)]
pub struct MockStreamHandle {
    inner: Rc<RefCell<MockStreamInner>>,
}

#[derive(Debug, Clone, Default)]
struct MockStreamInner {
    read_buf: VecDeque<u8>,
    write_buf: VecDeque<u8>,
}

impl MockStream {
    /// Create a new, empty, [`MockStream`]. Use [`MockStream::handle`]
    /// to read and write bytes to this stream for consumption.
    pub fn new() -> Self {
        Self {
            inner: Rc::new(RefCell::new(MockStreamInner {
                read_buf: Default::default(),
                write_buf: Default::default(),
            })),
        }
    }

    /// Create a handle to this [`MockStream`] which allows bytes to be read
    /// and written through it.
    pub fn handle(&self) -> MockStreamHandle {
        MockStreamHandle {
            inner: self.inner.clone(),
        }
    }
}

impl AsyncRead for MockStream {
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), AsyncReadError> {
        let mut inner = self.inner.borrow_mut();

        if inner.read_buf.len() < buf.len() {
            drop(inner);
            return core::future::pending().await;
        }

        for (i, b) in inner.read_buf.drain(..buf.len()).enumerate() {
            buf[i] = b;
        }

        Ok(())
    }
}

impl AsyncWrite for MockStream {
    async fn write_all(&mut self, data: &[u8]) -> Result<(), AsyncWriteError> {
        self.inner.borrow_mut().write_buf.extend(data);
        Ok(())
    }
}

impl MockStreamHandle {
    /// Push a byte to the buffer that will be read when [`MockStream::read_exact`] is used.
    pub fn push(&self, byte: u8) {
        self.inner.borrow_mut().read_buf.push_back(byte);
    }

    /// Drain `n` bytes from the buffer that is written too when [`MockStream::write_all`] is
    /// used, from the oldest to newest byte written.
    pub fn drain(&self, n: usize) -> Vec<u8> {
        let mut inner = self.inner.borrow_mut();
        inner.write_buf.drain(..n).collect()
    }

    /// Drain all bytes from the write buffer.
    pub fn drain_all(&self) -> Vec<u8> {
        let mut inner = self.inner.borrow_mut();
        inner.write_buf.drain(..).collect()
    }
}

impl Extend<u8> for MockStreamHandle {
    fn extend<T: IntoIterator<Item = u8>>(&mut self, iter: T) {
        for b in iter.into_iter() {
            self.push(b);
        }
    }
}

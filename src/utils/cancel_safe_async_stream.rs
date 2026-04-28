use core::future::Future;
use core::pin::Pin;
use alloc::vec::Vec;
use alloc::vec;
use alloc::boxed::Box;
use alloc::collections::VecDeque;
use core::task::Poll;
use crate::utils::async_stream::{AsyncRead, AsyncReadError, AsyncWrite, AsyncWriteError};

/// This wraps anything implementing [`AsyncRead`] and itself implements [`AsyncRead`],
/// but internally buffers things such that we can drop the promise returned from
/// [`CancelSafeAsyncRead::read_exact`] as needed and it will resume when called again.
pub struct CancelSafeAsyncRead<R> {
    inner: R,
    buf: VecDeque<u8>,
    fut: Option<Pin<Box<dyn Future<Output = Result<Vec<u8>, AsyncReadError>>>>>
}

impl <R: AsyncRead> CancelSafeAsyncRead<R> {
    fn read_exact(
        &mut self,
        buf: &mut [u8],
    ) -> impl core::future::Future<Output = Result<(), AsyncReadError>> {
        core::future::poll_fn(move |cx| {
            loop {
                // have we buffered enough bytes to hand back?
                if self.buf.len() >= buf.len() {
                    for (i, b) in self.buf.drain(buf.len()).enumerate() {
                        buf[i] = b;
                    }
                    return Poll::Ready(Ok(()));
                }
    
                // else, fetch our ongoing future to read more bytes, creating a new one
                // if we don't already have one going.
                let fut = self.fut.take().unwrap_or_else(|| {
                    let bytes_needed = buf.len() - self.buf.len();
                    Box::pin(async move {
                        let mut inner_buf = vec![0u8; bytes_needed];
                        self.inner.read_exact(&mut inner_buf).await?;
                        Ok(inner_buf)
                    })
                });
    
                // poll the inner future and handle the result.
                match fut.as_mut().poll(cx) {
                    Poll::Pending => {
                        self.fut = Some(fut);
                        return Poll::Pending;
                    },
                    Poll::Ready(Err(e)) => {
                        return Poll::Ready(Err(e))
                    },
                    Poll::Ready(Ok(bytes)) => {
                        self.buf.extend(bytes);
                    }
                }
            }
        })
    }
}

/// This wraps anything implementing [`AsyncWrite`] and itself implements [`AsyncWrite`],
/// but internally buffers things such that we can drop the promise returned from
/// [`CancelSafeAsyncWrite::write_all`] as needed and it will resume writing when called again.
pub struct CancelSafeAsyncWrite<W> {
    inner: W,
    buf: VecDeque<u8>,
    fut: Option<Pin<Box<dyn Future<Output = Result<(), AsyncReadError>>>>>
}

impl <W: AsyncWrite> AsyncWrite for CancelSafeAsyncWrite<W> {
    fn write_all(&mut self, data: &[u8]) -> impl core::future::Future<Output = Result<(), AsyncWriteError>> {
        // Push any new data that we want to write to our write buffer:
        self.buf.extend(data);

        core::future::poll_fn(move |cx| {
            loop {
                // fetch our ongoing future to write bytes, creating a new one
                // if we don't already have one going.
                let fut = self.fut.take().unwrap_or_else(|| {
                    let mut bytes_to_write = core::mem::take(&mut self.buf);
                    Box::pin(async move {
                        let (a, b) = bytes_to_write.as_slices();
                        self.inner.write_all(&a).await?;
                        self.inner.write_all(&b).await?;
                        Ok(())
                    })
                });

                // poll the inner future and handle the result.
                match fut.as_mut().poll(cx) {
                    Poll::Pending => {
                        self.fut = Some(fut);
                        return Poll::Pending;
                    },
                    Poll::Ready(Err(e)) => {
                        return Poll::Ready(Err(e))
                    },
                    Poll::Ready(Ok(bytes)) => {
                        if self.buf.is_empty() {
                            return Poll::Ready(Ok(()))
                        }
                    }
                }
            }
        })
    }
}
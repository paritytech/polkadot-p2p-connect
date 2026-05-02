use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::task::Poll;

pub enum Never {}

/// This holds a future for reading and a future for writing, and
/// returns any values read while progressing the writing future.
///
/// This is used specifically when calling YamuxSession::next and is
/// somewhat tailored to that use case.
#[allow(clippy::type_complexity)]
pub struct ReadWriteJoin<T, E> {
    write_errored: bool,
    write_fut: Pin<Box<dyn Future<Output = Result<Never, E>>>>,
    read_fut: Option<Pin<Box<dyn Future<Output = Result<T, E>>>>>,
}

impl<T, E> ReadWriteJoin<T, E> {
    /// Create a new, empty [`ReadWriteJoin`]. Use [`ReadWriteJoin::call`] to
    /// start executing a pair of futures.
    pub fn new<WriteFut>(write_fut: WriteFut) -> Self 
    where
        WriteFut: Future<Output = Result<Never, E>> + 'static
    {
        ReadWriteJoin {
            write_errored: false,
            write_fut: Box::pin(write_fut),
            read_fut: None,
        }
    }

    /// If you provide a function that returns a read future and a function that returns
    /// a write future, this returns a future which will drive both internally until the
    /// read future returns a value. This returned future can be cancelled and will resume
    /// when this is called again.
    pub fn call<ReadFn, ReadFut>(
        &mut self,
        read_fn: ReadFn,
    ) -> impl Future<Output = Result<T, E>>
    where
        ReadFn: Fn() -> ReadFut,
        ReadFut: Future<Output = Result<T, E>> + 'static,
    {
        core::future::poll_fn(move |cx| {
            // Continue or create a new read fut as needed.
            let mut read_fut = self.read_fut.take().unwrap_or_else(|| Box::pin(read_fn()));

            // Poll both futures concurrently (so long as write fut didn't error).
            let read_poll = read_fut.as_mut().poll(cx);

            if !self.write_errored {
                let write_poll = self.write_fut.as_mut().poll(cx);
                match write_poll {
                    Poll::Pending => {
                        // Nothing to do here; will be polled again when ready.
                    }
                    Poll::Ready(Err(e)) => {
                        // Error; replace the rad future and return.
                        self.write_errored = true;
                        self.read_fut = Some(read_fut);
                        return Poll::Ready(Err(e));
                    }
                }
            }

            match read_poll {
                Poll::Pending => {
                    // Our read future isn't finished yet so replace it and return.
                    self.read_fut = Some(read_fut);
                    Poll::Pending
                }
                Poll::Ready(Err(e)) => {
                    Poll::Ready(Err(e))
                }
                Poll::Ready(Ok(val)) => {
                    Poll::Ready(Ok(val))
                }
            }
        })
    }
}

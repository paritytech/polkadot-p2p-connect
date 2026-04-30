use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::task::Poll;

/// This holds a future for reading and a future for writing, and
/// returns any values read while progressing the writing future.
///
/// This is used specifically when calling YamuxSession::next and is
/// somewhat tailored to that use case.
pub struct ReadWriteJoin<T, E> {
    write_fut: Option<Pin<Box<dyn Future<Output = Result<(), E>>>>>,
    read_fut: Option<Pin<Box<dyn Future<Output = Result<T, E>>>>>,
}

impl<T, E> ReadWriteJoin<T, E> {
    /// Create a new, empty [`ReadWriteJoin`]. Use [`ReadWriteJoin::call`] to
    /// start executing a pair of futures.
    pub fn new() -> Self {
        ReadWriteJoin {
            write_fut: None,
            read_fut: None,
        }
    }

    /// If you provide a function that returns a read future and a function that returns
    /// a write future, this returns a future which will drive both internally until the
    /// read future returns a value. This returned future can be cancelled and will resume
    /// when this is called again.
    pub fn call<ReadFn, ReadFut, WriteFn, WriteFut>(
        &mut self,
        read_fn: ReadFn,
        write_fn: WriteFn,
    ) -> impl Future<Output = Result<T, E>>
    where
        ReadFn: Fn() -> ReadFut,
        ReadFut: Future<Output = Result<T, E>> + 'static,
        WriteFn: Fn() -> WriteFut,
        WriteFut: Future<Output = Result<(), E>> + 'static,
    {
        core::future::poll_fn(move |cx| {
            let mut read_fut = self.read_fut.take().unwrap_or_else(|| Box::pin(read_fn()));
            let mut write_fut = self
                .write_fut
                .take()
                .unwrap_or_else(|| Box::pin(write_fn()));

            // Poll both futures concurrently.
            let read_poll = read_fut.as_mut().poll(cx);
            let write_poll = write_fut.as_mut().poll(cx);

            let mut write_pending = false;
            match write_poll {
                Poll::Pending => {
                    // Note the pending state and replace it.
                    write_pending = true;
                }
                Poll::Ready(Err(e)) => {
                    // Error; replace the other one and return the err. On the
                    // next call we'll create a new write_fut and try again.
                    self.read_fut = Some(read_fut);
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(())) => {
                    // Future finished so don't replace it. On the next
                    // loop we'll start a new write future going.
                }
            }

            match read_poll {
                Poll::Pending => {
                    // Our read future isn't finished yet so replace it and return.
                    //
                    // If the write future is pending, it will wake this poll_fn up and
                    // cause both to be re-polled. If the write future is finished and Ok(()),
                    // we won't try doing another write until the read fut completes. This is ok because
                    // the user has to drop this future to insert more writes, upon which we will
                    // begin executing them when we poll again (as well as any reads).
                    //
                    // If we create a new write future straight away and the write future has nothing
                    // to do, then it will just spin and waste CPU while we are waiting for the read
                    // future.
                    self.read_fut = Some(read_fut);

                    if write_pending {
                        self.write_fut = Some(write_fut);
                    }
                    Poll::Pending
                }
                Poll::Ready(Err(e)) => {
                    if write_pending {
                        self.write_fut = Some(write_fut);
                    }
                    Poll::Ready(Err(e))
                }
                Poll::Ready(Ok(val)) => {
                    if write_pending {
                        self.write_fut = Some(write_fut);
                    }
                    Poll::Ready(Ok(val))
                }
            }
        })
    }
}

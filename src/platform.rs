use core::future::Future;
use core::marker::Unpin;
use core::pin::Pin;
use core::task::Poll;
use core::time::Duration;

/// This trait provides any core features that we need in our [`crate::Connection`].
pub trait PlatformT {
    /// The type returned from [`PlatformT::sleep()`]. This should
    /// be a future which resolves after the given sleep duration.
    type Sleep: Future<Output = ()> + Unpin + Send + 'static;

    /// Fill the given buffer with random bytes.
    fn fill_with_random_bytes(bytes: &mut [u8]);

    /// Sleep for the given duration
    fn sleep(duration: Duration) -> Self::Sleep;
}

/// A naive timeout implementation based on [`PlatformT::sleep`]
pub fn timeout<P: PlatformT, R, F: Future<Output = R> + Unpin>(
    duration: core::time::Duration,
    mut fut: F,
) -> impl Future<Output = Result<R, ()>> {
    let mut s = P::sleep(duration);
    core::future::poll_fn(move |cx| {
        if let Poll::Ready(val) = Pin::new(&mut fut).poll(cx) {
            Poll::Ready(Ok(val))
        } else if let Poll::Ready(()) = Pin::new(&mut s).poll(cx) {
            Poll::Ready(Err(()))
        } else {
            Poll::Pending
        }
    })
}
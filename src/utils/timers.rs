use crate::PlatformT;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::task::Wake;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};
use core::time::Duration;

/// A set of timers, all with the same duration. New
/// values can be added, and calling [`Timers::try_next`]
/// will return the next elapsed value.
///
/// This is _not_ async because we don't want to wait for
/// the next timer to complete; only check if it is ready
/// periodically without waiting for it.
///
/// This internally reuses [`PlatformT::sleep()`] to do the
/// timing, which avoids needing additional platform methods
/// to fetch the current instant for example.
pub struct Timers<T, P: PlatformT> {
    poll_next: Arc<AtomicBool>,
    duration: Duration,
    timers: VecDeque<(T, P::Sleep)>,
}

impl<T, P: PlatformT> Timers<T, P> {
    /// Instantiate a new timer set. Every timer will have
    /// the given duration.
    pub fn new(duration: Duration) -> Self {
        Self {
            poll_next: Arc::new(AtomicBool::new(false)),
            duration,
            timers: Default::default(),
        }
    }

    /// Add a new timer to the set, which will return the given
    /// item upon completion.
    pub fn add(&mut self, item: T) {
        let fut = P::sleep(self.duration);
        self.timers.push_back((item, fut));
        if self.timers.len() == 1 {
            // If we've added the first item, we need to
            // make a note to try polling it.
            self.poll_next.store(true, Ordering::Relaxed);
        }
    }

    /// Return the next available ready value, if there is one.
    pub fn try_next(&mut self) -> Option<T> {
        // If our poll_next is false then we don't poll and return false.
        // we are waiting for our next fut to ask to be polled still.
        if !self.poll_next.load(Ordering::Relaxed) {
            return None;
        }

        let (item, mut fut) = self.timers.pop_front()?;

        // A quick waker that, when called, sets our poll_next to true.
        struct PollWaker {
            poll_me: Arc<AtomicBool>,
        }
        impl Wake for PollWaker {
            fn wake(self: Arc<Self>) {
                self.poll_me.store(true, Ordering::Relaxed);
            }
        }
        let waker = Waker::from(Arc::new(PollWaker {
            poll_me: self.poll_next.clone(),
        }));

        // poll our future and either return the value or put it back in
        // the queue if it's not ready yet.
        let mut cx = Context::from_waker(&waker);
        match Pin::new(&mut fut).poll(&mut cx) {
            Poll::Pending => {
                self.poll_next.store(false, Ordering::Relaxed);
                self.timers.push_front((item, fut));
                None
            }
            Poll::Ready(()) => {
                // Leave poll_me set to true so that we
                // try the next item.
                Some(item)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use std::sync::Mutex;

    /// A sleep future whose readiness is controlled via a shared flag.
    /// When polled while not ready, it stores the waker so that
    /// `complete_sleep` can wake it — just like a real timer would.
    struct MockSleep {
        inner: Arc<MockSleepInner>,
    }

    struct MockSleepInner {
        ready: AtomicBool,
        waker: Mutex<Option<Waker>>,
    }

    impl core::future::Future for MockSleep {
        type Output = ();
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.inner.ready.load(Ordering::Relaxed) {
                return Poll::Ready(());
            }
            *self.inner.waker.lock().unwrap() = Some(cx.waker().clone());
            // Re-check after storing waker to avoid missed wake.
            if self.inner.ready.load(Ordering::Relaxed) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    }

    std::thread_local! {
        static MOCK_SLEEPS: RefCell<Vec<Arc<MockSleepInner>>> = RefCell::new(Vec::new());
    }

    /// This test platform only impls sleep and hands back our [`MockSleep`] type,
    /// which tests can manually resolve with [`complete_sleep`].
    enum TestPlatform {}
    impl PlatformT for TestPlatform {
        type Sleep = MockSleep;

        fn fill_with_random_bytes(_bytes: &mut [u8]) {
            unimplemented!()
        }
        fn sleep(_duration: Duration) -> Self::Sleep {
            let inner = Arc::new(MockSleepInner {
                ready: AtomicBool::new(false),
                waker: Mutex::new(None),
            });
            MOCK_SLEEPS.with(|sleeps| sleeps.borrow_mut().push(inner.clone()));
            MockSleep { inner }
        }
    }

    /// Mark the Nth mock sleep (0-indexed) as ready and wake its waker.
    fn complete_sleep(index: usize) {
        MOCK_SLEEPS.with(|sleeps| {
            let sleeps = sleeps.borrow();
            let inner = &sleeps[index];
            inner.ready.store(true, Ordering::Relaxed);
            if let Some(waker) = inner.waker.lock().unwrap().take() {
                waker.wake();
            }
        });
    }

    fn reset_sleeps() {
        MOCK_SLEEPS.with(|sleeps| sleeps.borrow_mut().clear());
    }

    #[test]
    fn try_next_returns_none_when_empty() {
        reset_sleeps();
        let mut timers: Timers<u32, TestPlatform> = Timers::new(Duration::from_secs(1));
        assert!(timers.try_next().is_none());
    }

    #[test]
    fn returns_item_after_sleep_completes() {
        reset_sleeps();
        let mut timers: Timers<&str, TestPlatform> = Timers::new(Duration::from_secs(1));
        timers.add("hello");

        // Not ready yet.
        assert!(timers.try_next().is_none());

        // Mark the sleep as done.
        complete_sleep(0);
        assert_eq!(timers.try_next(), Some("hello"));

        // Now empty again.
        assert!(timers.try_next().is_none());
    }

    #[test]
    fn fifo_order_when_all_complete() {
        reset_sleeps();
        let mut timers: Timers<u32, TestPlatform> = Timers::new(Duration::from_secs(1));
        timers.add(1);
        timers.add(2);
        timers.add(3);

        // Complete all sleeps.
        complete_sleep(0);
        complete_sleep(1);
        complete_sleep(2);

        assert_eq!(timers.try_next(), Some(1));
        assert_eq!(timers.try_next(), Some(2));
        assert_eq!(timers.try_next(), Some(3));
        assert!(timers.try_next().is_none());
    }

    #[test]
    fn blocked_until_front_completes() {
        reset_sleeps();
        let mut timers: Timers<u32, TestPlatform> = Timers::new(Duration::from_secs(1));
        timers.add(1);
        timers.add(2);

        // Complete only the second sleep; front is still pending.
        complete_sleep(1);
        assert!(timers.try_next().is_none());

        // Now complete the first.
        complete_sleep(0);
        assert_eq!(timers.try_next(), Some(1));
        assert_eq!(timers.try_next(), Some(2));
    }

    #[test]
    fn add_after_drain_works() {
        reset_sleeps();
        let mut timers: Timers<u32, TestPlatform> = Timers::new(Duration::from_secs(1));

        timers.add(1);
        complete_sleep(0);
        assert_eq!(timers.try_next(), Some(1));
        assert!(timers.try_next().is_none());

        // Add another item after fully draining.
        timers.add(2);
        assert!(timers.try_next().is_none());
        complete_sleep(1);
        assert_eq!(timers.try_next(), Some(2));
    }

    #[test]
    fn interleaved_add_and_drain() {
        reset_sleeps();
        let mut timers: Timers<u32, TestPlatform> = Timers::new(Duration::from_secs(1));

        timers.add(1);
        complete_sleep(0);
        assert_eq!(timers.try_next(), Some(1));

        // Add two more while empty.
        timers.add(2);
        timers.add(3);
        complete_sleep(1);
        assert_eq!(timers.try_next(), Some(2));

        // Add another while 3 is still pending.
        timers.add(4);
        complete_sleep(2);
        complete_sleep(3);
        assert_eq!(timers.try_next(), Some(3));
        assert_eq!(timers.try_next(), Some(4));
    }
}

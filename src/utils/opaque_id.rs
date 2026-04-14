use core::sync::atomic::{ AtomicUsize, Ordering };

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// An opaque ID. There is no way to construc this from a usize; the
/// only way to build them is to call [`OpaqueId::new()`]. Each ID is
/// guaranteed to be unique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpaqueId(usize);

impl OpaqueId {
    /// Create a new unique ID.
    pub fn new() -> OpaqueId {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        OpaqueId(n)
    }

    /// Fetch the [`usize`] value of this ID.
    pub fn get(self) -> usize {
        self.0
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DebugIgnore<T>(pub T);

impl<T> From<T> for DebugIgnore<T> {
    fn from(value: T) -> Self {
        DebugIgnore(value)
    }
}

impl<T> core::ops::Deref for DebugIgnore<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> core::ops::DerefMut for DebugIgnore<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<T> core::fmt::Debug for DebugIgnore<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("<ignored>")
    }
}

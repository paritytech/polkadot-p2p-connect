/// Passing this as the third argument to [`SyncOrAyncFn`]
/// enforces that the provided function is async.
pub enum Async {}

/// Passing this as the third argument to [`SyncOrAyncFn`]
/// enforces that the provided function is not async.
pub enum Sync {}

/// This trait is implemented for `Fn` or `AsyncFn` types. Normally
/// the compiler can infer the `Type` parameter based on which of these
/// is given, and if not then [`Async`] or [`Sync`] can be given as a hint.
pub trait SyncOrAyncFn<Args, Output, Type> {

    /// Call the function with a tuple of the required arguments.
    async fn call(&self, args: Args) -> Output;
}

macro_rules! impl_sync_or_async_fn {
    ($($ty:ident $num:tt),*) => {
        impl <F, $($ty,)* Output> SyncOrAyncFn<($($ty,)*), Output, Async> for F
        where
            F: AsyncFn($($ty),*) -> Output 
        {
            async fn call(&self, args: ($($ty,)*)) -> Output {
                self(
                    $(
                        args.$num,
                    )*
                ).await
            }
        }

        impl <F, $($ty,)* Output> SyncOrAyncFn<($($ty,)*), Output, Sync> for F
        where
            F: Fn($($ty),*) -> Output 
        {
            async fn call(&self, args: ($($ty,)*)) -> Output {
                self(
                    $(
                        args.$num,
                    )*
                )
            }
        }
    };
}

impl_sync_or_async_fn!(A 0);
impl_sync_or_async_fn!(A 0, B 1);
impl_sync_or_async_fn!(A 0, B 1, C 2);
impl_sync_or_async_fn!(A 0, B 1, C 2, D 3);
impl_sync_or_async_fn!(A 0, B 1, C 2, D 3, E 4);
impl_sync_or_async_fn!(A 0, B 1, C 2, D 3, E 4, F2 5);
impl_sync_or_async_fn!(A 0, B 1, C 2, D 3, E 4, F2 5, G 6);
impl_sync_or_async_fn!(A 0, B 1, C 2, D 3, E 4, F2 5, G 6, H 7);
impl_sync_or_async_fn!(A 0, B 1, C 2, D 3, E 4, F2 5, G 6, H 7, I 8);
impl_sync_or_async_fn!(A 0, B 1, C 2, D 3, E 4, F2 5, G 6, H 7, I 8, J 9);

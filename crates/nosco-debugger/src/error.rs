/// Error type of this crate.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Error from the [wholesym] crate.
    #[error(transparent)]
    Wholesym(#[from] wholesym::Error),

    /// Internal debugger error.
    #[error(transparent)]
    DebuggerInternal(#[from] crate::sys::Error),
}

/// Result type of this crate.
pub type Result<T> = core::result::Result<T, Error>;

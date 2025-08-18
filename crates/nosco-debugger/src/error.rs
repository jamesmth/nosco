/// Error type of this crate.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Error from the [wholesym] crate.
    #[error(transparent)]
    Wholesym(#[from] wholesym::Error),

    /// Error from the [nosco-symbol] crate.
    #[error(transparent)]
    Symbol(#[from] nosco_symbol::Error),

    /// An untracked thread was discovered.
    #[error("Untracked thread {0}")]
    UntrackedThread(u64),

    /// Internal debugger error.
    #[error(transparent)]
    DebuggerInternal(#[from] crate::sys::Error),
}

/// Result type of this crate.
pub type Result<T> = core::result::Result<T, Error>;

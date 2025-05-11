/// Error type of this crate.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Invalid CPU instruction error.
    #[error("Invalid CPU instruction at {0:#x}")]
    BadCpuInstruction(u64),

    /// Error from the [wholesym] crate.
    #[error(transparent)]
    Wholesym(#[from] wholesym::Error),

    /// Internal debugger error.
    #[error(transparent)]
    DebuggerInternal(#[from] crate::sys::Error),
}

/// Result type of this crate.
pub type Result<T> = core::result::Result<T, Error>;

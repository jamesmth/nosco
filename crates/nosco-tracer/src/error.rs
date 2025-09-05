/// Debugger error.
#[derive(thiserror::Error, Debug)]
#[error(transparent)]
pub struct DebuggerError<E>(pub E);

/// Event handler error.
#[derive(thiserror::Error, Debug)]
#[error(transparent)]
pub struct HandlerError<E>(pub E);

/// Error type of this crate.
#[derive(thiserror::Error, Debug)]
pub enum Error<E1, E2> {
    /// A debugger error occurred.
    #[error(transparent)]
    Debugger(#[from] DebuggerError<E1>),

    /// An event handler error occurred.
    #[error(transparent)]
    Handler(#[from] HandlerError<E2>),

    /// A symbol wasn't found within a binary.
    #[error("Symbol {1} not found in {0}")]
    SymbolNotFound(String, String),

    /// The tracee was previously resumed.
    #[error("Tracee previously resumed")]
    TraceeAlreadyResumed,

    /// The tracee has no thread.
    #[error("Tracee has no thread")]
    TraceeWithoutThread,
}

/// Result type of this crate.
pub type Result<T, E1, E2> = core::result::Result<T, Error<E1, E2>>;

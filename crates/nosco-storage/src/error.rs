/// Error type of this crate.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// MLA archive error.
    #[error(transparent)]
    Mla(#[from] mla::errors::Error),

    /// Tokio task joining error.
    #[error(transparent)]
    TaskJoin(#[from] tokio::task::JoinError),

    /// Standard MPSC receiver error.
    #[error(transparent)]
    MpscRecv(#[from] std::sync::mpsc::RecvError),

    /// Error when the storage writer previously returned an error, and another
    /// write operation was attempted.
    #[error("the storage writer previously returned an error")]
    WriterPreviouslyFailed,

    /// Error when the storage writer is finalized more than once.
    #[error("the storage writer was already finalized")]
    WriterFinalized,

    /// Time-related error.
    #[error(transparent)]
    SystemTime(#[from] std::time::SystemTimeError),

    /// Error when a writing operation requires a call stream to exist, but
    /// couldn't find any.
    #[error("missing call stream")]
    MissingCallStream,

    /// Error when a thread ID for a writing operation is invalid.
    #[error("unexpected thread ID: {0}")]
    UnexpectedThreadId(u64),

    /// Error when an invalid function call ID was specified to a reading operation.
    #[error("invalid call ID: {0}")]
    InvalidCallId(String),

    /// Error when a reading operation couldn't find the tracing state init in
    /// the storage.
    #[error("missing init state in storage")]
    MissingInitState,

    /// Error when a reading operation couldn't find the tracing state updates in
    /// the storage.
    #[error("missing update state in storage")]
    MissingUpdateState,

    /// Bincode serialization/deserialization error.
    #[error(transparent)]
    Bincode(#[from] bincode::Error),
}

/// Result type of this crate.
pub type Result<T> = core::result::Result<T, Error>;

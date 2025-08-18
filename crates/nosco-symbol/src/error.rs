/// Error type of this crate.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Error from the [wholesym] crate.
    #[cfg(feature = "elf")]
    #[error(transparent)]
    Wholesym(#[from] wholesym::Error),

    /// File open/create error.
    #[cfg(feature = "elf")]
    #[error("{0}: {1}")]
    File(std::path::PathBuf, std::io::Error),

    /// Missing ELF PT_LOAD segment.
    #[cfg(feature = "elf")]
    #[error("missing PT_LOAD")]
    MissingPtLoad,

    /// Error from the [goblin] crate.
    #[cfg(feature = "elf")]
    #[error(transparent)]
    Goblin(#[from] goblin::error::Error),
}

/// Result type of this crate.
pub type Result<T> = core::result::Result<T, Error>;

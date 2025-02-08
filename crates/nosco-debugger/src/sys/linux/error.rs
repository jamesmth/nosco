use nix::sys::wait::WaitStatus;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// File open/create error.
    #[error("{0}: {1}")]
    File(std::path::PathBuf, std::io::Error),

    #[error("bad child wait status: {0:?}")]
    BadChildWait(WaitStatus),

    #[error("os error: {0}")]
    Os(#[from] nix::Error),

    #[error(transparent)]
    Elf(#[from] goblin::error::Error),

    #[error("elf.e_machine={0:#x} not supported")]
    ElfPlatform(u16),

    #[error("missing auxv value")]
    MissingAuxv,

    #[error("missing PT_PHDR")]
    MissingPtPhdr,

    #[error("missing PT_INTERP")]
    MissingPtInterp,

    #[error("missing PT_LOAD")]
    MissingPtLoad,

    #[error("missing DT_DEBUG")]
    MissingDtDebug,

    #[error("missing r_debug")]
    MissingRDebug,

    #[error("missing .symtab")]
    MissingSymtab,

    #[error("invalid .strtab index: {0}")]
    InvalidStrtabIndex(usize),

    #[error("memory read/write {0} bytes instead of {1}")]
    PartialMemOp(usize, usize),

    #[error("previous load state: {0}, new state: {1}")]
    BadSoState(u8, u8),

    #[error(transparent)]
    FromBytesWithNul(#[from] std::ffi::FromBytesWithNulError),

    #[error(transparent)]
    InteriorNulByte(#[from] std::ffi::NulError),

    #[error("Child process execution failed: {0}")]
    ChildExec(std::io::Error),
}

/// Result type of this crate.
pub type Result<T> = core::result::Result<T, Error>;

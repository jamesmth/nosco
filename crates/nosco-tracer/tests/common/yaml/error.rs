/// Error type of this crate.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// String parsing error.
    #[error(transparent)]
    StringParsing(#[from] std::num::ParseIntError),

    /// YAML parser error.
    #[error(transparent)]
    Yaml(#[from] libyaml_safer::Error),
}

/// Result type of this crate.
pub type Result<T> = core::result::Result<T, Error>;

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
    #[error("YAML internal error: {0}")]
    Yaml(serde_yml::libyml::error::Error),
}

/// Result type of this crate.
pub type Result<T> = core::result::Result<T, Error>;

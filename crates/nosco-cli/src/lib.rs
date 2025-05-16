//! Crate implementing the CLI commands.

mod cli;
mod config;
mod dump;
mod run;
mod tracer;

pub use self::cli::{CliAction, CliDumpAction, CliOpts};
pub use self::config::{TraceConfig, TraceScope};
pub use self::dump::evaluate_dump;
pub use self::run::evaluate_run;
pub use self::tracer::TraceEventHandler;

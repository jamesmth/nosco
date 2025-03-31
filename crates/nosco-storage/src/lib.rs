//! This crate provides the low-level helpers to emit/parse tracing session files.
//!
//! It is used by `nosco-cli` to save a tracing session into a file (when
//! running `nosco run`), and to provide a high-level inspection of it (with
//! `nosco dump`).

mod error;
mod mla;
mod writer;

pub use self::error::{Error, Result};
pub use self::mla::{BacktraceElement, MlaStorageReader, MlaStorageWriter};
pub use self::writer::TraceSessionStorageWriter;

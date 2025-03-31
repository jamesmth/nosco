use std::future::{self, Future};
use std::path::Path;

/// Trait for implementing a tracing session storage writer.
pub trait TraceSessionStorageWriter {
    /// Error returned by this storage writer.
    type Error: std::error::Error;

    /// Writes a function call event into the tracing session storage.
    ///
    /// # Note
    ///
    /// `backtrace` is `None` when the function call is a nested one (not a
    /// root call of a tracing scope).
    fn write_call_start(
        &mut self,
        _thread_id: u64,
        _call_addr: u64,
        _backtrace: Option<Vec<u64>>,
    ) -> impl Future<Output = std::result::Result<(), Self::Error>> {
        future::ready(Ok(()))
    }

    /// Writes a function return event into the tracing session storage.
    fn write_call_end(
        &mut self,
        _thread_id: u64,
    ) -> impl Future<Output = std::result::Result<(), Self::Error>> {
        future::ready(Ok(()))
    }

    /// Writes an executed instruction event into the tracing session storage.
    fn write_executed_instruction(
        &mut self,
        _thread_id: u64,
        _opcodes_addr: u64,
        _opcodes: Vec<u8>,
    ) -> impl Future<Output = std::result::Result<(), Self::Error>> {
        future::ready(Ok(()))
    }

    /// Writes a loaded binary event into the tracing session storage.
    ///
    /// # Note
    ///
    /// `thread_id` is `None` when the binary was loaded before
    /// the tracer was attached to the tracee.
    fn write_loaded_binary(
        &mut self,
        _thread_id: Option<u64>,
        _binary: &Path,
        _load_addr: u64,
    ) -> impl Future<Output = std::result::Result<(), Self::Error>> {
        future::ready(Ok(()))
    }

    /// Writes an unloaded binary event into the tracing session storage.
    fn write_unloaded_binary(
        &mut self,
        _thread_id: u64,
        _unload_addr: u64,
    ) -> impl Future<Output = std::result::Result<(), Self::Error>> {
        future::ready(Ok(()))
    }

    /// Writes a created thread event into the tracing session storage.
    ///
    /// # Note
    ///
    /// `parent_thread_id` is `None` when the thread was created before
    /// the tracer was attached to the tracee.
    fn write_created_thread(
        &mut self,
        _parent_thread_id: Option<u64>,
        _new_thread_id: u64,
    ) -> impl Future<Output = std::result::Result<(), Self::Error>> {
        future::ready(Ok(()))
    }

    /// Writes an exited thread event into the tracing session storage.
    fn write_exited_thread(
        &mut self,
        _thread_id: u64,
        _exit_code: i32,
    ) -> impl Future<Output = std::result::Result<(), Self::Error>> {
        future::ready(Ok(()))
    }

    /// Finalizes the writing operation over the tracing session storage.
    fn finalize(&mut self) -> impl Future<Output = std::result::Result<(), Self::Error>> {
        future::ready(Ok(()))
    }
}

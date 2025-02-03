use std::future::{self, Future};

use crate::debugger::DebugSession;

/// Trait for implementing a trace event handler.
pub trait EventHandler {
    /// Debugger session of this event handler.
    type Session: DebugSession;

    /// Error returned by this event handler.
    type Error: std::error::Error;

    /// Function called when a function is being called.
    ///
    /// Only the functions called within the trace scope are handled.
    /// Check out [Builder::trace_all](super::tracer::Builder::trace_all) and
    /// [Builder::trace_scopes](super::tracer::Builder::trace_scopes) for more
    /// information.
    fn function_entered(
        &mut self,
        _session: &mut Self::Session,
        _thread: &<Self::Session as DebugSession>::StoppedThread,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        future::ready(Ok(()))
    }

    /// Function called when a function has returned.
    ///
    /// Only the return of functions called within the trace scope are handled.
    /// Check out [Builder::trace_all](super::tracer::Builder::trace_all) and
    /// [Builder::trace_scopes](super::tracer::Builder::trace_scopes) for more
    /// information.
    fn function_returned(
        &mut self,
        _session: &mut Self::Session,
        _thread: &<Self::Session as DebugSession>::StoppedThread,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        future::ready(Ok(()))
    }

    /// Function called when a new binary is loaded by the tracee.
    ///
    /// # Note
    ///
    /// `thread_id` is `None` when the binary was loaded before
    /// the tracer was attached to the tracee.
    fn binary_loaded(
        &mut self,
        _session: &mut Self::Session,
        _thread_id: Option<u64>,
        _binary: &<Self::Session as DebugSession>::MappedBinary,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        future::ready(Ok(()))
    }

    /// Function called when a binary is unloaded by the tracee.
    fn binary_unloaded(
        &mut self,
        _session: &mut Self::Session,
        _thread_id: u64,
        _unload_addr: u64,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        future::ready(Ok(()))
    }

    /// Function called when a new thread is created by the tracee.
    ///
    /// # Note
    ///
    /// `parent_thread_id` is `None` when the thread was created before
    /// the tracer was attached to the tracee.
    fn thread_created(
        &mut self,
        _session: &mut Self::Session,
        _parent_thread_id: Option<u64>,
        _new_thread: &<Self::Session as DebugSession>::StoppedThread,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        future::ready(Ok(()))
    }

    /// Function called when a thread has exited within the tracee.
    fn thread_exited(
        &mut self,
        _session: &mut Self::Session,
        _thread_id: u64,
        _exit_code: i32,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        future::ready(Ok(()))
    }

    /// Function called when a tracee's thread has executed some instruction.
    ///
    /// Only the instructions executed within the trace scope are handled.
    /// Check out [Builder::trace_all](super::tracer::Builder::trace_all) and
    /// [Builder::trace_scopes](super::tracer::Builder::trace_scopes) for more
    /// information.
    fn instruction_executed(
        &mut self,
        _session: &mut Self::Session,
        _thread: &<Self::Session as DebugSession>::StoppedThread,
        _opcodes_addr: u64,
        _opcodes: Vec<u8>,
    ) -> impl Future<Output = Result<(), Self::Error>> {
        future::ready(Ok(()))
    }
}

use std::process::{ChildStderr, ChildStdin, ChildStdout};

use super::TraceTask;
use crate::debugger::DebugSession;
use crate::handler::EventHandler;

/// Suspended process ready to be resumed and traced.
pub struct TracedProcess<S: DebugSession, H> {
    trace_task: TraceTask<S, H>,
}

impl<S: DebugSession, H> TracedProcess<S, H> {
    pub(super) const fn new(trace_task: TraceTask<S, H>) -> Self {
        Self { trace_task }
    }
}

impl<S, H> TracedProcess<S, H>
where
    S: DebugSession,
    H: EventHandler<Session = S>,
{
    /// Resumes the process and trace its execution.
    ///
    /// Any execution trace event is forwarded to the [handler](crate::handler::EventHandler)
    /// specified when [building the tracer](super::Builder).
    ///
    /// On success, the exit code of the process is returned, as well as the event handler.
    pub async fn resume_and_trace(self) -> crate::Result<(i32, H), S::Error, H::Error> {
        self.trace_task.run().await
    }
}

/// Standard I/O stream for the traced process.
pub struct TracedProcessStdio {
    /// The handle for writing to the standard input (stdin), of the traced
    /// process.
    pub stdin: ChildStdin,

    /// The handle for reading from the standard output (stdout) of the traced
    /// process.
    pub stdout: ChildStdout,

    /// The handle for reading from the standard error (stderr) of the traced
    /// process.
    pub stderr: ChildStderr,
}

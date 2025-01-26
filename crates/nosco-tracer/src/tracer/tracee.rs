use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout};

use super::TraceTask;
use crate::debugger::DebugSession;
use crate::handler::EventHandler;

/// Suspended process ready to be resumed and traced.
pub struct TracedProcess<S: DebugSession, H> {
    trace_task: TraceTask<S, H>,
    child: Option<Child>,
}

impl<S: DebugSession, H> TracedProcess<S, H> {
    pub(super) const fn new(trace_task: TraceTask<S, H>, child: Option<Child>) -> Self {
        Self { trace_task, child }
    }

    /// The handle for reading from the standard output (stdout) of the traced
    /// process, if it has been captured.
    ///
    /// # Note
    ///
    /// You may want to call this function before calling [resume_and_trace](Self::resume_and_trace),
    /// so that you can read the tracee's stdout while it is running.
    pub fn stdout(&mut self) -> Option<ChildStdout> {
        self.child.as_mut().and_then(|child| child.stdout.take())
    }

    /// The handle for reading from the standard error (stderr) of the traced
    /// process, if it has been captured.
    ///
    /// # Note
    ///
    /// You may want to call this function before calling [resume_and_trace](Self::resume_and_trace),
    /// so that you can read the tracee's stderr while it is running.
    pub fn stderr(&mut self) -> Option<ChildStderr> {
        self.child.as_mut().and_then(|child| child.stderr.take())
    }

    /// The handle for writing to the standard input (stdin), of the traced
    /// process, if it has been captured.
    ///
    /// # Note
    ///
    /// You may want to call this function before calling [resume_and_trace](Self::resume_and_trace),
    /// so that you can write to the tracee's stdin while it is running.
    pub fn stdin(&mut self) -> Option<ChildStdin> {
        self.child.as_mut().and_then(|child| child.stdin.take())
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
    /// On success, the exit code of the process is returned.
    pub async fn resume_and_trace(self) -> crate::Result<i32, S::Error, H::Error> {
        self.trace_task.run().await
    }
}

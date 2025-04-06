use nosco_tracer::Command;
use nosco_tracer::tracer::TracedProcessStdio;

use super::session::Session;
use crate::sys;

/// Default debugger (local debugging) implementation.
///
/// # Note
///
/// Right now, only **Linux** is supported.
#[derive(Default)]
pub struct Debugger;

impl Debugger {
    /// Creates a new debugger.
    pub const fn new() -> Self {
        Self
    }
}

impl nosco_tracer::debugger::Debugger for Debugger {
    type Session = super::session::Session;
    type Error = crate::Error;

    async fn spawn(
        &mut self,
        command: Command,
    ) -> Result<(Self::Session, TracedProcessStdio), Self::Error> {
        let (debuggee_handle, debuggee_stdio) = sys::spawn_debuggee(command).await?;

        let session = Session::init(debuggee_handle, &[]).await?;

        Ok((session, debuggee_stdio))
    }
}

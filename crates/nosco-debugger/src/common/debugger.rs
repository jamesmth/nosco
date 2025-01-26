use tokio::process::{Child, Command};

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
        command: &mut Command,
    ) -> Result<(Self::Session, Child), Self::Error> {
        let (main_thread_id, child) = sys::spawn_debuggee(command).await?;

        let session = Session::init(main_thread_id, &[]).await?;

        Ok((session, child))
    }
}

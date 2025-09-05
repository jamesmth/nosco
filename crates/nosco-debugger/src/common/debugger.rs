use nosco_tracer::Command;
use nosco_tracer::debugger::SpawnedTracedProcess;

use super::session::Session;
use super::thread::ThreadManager;
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
    ) -> Result<SpawnedTracedProcess<Self::Session>, Self::Error> {
        let (debuggee_handle, debuggee_stdio) = sys::spawn_debuggee(command).await?;

        //
        // Handle all threads already created by the debuggee.
        //

        let mut thread_manager = ThreadManager::new();

        let regs = sys::thread::get_thread_registers(debuggee_handle.raw_id())?;

        let mut thread = thread_manager.register_thread_create(debuggee_handle.raw_id());
        thread.instr_addr = regs.instr_addr();

        let (debug_session, loaded_binaries) =
            Session::from_suspended_process(debuggee_handle, &[], thread_manager).await?;

        //
        // Handle all binaries already loaded by the debuggee.
        //

        Ok(SpawnedTracedProcess {
            debug_session,
            loaded_binaries,
            spawned_threads: vec![thread],
            stdio: debuggee_stdio,
        })
    }
}

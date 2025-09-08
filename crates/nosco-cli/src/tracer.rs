use nosco_storage::TraceSessionStorageWriter;
use nosco_tracer::debugger::{DebugSession, MappedBinary, Thread};
use nosco_tracer::handler::EventHandler;

/// Execution trace event handler.
pub struct TraceEventHandler<S> {
    storage: S,
    backtrace_depth: usize,
}

impl<S> TraceEventHandler<S> {
    /// Initializes the event handler with a storage writer.
    pub const fn new(storage: S, backtrace_depth: usize) -> Self {
        Self {
            storage,
            backtrace_depth,
        }
    }
}

impl<S: TraceSessionStorageWriter> TraceEventHandler<S> {
    /// Finalizes the inner tracing session storage.
    pub async fn finalize_storage(mut self) -> Result<(), S::Error> {
        self.storage.finalize().await?;
        Ok(())
    }
}

impl<S: TraceSessionStorageWriter> EventHandler for TraceEventHandler<S> {
    type Session = nosco_debugger::Session;
    type Error = Error<<Self::Session as DebugSession>::Error, S::Error>;

    async fn binary_loaded(
        &mut self,
        session: &mut Self::Session,
        thread: &<Self::Session as DebugSession>::StoppedThread,
        binary: &mut <Self::Session as DebugSession>::MappedBinary,
        is_loaded_on_start: bool,
    ) -> Result<(), Self::Error> {
        let thread_id_with_backtrace = if !is_loaded_on_start {
            let backtrace = session
                .compute_backtrace(thread, self.backtrace_depth)
                .map_err(DebuggerError)?;
            Some((thread.id(), backtrace))
        } else {
            None
        };

        self.storage
            .write_loaded_binary(
                thread_id_with_backtrace,
                binary.path(),
                binary.addr_range().clone(),
            )
            .await
            .map_err(StorageError)?;

        Ok(())
    }

    async fn binary_unloaded(
        &mut self,
        session: &mut Self::Session,
        thread: &<Self::Session as DebugSession>::StoppedThread,
        unload_addr: u64,
    ) -> Result<(), Self::Error> {
        let backtrace = session
            .compute_backtrace(thread, self.backtrace_depth)
            .map_err(DebuggerError)?;

        self.storage
            .write_unloaded_binary(thread.id(), unload_addr, backtrace)
            .await
            .map_err(StorageError)?;

        Ok(())
    }

    async fn function_entered(
        &mut self,
        session: &mut Self::Session,
        thread: &<Self::Session as nosco_tracer::debugger::DebugSession>::StoppedThread,
    ) -> Result<(), Self::Error> {
        let backtrace = if !thread.is_single_step() {
            session
                .compute_backtrace(thread, self.backtrace_depth)
                .map(Some)
                .map_err(DebuggerError)?
        } else {
            None
        };

        self.storage
            .write_call_start(thread.id(), thread.instr_addr(), backtrace)
            .await
            .map_err(StorageError)?;

        Ok(())
    }

    async fn function_returned(
        &mut self,
        _session: &mut Self::Session,
        thread: &<Self::Session as nosco_tracer::debugger::DebugSession>::StoppedThread,
    ) -> Result<(), Self::Error> {
        self.storage
            .write_call_end(thread.id())
            .await
            .map_err(StorageError)?;

        Ok(())
    }

    async fn instruction_executed(
        &mut self,
        _session: &mut Self::Session,
        thread: &<Self::Session as nosco_tracer::debugger::DebugSession>::StoppedThread,
        opcodes_addr: u64,
        opcodes: Vec<u8>,
    ) -> Result<(), Self::Error> {
        self.storage
            .write_executed_instruction(thread.id(), opcodes_addr, opcodes)
            .await
            .map_err(StorageError)?;

        Ok(())
    }

    async fn thread_created(
        &mut self,
        session: &mut Self::Session,
        parent_thread: Option<&<Self::Session as DebugSession>::StoppedThread>,
        new_thread: &<Self::Session as DebugSession>::StoppedThread,
    ) -> Result<(), Self::Error> {
        let parent_thread_id_with_backtrace = if let Some(parent_thread) = parent_thread {
            let backtrace = session
                .compute_backtrace(parent_thread, self.backtrace_depth)
                .map_err(DebuggerError)?;
            Some((parent_thread.id(), backtrace))
        } else {
            None
        };

        self.storage
            .write_created_thread(parent_thread_id_with_backtrace, new_thread.id())
            .await
            .map_err(StorageError)?;

        Ok(())
    }

    async fn thread_exited(
        &mut self,
        session: &mut Self::Session,
        thread: &<Self::Session as DebugSession>::StoppedThread,
        exit_code: i32,
    ) -> Result<(), Self::Error> {
        let backtrace = session
            .compute_backtrace(thread, self.backtrace_depth)
            .map_err(DebuggerError)?;

        self.storage
            .write_exited_thread(thread.id(), exit_code, backtrace)
            .await
            .map_err(StorageError)?;

        Ok(())
    }
}

/// Debugger error.
#[derive(thiserror::Error, Debug)]
#[error(transparent)]
pub struct DebuggerError<E>(pub E);

/// Event handler error.
#[derive(thiserror::Error, Debug)]
#[error(transparent)]
pub struct StorageError<E>(pub E);

/// Error type of this crate.
#[derive(thiserror::Error, Debug)]
pub enum Error<E1, E2> {
    /// A debugger error occurred.
    #[error(transparent)]
    Debugger(#[from] DebuggerError<E1>),

    /// A storage error occurred.
    #[error(transparent)]
    Storage(#[from] StorageError<E2>),
}

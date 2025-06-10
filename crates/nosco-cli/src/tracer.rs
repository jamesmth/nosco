use nosco_storage::TraceSessionStorageWriter;
use nosco_tracer::debugger::{BinaryInformation, DebugSession, Thread};
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
        _session: &mut Self::Session,
        thread_id: Option<u64>,
        binary: &<Self::Session as nosco_tracer::debugger::DebugSession>::MappedBinary,
    ) -> Result<(), Self::Error> {
        self.storage
            .write_loaded_binary(thread_id, binary.path(), binary.addr_range().clone())
            .await
            .map_err(StorageError)?;

        Ok(())
    }

    async fn binary_unloaded(
        &mut self,
        _session: &mut Self::Session,
        thread_id: u64,
        unload_addr: u64,
    ) -> Result<(), Self::Error> {
        self.storage
            .write_unloaded_binary(thread_id, unload_addr)
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
        _session: &mut Self::Session,
        parent_thread_id: Option<u64>,
        new_thread: &<Self::Session as nosco_tracer::debugger::DebugSession>::StoppedThread,
    ) -> Result<(), Self::Error> {
        self.storage
            .write_created_thread(parent_thread_id, new_thread.id())
            .await
            .map_err(StorageError)?;

        Ok(())
    }

    async fn thread_exited(
        &mut self,
        _session: &mut Self::Session,
        thread_id: u64,
        exit_code: i32,
    ) -> Result<(), Self::Error> {
        self.storage
            .write_exited_thread(thread_id, exit_code)
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

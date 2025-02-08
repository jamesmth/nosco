mod binary;
mod thread;

use std::future::Future;

pub use self::binary::{BinaryInformation, BinaryView};
pub use self::thread::Thread;
use crate::tracer::TracedProcessStdio;
use crate::Command;

/// Trait implementing the spawning logic of a debugger.
pub trait Debugger {
    /// Debugging session returned by this debugger.
    type Session: DebugSession<Error: Into<Self::Error>>;

    /// Error returned by this trait.
    type Error;

    /// Spawns a process with the given command line.
    ///
    /// The process is spawned in a **suspended** state.
    fn spawn(
        &mut self,
        command: Command,
    ) -> impl Future<Output = Result<(Self::Session, TracedProcessStdio), Self::Error>>;
}

/// Trait implementing the instrumentation logic of a debugger.
pub trait DebugSession {
    /// Type of the register state of a stopped thread.
    type Registers: Registers;

    /// Type of a binary mapped into the debuggee's address space.
    type MappedBinary: BinaryInformation<Error: Into<Self::Error>>;

    /// Type of a debuggee's stopped thread.
    type StoppedThread: Thread<Error: Into<Self::Error>>;

    /// Error returned by this trait.
    type Error: std::error::Error;

    /// Returns the next debug event.
    fn wait_event(&mut self) -> impl Future<Output = Result<DebugEvent<Self>, Self::Error>>;

    /// Reads a single CPU instruction from the debuggee's address space.
    fn read_cpu_instruction(&self, addr: u64) -> Result<CpuInstruction, Self::Error>;

    /// Reads data from the debuggee's address space.
    fn read_memory(&self, addr: u64, buf: &mut [u8]) -> Result<(), Self::Error>;

    /// Writes data to the debuggee's address space.
    fn write_memory(&self, addr: u64, buf: &[u8]) -> Result<(), Self::Error>;

    /// Retrieves registers of the given stopped thread.
    fn get_registers(
        &mut self,
        thread: &Self::StoppedThread,
    ) -> Result<Self::Registers, Self::Error>;

    /// Modifies registers of the given stopped thread.
    fn set_registers(
        &mut self,
        thread: &Self::StoppedThread,
        regs: Self::Registers,
    ) -> Result<(), Self::Error>;

    /// Adds a breakpoint at the given address of the debuggee's address space,
    ///
    /// If `thread` is specified, the breakpoint is added for a **single
    /// thread only**.
    ///
    /// # Note
    ///
    /// If `thread` is specified and the breakpoint is triggered by another
    /// thread, the implementor makes sure that it is silently resumed
    /// (e.g., not reported by a call to `wait_event`).
    fn add_breakpoint<'a>(
        &'a mut self,
        thread: impl Into<Option<&'a Self::StoppedThread>>,
        addr: u64,
    ) -> Result<(), Self::Error>;

    /// Removes a breakpoint from the given address of the debuggee's address
    /// space.
    ///
    /// If `thread` is specified, the breakpoint is removed for a **single
    /// thread only**.
    fn remove_breakpoint<'a>(
        &'a mut self,
        thread: impl Into<Option<&'a Self::StoppedThread>>,
        addr: u64,
    ) -> Result<(), Self::Error>;

    /// Resumes the thread's execution.
    ///
    /// # Note
    ///
    /// If the thread is in [single-step mode](self::thread::Thread::single_step_mut),
    /// this function makes the thread execute a single instruction.
    fn resume(&mut self, thread: Self::StoppedThread) -> Result<(), Self::Error>;
}

/// Trait for implementing the register state of a stopped thread.
pub trait Registers {
    /// Returns a mutable reference over the instruction address.
    fn instr_addr_mut(&mut self) -> &mut u64;

    /// Returns a mutable reference over the return address.
    fn ret_addr_mut(&mut self) -> &mut u64;
}

/// Event describing some action taking place within the debuggee.
pub enum DebugEvent<S: DebugSession + ?Sized> {
    /// A thread has stopped by triggering a breakpoint.
    Breakpoint(S::StoppedThread),

    /// A thread has stopped by single-stepping.
    Singlestep(S::StoppedThread),

    /// The debugger detected some initial state within the debuggee.
    StateInit(DebugStateChange<S>),

    /// The debugger detected some state change within the debuggee.
    StateUpdate {
        /// ID of the thread responsible for the change.
        thread_id: u64,

        /// The change that occurred within the debuggee.
        change: DebugStateChange<S>,
    },

    /// The debuggee has exited.
    Exited {
        /// Exit code of the debuggee.
        exit_code: i32,
    },
}

/// State change that occurred within the debuggee.
pub enum DebugStateChange<S: DebugSession + ?Sized> {
    /// A thread is created by the debuggee.
    ThreadCreated(S::StoppedThread),

    /// A thread has exited.
    ThreadExited {
        /// Exit code of the thread.
        exit_code: i32,
    },

    /// A binary is loaded by the debuggee.
    BinaryLoaded(S::MappedBinary),

    /// A binary is unloaded by the debuggee.
    BinaryUnloaded {
        /// Image base address before unloading.
        addr: u64,
    },
}

/// CPU instruction type (arch-independent).
#[derive(Clone, Copy)]
pub enum CpuInstructionType {
    /// Function call instruction.
    FnCall,

    /// Function return instruction.
    FnRet,

    /// Other type of instruction.
    Other,
}

/// CPU instruction.
pub struct CpuInstruction {
    /// CPU instruction type.
    pub ty: CpuInstructionType,

    /// CPU instruction opcodes.
    pub opcodes: Vec<u8>,
}

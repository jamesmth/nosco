mod binary;
mod thread;

use std::future::Future;

pub use self::binary::MappedBinary;
pub use self::thread::Thread;
use crate::Command;
use crate::tracer::TracedProcessStdio;

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
    /// Type of a binary mapped into the debuggee's address space.
    type MappedBinary: MappedBinary<Error: Into<Self::Error>>;

    /// Type of a debuggee's stopped thread.
    type StoppedThread: Thread<Error: Into<Self::Error>>;

    /// Type of the register state of a stopped thread, for the x86
    /// architecture.
    type RegisterStateX86: RegistersX86<Self>;

    /// Type of the register state of a stopped thread, for the x86_64
    /// architecture.
    type RegisterStateX86_64: RegistersX86_64<Self>;

    /// Type of the register state of a stopped thread, for the arm
    /// architecture.
    type RegisterStateArm: RegistersArm<Self>;

    /// Type of the register state of a stopped thread, for the aarch64
    /// architecture.
    type RegisterStateAarch64: RegistersAarch64<Self>;

    /// Type of exception returned by the debuggee.
    type Exception;

    /// Error returned by this trait.
    type Error: std::error::Error;

    /// Returns the next debug event.
    fn wait_event(&mut self) -> impl Future<Output = Result<DebugEvent<Self>, Self::Error>>;

    /// Debuggee's process ID.
    fn process_id(&self) -> u64;

    /// Debuggee's binary context (size, endianness).
    fn binary_ctx(&self) -> BinaryContext;

    /// Reads data from the debuggee's address space.
    fn read_memory(
        &self,
        thread: &Self::StoppedThread,
        addr: u64,
        buf: &mut [u8],
    ) -> Result<(), Self::Error>;

    /// Writes data to the debuggee's address space.
    fn write_memory(
        &self,
        thread: &Self::StoppedThread,
        addr: u64,
        buf: &[u8],
    ) -> Result<(), Self::Error>;

    /// Retrieves registers of the given stopped thread.
    fn get_registers(
        &mut self,
        thread: &Self::StoppedThread,
    ) -> Result<ThreadRegisters<Self>, Self::Error>;

    /// Computes a backtrace by unwinding the stack of the given thread.
    ///
    /// The first element is the address of the last calling instruction (in
    /// other words, the most recent parent), the last being for the oldest
    /// parent.
    fn compute_backtrace(
        &mut self,
        thread: &Self::StoppedThread,
        depth: usize,
    ) -> Result<Vec<u64>, Self::Error>;

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
    /// If the thread is in [single-step mode](self::thread::Thread::is_single_step),
    /// this function makes the thread execute a single instruction.
    fn resume(&mut self, thread: Self::StoppedThread) -> Result<(), Self::Error>;
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
    Exited(ExitStatus<S::Exception>),
}

/// Exit status of the debuggee.
pub enum ExitStatus<E> {
    /// The debuggee has stopped with an exit code.
    ExitCode(i32),

    /// The debuggee has stopped because of an exception.
    Exception(E),
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

/// Binary context (container size, byte endianness).
#[derive(Copy, Clone)]
pub struct BinaryContext {
    /// Dubious pointer/address byte size of the binary context.
    pub container_size: usize,

    /// Whether the container of this binary context is "big" or not.
    ///
    /// On `x86_64`, a 64-bit binary is considered to have a "big" container,
    /// and 32-bit a "small" one.
    pub is_big_container: bool,

    /// Whether this binary context is little endian or not.
    pub is_little_endian: bool,
}

/// Register state of a stopped thread, depending on the debuggee's
/// architecture.
pub enum ThreadRegisters<S: DebugSession + ?Sized> {
    /// Register state for the x86 architecture.
    X86(S::RegisterStateX86),

    /// Register state for the x86_64 architecture.
    X86_64(S::RegisterStateX86_64),

    /// Register state for the arm architecture.
    Arm(S::RegisterStateArm),

    /// Register state for the aarch64 architecture.
    Aarch64(S::RegisterStateAarch64),
}

/// Trait implementing the register state of a stopped thread for the x86
/// architecture.
pub trait RegistersX86<S: DebugSession + ?Sized> {
    /// Assigns the registers to the stopped thread.
    fn assign_to_thread(&self, session: &S, thread: &S::StoppedThread) -> Result<(), S::Error>;

    /// Returns the value of the EAX register.
    fn eax(&self) -> u32;

    /// Returns the value of the EBX register.
    fn ebx(&self) -> u32;

    /// Returns the value of the ECX register.
    fn ecx(&self) -> u32;

    /// Returns the value of the EDX register.
    fn edx(&self) -> u32;

    /// Returns the value of the CS register.
    fn cs(&self) -> u16;

    /// Returns the value of the DS register.
    fn ds(&self) -> u16;

    /// Returns the value of the ES register.
    fn es(&self) -> u16;

    /// Returns the value of the FS register.
    fn fs(&self) -> u16;

    /// Returns the value of the GS register.
    fn gs(&self) -> u16;

    /// Returns the value of the SS register.
    fn ss(&self) -> u16;

    /// Returns the value of the ESI register.
    fn esi(&self) -> u32;

    /// Returns the value of the EDI register.
    fn edi(&self) -> u32;

    /// Returns the value of the EBP register.
    fn ebp(&self) -> u32;

    /// Returns the value of the ESP register.
    fn esp(&self) -> u32;

    /// Returns the value of the EIP register.
    fn eip(&self) -> u32;

    /// Returns the value of the EFLAGS register.
    fn eflags(&self) -> u32;
}

/// Trait implementing the register state of a stopped thread for the x86_64
/// architecture.
pub trait RegistersX86_64<S: DebugSession + ?Sized> {
    /// Assigns the registers to the stopped thread.
    fn assign_to_thread(&self, session: &S, thread: &S::StoppedThread) -> Result<(), S::Error>;

    /// Returns the value of the RAX register.
    fn rax(&self) -> u64;

    /// Returns the value of the RBX register.
    fn rbx(&self) -> u64;

    /// Returns the value of the RCX register.
    fn rcx(&self) -> u64;

    /// Returns the value of the RDX register.
    fn rdx(&self) -> u64;

    /// Returns the value of the R8 register.
    fn r8(&self) -> u64;

    /// Returns the value of the R9 register.
    fn r9(&self) -> u64;

    /// Returns the value of the R10 register.
    fn r10(&self) -> u64;

    /// Returns the value of the R11 register.
    fn r11(&self) -> u64;

    /// Returns the value of the R12 register.
    fn r12(&self) -> u64;

    /// Returns the value of the R13 register.
    fn r13(&self) -> u64;

    /// Returns the value of the R14 register.
    fn r14(&self) -> u64;

    /// Returns the value of the R15 register.
    fn r15(&self) -> u64;

    /// Returns the value of the CS register.
    fn cs(&self) -> u16;

    /// Returns the value of the DS register.
    fn ds(&self) -> u16;

    /// Returns the value of the ES register.
    fn es(&self) -> u16;

    /// Returns the value of the FS register.
    fn fs(&self) -> u16;

    /// Returns the value of the GS register.
    fn gs(&self) -> u16;

    /// Returns the value of the SS register.
    fn ss(&self) -> u16;

    /// Returns the value of the RSI register.
    fn rsi(&self) -> u64;

    /// Returns the value of the RDI register.
    fn rdi(&self) -> u64;

    /// Returns the value of the RBP register.
    fn rbp(&self) -> u64;

    /// Returns the value of the RSP register.
    fn rsp(&self) -> u64;

    /// Returns the value of the RIP register.
    fn rip(&self) -> u64;

    /// Returns the value of the RFLAGS register.
    fn rflags(&self) -> u64;
}

/// Trait implementing the register state of a stopped thread for the arm
/// architecture.
pub trait RegistersArm<S: DebugSession + ?Sized> {
    /// Assigns the registers to the stopped thread.
    fn assign_to_thread(&self, session: &S, thread: &S::StoppedThread) -> Result<(), S::Error>;

    /// Returns the value of the R0 register.
    fn r0(&self) -> u32;

    /// Returns the value of the R1 register.
    fn r1(&self) -> u32;

    /// Returns the value of the R2 register.
    fn r2(&self) -> u32;

    /// Returns the value of the R3 register.
    fn r3(&self) -> u32;

    /// Returns the value of the R4 register.
    fn r4(&self) -> u32;

    /// Returns the value of the R5 register.
    fn r5(&self) -> u32;

    /// Returns the value of the R6 register.
    fn r6(&self) -> u32;

    /// Returns the value of the R7 register.
    fn r7(&self) -> u32;

    /// Returns the value of the R8 register.
    fn r8(&self) -> u32;

    /// Returns the value of the R9 register.
    fn r9(&self) -> u32;

    /// Returns the value of the R10 register.
    fn r10(&self) -> u32;

    /// Returns the value of the FP (R11) register.
    fn fp(&self) -> u32;

    /// Returns the value of the IP (R12) register.
    fn ip(&self) -> u32;

    /// Returns the value of the SP (R13) register.
    fn sp(&self) -> u32;

    /// Returns the value of the LR (R14) register.
    fn lr(&self) -> u32;

    /// Returns the value of the PC (R15) register.
    fn pc(&self) -> u32;

    /// Returns the value of the CPSR register.
    fn cpsr(&self) -> u32;
}

/// Trait implementing the register state of a stopped thread for the aarch64
/// architecture.
pub trait RegistersAarch64<S: DebugSession + ?Sized> {
    /// Assigns the registers to the stopped thread.
    fn assign_to_thread(&self, session: &S, thread: &S::StoppedThread) -> Result<(), S::Error>;

    /// Returns the value of the R0 register.
    fn r0(&self) -> u64;

    /// Returns the value of the R1 register.
    fn r1(&self) -> u64;

    /// Returns the value of the R2 register.
    fn r2(&self) -> u64;

    /// Returns the value of the R3 register.
    fn r3(&self) -> u64;

    /// Returns the value of the R4 register.
    fn r4(&self) -> u64;

    /// Returns the value of the R5 register.
    fn r5(&self) -> u64;

    /// Returns the value of the R6 register.
    fn r6(&self) -> u64;

    /// Returns the value of the R7 register.
    fn r7(&self) -> u64;

    /// Returns the value of the R8 register.
    fn r8(&self) -> u64;

    /// Returns the value of the R9 register.
    fn r9(&self) -> u64;

    /// Returns the value of the R10 register.
    fn r10(&self) -> u64;

    /// Returns the value of the R11 register.
    fn r11(&self) -> u64;

    /// Returns the value of the R12 register.
    fn r12(&self) -> u64;

    /// Returns the value of the R13 register.
    fn r13(&self) -> u64;

    /// Returns the value of the R14 register.
    fn r14(&self) -> u64;

    /// Returns the value of the R15 register.
    fn r15(&self) -> u64;

    /// Returns the value of the R16 register.
    fn r16(&self) -> u64;

    /// Returns the value of the R17 register.
    fn r17(&self) -> u64;

    /// Returns the value of the R18 register.
    fn r18(&self) -> u64;

    /// Returns the value of the R19 register.
    fn r19(&self) -> u64;

    /// Returns the value of the R20 register.
    fn r20(&self) -> u64;

    /// Returns the value of the R21 register.
    fn r21(&self) -> u64;

    /// Returns the value of the R22 register.
    fn r22(&self) -> u64;

    /// Returns the value of the R23 register.
    fn r23(&self) -> u64;

    /// Returns the value of the R24 register.
    fn r24(&self) -> u64;

    /// Returns the value of the R25 register.
    fn r25(&self) -> u64;

    /// Returns the value of the R26 register.
    fn r26(&self) -> u64;

    /// Returns the value of the R27 register.
    fn r27(&self) -> u64;

    /// Returns the value of the R28 register.
    fn r28(&self) -> u64;

    /// Returns the value of the FP (R29) register.
    fn fp(&self) -> u64;

    /// Returns the value of the LR (R30) register.
    fn lr(&self) -> u64;

    /// Returns the value of the SP register.
    fn sp(&self) -> u64;

    /// Returns the value of the PC register.
    fn pc(&self) -> u64;

    /// Returns the value of the PSTATE register.
    fn pstate(&self) -> u64;
}

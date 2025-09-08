mod builder;
mod opcode;
mod state;
mod tracee;

use std::collections::hash_map::{Entry, OccupiedEntry, VacantEntry};
use std::collections::{HashMap, HashSet};

use tracing::Instrument;

pub use self::builder::Builder;
use self::builder::NeedsDebugger;
use self::opcode::{Opcodes, OpcodesType};
use self::state::{FullTraceState, ScopedTraceConfig, ScopedTraceState};
pub use self::tracee::{TracedProcess, TracedProcessStdio};
use crate::Command;
use crate::debugger::{DebugEvent, DebugStateChange, Debugger, MappedBinary, ThreadRegisters};
use crate::debugger::{DebugSession, ExitStatus, SpawnedTracedProcess, Thread};
use crate::debugger::{RegistersAarch64, RegistersArm, RegistersX86, RegistersX86_64};
use crate::error::{DebuggerError, HandlerError};
use crate::handler::EventHandler;

/// Process tracer.
pub struct Tracer<D, H> {
    /// Debugger attached to the tracee.
    pub(super) debugger: D,

    /// Trace event handler.
    pub(super) handler: H,

    /// Trace mode (either full-tracing, or scoped tracing)
    pub(super) trace_mode: TraceModeConfig,
}

impl Tracer<(), ()> {
    /// Creates a tracer builder.
    pub const fn builder() -> Builder<NeedsDebugger> {
        Builder::new()
    }
}

impl<D: Debugger, H> Tracer<D, H> {
    /// Spawns the process to trace with the given command line.
    ///
    /// # Note
    ///
    /// The spawned process (tracee) is suspended until [resume_and_trace](TracedProcess::resume_and_trace)
    /// is called.
    ///
    /// If the returned [`TracedProcess`] is dropped, a kill operation is invoked
    /// on the spawned process.
    #[tracing::instrument(name = "Spawn", skip_all, fields(program = %command.program.display(), args = ?command.args))]
    #[allow(clippy::type_complexity)]
    pub async fn spawn(
        mut self,
        command: Command,
    ) -> Result<(TracedProcess<D::Session, H>, TracedProcessStdio), D::Error> {
        let SpawnedTracedProcess {
            debug_session,
            loaded_binaries,
            spawned_threads,
            stdio,
        } = self.debugger.spawn(command).await?;

        tracing::info!(tracee_pid = debug_session.process_id(), "spawned");

        let state = match self.trace_mode {
            TraceModeConfig::Full { depth } => TraceState::new_full(depth),
            TraceModeConfig::Scoped(config) => TraceState::new_scoped(config),
        };

        let suspended_process = TracedProcess::new(TraceTask {
            session: debug_session,
            handler: self.handler,
            state,
            loaded_binaries,
            spawned_threads,
        });

        Ok((suspended_process, stdio))
    }
}

pub(crate) enum TraceModeConfig {
    Full { depth: usize },
    Scoped(ScopedTraceConfig),
}

/// Tracing task.
///
/// The tracee is suspended until [run](Self::run) is called.
struct TraceTask<S: DebugSession, H> {
    /// Debug session over the tracee.
    session: S,

    /// Trace event handler.
    handler: H,

    /// Trace state (full-tracing, or scoped tracing)
    state: TraceState,

    /// Loaded binaries in the tracee.
    loaded_binaries: Vec<S::MappedBinary>,

    /// Threads spawned in the tracee.
    spawned_threads: Vec<S::StoppedThread>,
}

impl<S, H> TraceTask<S, H>
where
    S: DebugSession,
    H: EventHandler<Session = S>,
{
    /// Runs the tracing task until the tracee exits.
    ///
    /// On success, the tracee's exit code is returned as well as the event handler.
    #[tracing::instrument(name = "Trace", skip_all, fields(mode = self.state.label()))]
    pub async fn run(&mut self) -> crate::Result<ExitStatus<S::Exception>, S::Error, H::Error> {
        // previously executed CPU instruction by threads (ID)
        let mut prev_instrs = HashMap::<u64, (u64, Opcodes)>::new();

        let spawned_threads = self.spawned_threads.drain(..).collect::<Vec<_>>();

        let main_thread = spawned_threads
            .first()
            .ok_or(crate::Error::TraceeWithoutThread)?;

        for binary in self.loaded_binaries.drain(..).collect::<Vec<_>>() {
            self.handle_loaded_binary_in_tracee(main_thread, binary, true)
                .instrument(tracing::info_span!("StateInit"))
                .await?;
        }

        for thread in spawned_threads {
            self.handle_created_thread_in_tracee(thread, None, &mut prev_instrs)
                .instrument(tracing::info_span!("StateInit"))
                .await?;
        }

        loop {
            let (thread, changes) = match self.session.wait_event().await.map_err(DebuggerError)? {
                DebugEvent::Breakpoint {
                    mut thread,
                    changes,
                } => {
                    match prev_instrs.entry(thread.id()) {
                        // breakpoint triggered while single-stepping
                        Entry::Occupied(prev_instr) if thread.is_single_step() => {
                            self.handle_tracee_thread_single_step(&mut thread, prev_instr)
                                .await?
                        }
                        Entry::Vacant(prev_instr) => {
                            self.handle_tracee_thread_breakpoint(&mut thread, prev_instr)
                                .await?
                        }
                        _ => unreachable!("unexpected tracing state at breakpoint"),
                    }

                    (thread, changes)
                }
                DebugEvent::Singlestep {
                    mut thread,
                    changes,
                } => {
                    let Entry::Occupied(prev_instr) = prev_instrs.entry(thread.id()) else {
                        unreachable!("unexpected tracing state at single-step");
                    };

                    self.handle_tracee_thread_single_step(&mut thread, prev_instr)
                        .await?;

                    (thread, changes)
                }
                DebugEvent::StateUpdate { thread, changes } => (thread, Some(changes)),
                DebugEvent::Exited(status) => {
                    match status {
                        ExitStatus::ExitCode(exit_code) => {
                            tracing::info!(%exit_code, "tracee has exited")
                        }
                        ExitStatus::Exception(_) => {
                            tracing::info!("tracee has exited with exception")
                        }
                    }

                    break Ok(status);
                }
            };

            if let Some(changes) = changes {
                for change in changes {
                    self.handle_tracee_state_change(&thread, change, &mut prev_instrs)
                        .instrument(tracing::info_span!("StateChange", tid = thread.id()))
                        .await?;
                }
            }

            self.session.resume(thread).map_err(DebuggerError)?;
        }
    }

    async fn handle_tracee_thread_breakpoint(
        &mut self,
        thread: &mut S::StoppedThread,
        prev_instr: VacantEntry<'_, u64, (u64, Opcodes)>,
    ) -> crate::Result<(), S::Error, H::Error> {
        let switch_to_singlestep = if self.state.is_traced_function(thread.instr_addr()) {
            tracing::info!("traced function called");

            self.handler
                .function_entered(&mut self.session, thread)
                .await
                .map_err(HandlerError)?;

            let max_depth_exceeded = match &mut self.state {
                TraceState::Full { .. } => unreachable!("unexpected tracing mode"),
                TraceState::Scoped { state, .. } => {
                    state.register_function_call(thread.id(), thread.instr_addr())
                }
            };

            if max_depth_exceeded {
                // add breakpoint to return address, even though we don't switch back to
                // single-step once it returns (we still want to catch the fact that the
                // function returned)

                let ret_addr = self.compute_return_address_at_call_start(thread)?;

                let is_first_time = self
                    .state
                    .register_breakpoint_on_return(thread.id(), ret_addr);

                if is_first_time {
                    self.session
                        .add_breakpoint(thread, false, ret_addr)
                        .map_err(DebuggerError)?;
                }
            }

            !max_depth_exceeded
        } else if let Some(is_registered_once) = self
            .state
            .unregister_breakpoint_on_return(thread.id(), thread.instr_addr())
        {
            if is_registered_once {
                self.session
                    .remove_breakpoint(thread, false, thread.instr_addr())
                    .map_err(DebuggerError)?;
            }

            self.handler
                .function_returned(&mut self.session, thread)
                .await
                .map_err(HandlerError)?;

            let depth_is_0 = match &mut self.state {
                TraceState::Full { state, .. } => state.register_function_return(thread.id()),
                TraceState::Scoped { state, .. } => state.register_function_return(thread.id()),
            };

            !depth_is_0
        } else {
            unreachable!("unexpected breakpoint at {:#x}", thread.instr_addr());
        };

        if switch_to_singlestep {
            let cur_instr = Opcodes::read_once(&self.session, thread, thread.instr_addr())
                .map_err(DebuggerError)?;

            prev_instr.insert((thread.instr_addr(), cur_instr));

            thread.set_single_step(true);
        }

        Ok(())
    }

    async fn handle_tracee_thread_single_step(
        &mut self,
        thread: &mut S::StoppedThread,
        mut prev_instr: OccupiedEntry<'_, u64, (u64, Opcodes)>,
    ) -> crate::Result<(), S::Error, H::Error> {
        let cur_instr = Opcodes::read_once(&self.session, thread, thread.instr_addr())
            .map_err(DebuggerError)?;

        let (exec_addr, exec_instr) =
            std::mem::replace(prev_instr.get_mut(), (thread.instr_addr(), cur_instr));

        self.handler
            .instruction_executed(
                &mut self.session,
                thread,
                exec_addr,
                exec_instr.bytes.to_vec(),
            )
            .await
            .map_err(HandlerError)?;

        let disable_singlestep = if let Some(OpcodesType::Call) = exec_instr.ty {
            self.handler
                .function_entered(&mut self.session, thread)
                .await
                .map_err(HandlerError)?;

            let max_depth_exceeded = match &mut self.state {
                TraceState::Full { state, .. } => state.register_function_call(thread.id()),
                TraceState::Scoped { state, .. } => {
                    state.register_function_call(thread.id(), thread.instr_addr())
                }
            };

            if max_depth_exceeded {
                // add breakpoint to return address

                let ret_addr = self.compute_return_address_at_call_start(thread)?;

                let is_first_time = self
                    .state
                    .register_breakpoint_on_return(thread.id(), ret_addr);

                if is_first_time {
                    self.session
                        .add_breakpoint(thread, false, ret_addr)
                        .map_err(DebuggerError)?;
                }
            }

            max_depth_exceeded
        } else if let Some(OpcodesType::Ret) = exec_instr.ty {
            self.handler
                .function_returned(&mut self.session, thread)
                .await
                .map_err(HandlerError)?;

            match &mut self.state {
                TraceState::Full { state, .. } => state.register_function_return(thread.id()),
                TraceState::Scoped { state, .. } => state.register_function_return(thread.id()),
            }
        } else {
            false
        };

        if disable_singlestep {
            prev_instr.remove();
            thread.set_single_step(false);
        }

        Ok(())
    }

    async fn handle_loaded_binary_in_tracee(
        &mut self,
        thread: &S::StoppedThread,
        mut binary: S::MappedBinary,
        is_loaded_on_start: bool,
    ) -> crate::Result<(), S::Error, H::Error> {
        tracing::info!(
            path = tracing::field::display(binary.path().display()),
            addr_range = format_args!("{:#x?}", binary.addr_range()),
            "binary loaded"
        );

        self.handler
            .binary_loaded(&mut self.session, thread, &mut binary, is_loaded_on_start)
            .await
            .map_err(HandlerError)?;

        if let TraceState::Scoped { ref mut state, .. } = self.state {
            state
                .register_mapped_binary::<S, H>(&mut self.session, thread, binary)
                .await?;
        }

        Ok(())
    }

    async fn handle_created_thread_in_tracee(
        &mut self,
        mut thread: S::StoppedThread,
        parent_thread: Option<&S::StoppedThread>,
        prev_instrs: &mut HashMap<u64, (u64, Opcodes)>,
    ) -> crate::Result<(), S::Error, H::Error> {
        tracing::info!(tid = thread.id(), "thread created");

        self.handler
            .thread_created(&mut self.session, parent_thread, &thread)
            .await
            .map_err(HandlerError)?;

        match self.state {
            TraceState::Full { ref mut state, .. } => {
                state.register_thread_created(thread.id());

                let max_depth_exceeded = state.register_function_call(thread.id());

                if !max_depth_exceeded {
                    // enable single-step

                    let cur_instr = Opcodes::read_once(&self.session, &thread, thread.instr_addr())
                        .map_err(DebuggerError)?;

                    prev_instrs.insert(thread.id(), (thread.instr_addr(), cur_instr));

                    thread.set_single_step(true);
                }
            }
            TraceState::Scoped { ref mut state, .. } => {
                state.register_thread_created(thread.id());
            }
        }

        self.session.resume(thread).map_err(DebuggerError)?;

        Ok(())
    }

    /// On success, returns a newly created thread within the tracee, if any.
    async fn handle_tracee_state_change(
        &mut self,
        thread: &S::StoppedThread,
        state_change: DebugStateChange<S>,
        prev_instrs: &mut HashMap<u64, (u64, Opcodes)>,
    ) -> crate::Result<(), S::Error, H::Error> {
        match state_change {
            DebugStateChange::BinaryLoaded(binary) => {
                self.handle_loaded_binary_in_tracee(thread, binary, false)
                    .await
            }

            DebugStateChange::BinaryUnloaded { addr } => {
                tracing::info!(addr = format_args!("{addr:#x}"), "binary unloaded");

                self.handler
                    .binary_unloaded(&mut self.session, thread, addr)
                    .await
                    .map_err(HandlerError)?;

                if let TraceState::Scoped { ref mut state, .. } = self.state {
                    state.register_unmapped_binary::<S, H>(&mut self.session, thread, addr)?;
                }

                Ok(())
            }
            DebugStateChange::ThreadCreated(new_thread) => {
                self.handle_created_thread_in_tracee(new_thread, Some(thread), prev_instrs)
                    .await
            }
            DebugStateChange::ThreadExited { exit_code } => {
                tracing::info!(exit_code, "thread exited");

                self.handler
                    .thread_exited(&mut self.session, thread, exit_code)
                    .await
                    .map_err(HandlerError)?;

                match &mut self.state {
                    TraceState::Full { state, .. } => state.register_thread_exited(thread.id()),
                    TraceState::Scoped { state, .. } => state.register_thread_exited(thread.id()),
                }

                prev_instrs.remove(&thread.id());

                Ok(())
            }
        }
    }

    fn compute_return_address_at_call_start(
        &mut self,
        thread: &S::StoppedThread,
    ) -> crate::Result<u64, S::Error, H::Error> {
        let regs = self.session.get_registers(thread).map_err(DebuggerError)?;

        let ret_addr = match regs {
            ThreadRegisters::X86(regs) => {
                let mut buf = [0u8; 4];
                self.session
                    .read_memory(thread, regs.esp() as u64, &mut buf)
                    .map_err(DebuggerError)?;

                if self.session.binary_ctx().is_little_endian {
                    u32::from_le_bytes(buf) as u64
                } else {
                    u32::from_be_bytes(buf) as u64
                }
            }
            ThreadRegisters::X86_64(regs) => {
                let mut buf = [0u8; 8];
                self.session
                    .read_memory(thread, regs.rsp(), &mut buf)
                    .map_err(DebuggerError)?;

                if self.session.binary_ctx().is_little_endian {
                    u64::from_le_bytes(buf)
                } else {
                    u64::from_be_bytes(buf)
                }
            }
            ThreadRegisters::Arm(regs) => regs.lr() as u64,
            ThreadRegisters::Aarch64(regs) => regs.lr(),
        };

        Ok(ret_addr)
    }
}

enum TraceState {
    Full {
        state: FullTraceState,
        // breakpoints set on return addresses (when max tracing depth reached)
        breakpoints_on_ret: HashSet<(u64, u64)>,
    },
    Scoped {
        state: ScopedTraceState,
        // breakpoints set on return addresses (when max tracing depth reached)
        breakpoints_on_ret: HashMap<(u64, u64), usize>,
    },
}

impl TraceState {
    fn new_full(max_depth: usize) -> Self {
        Self::Full {
            state: FullTraceState::new(max_depth),
            breakpoints_on_ret: HashSet::new(),
        }
    }

    fn new_scoped(config: ScopedTraceConfig) -> Self {
        Self::Scoped {
            state: ScopedTraceState::new(config),
            breakpoints_on_ret: HashMap::new(),
        }
    }

    fn is_traced_function(&self, addr: u64) -> bool {
        match self {
            Self::Full { .. } => false,
            Self::Scoped { state, .. } => state.is_function_to_trace(addr),
        }
    }

    /// Returns whether this is the first time a breakpoint on the return
    /// address is registered.
    fn register_breakpoint_on_return(&mut self, thread_id: u64, ret_addr: u64) -> bool {
        match self {
            Self::Full {
                breakpoints_on_ret, ..
            } => {
                breakpoints_on_ret.insert((thread_id, ret_addr));
                true
            }
            Self::Scoped {
                breakpoints_on_ret, ..
            } => {
                let count = breakpoints_on_ret.entry((thread_id, ret_addr)).or_default();
                *count += 1;
                *count == 1
            }
        }
    }

    /// If a breakpoint was previously registered on the return address, it
    /// returns whether it was registered only once.
    fn unregister_breakpoint_on_return(&mut self, thread_id: u64, ret_addr: u64) -> Option<bool> {
        match self {
            Self::Full {
                breakpoints_on_ret, ..
            } => breakpoints_on_ret
                .remove(&(thread_id, ret_addr))
                .then_some(true),
            Self::Scoped {
                breakpoints_on_ret, ..
            } => match breakpoints_on_ret.entry((thread_id, ret_addr)) {
                Entry::Occupied(mut e) => {
                    let count = e.get_mut();
                    *count -= 1;

                    let is_registered_once = *count == 0;
                    if is_registered_once {
                        e.remove();
                    }

                    Some(is_registered_once)
                }
                Entry::Vacant(_) => None,
            },
        }
    }

    const fn label(&self) -> &str {
        match self {
            Self::Full { .. } => "full",
            Self::Scoped { .. } => "scoped",
        }
    }
}

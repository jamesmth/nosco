use std::collections::VecDeque;

use framehop::{FrameAddress, MayAllocateDuringUnwind, Unwinder};
use nosco_tracer::debugger::{BinaryContext, Thread, ThreadRegisters};
use nosco_tracer::debugger::{DebugEvent, DebugSession, DebugStateChange};
use wholesym::samply_symbols::pdb::FallibleIterator;

use super::DebugStop;
use super::breakpoint::BreakpointManager;
use super::thread::{ThreadManager, ThreadStopReason};
use crate::sys;
use crate::sys::process::TracedProcessHandle;

#[cfg(target_arch = "x86_64")]
type StackUnwinder = framehop::x86_64::UnwinderX86_64<Vec<u8>, MayAllocateDuringUnwind>;
#[cfg(target_arch = "aarch64")]
type StackUnwinder = framehop::aarch64::UnwinderAarch64<Vec<u8>, MayAllocateDuringUnwind>;

#[cfg(target_arch = "x86_64")]
type StackUnwinderCache = framehop::x86_64::CacheX86_64<MayAllocateDuringUnwind>;
#[cfg(target_arch = "aarch64")]
type StackUnwinderCache = framehop::aarch64::CacheAarch64<MayAllocateDuringUnwind>;

/// Debugging session created by [Debugger](crate::Debugger).
pub struct Session {
    inner: sys::Session,

    /// Events that happened within the debuggee, but where not waited for yet.
    debug_events: VecDeque<DebugEvent<Self>>,

    /// Breakpoint manager.
    breakpoint_manager: BreakpointManager,

    /// Thread manager.
    thread_manager: ThreadManager,

    /// Stack frame unwinder.
    unwinder: StackUnwinder,
}

impl Session {
    #[tracing::instrument(name = "DebugSessionInit", skip_all)]
    pub(super) async fn init(
        debuggee_handle: TracedProcessHandle,
        other_thread_ids: &[u64],
    ) -> crate::Result<Self> {
        let mut breakpoint_manager = BreakpointManager::new(debuggee_handle.raw_id());

        let mut debug_events = VecDeque::new();

        let mut unwinder = StackUnwinder::new();

        let main_thread_id = debuggee_handle.raw_id();

        let session = sys::Session::init(
            debuggee_handle,
            other_thread_ids,
            SessionCx {
                breakpoint_manager: &mut breakpoint_manager,
                debug_events: &mut debug_events,
                unwinder: &mut unwinder,
                stopped_thread_id: None,
            },
        )
        .await?;

        //
        // Handle all the threads already created by the debuggee.
        //

        let mut thread_manager = ThreadManager::new();

        for thread_id in Some(main_thread_id)
            .into_iter()
            .chain(other_thread_ids.iter().copied())
        {
            let regs = get_thread_registers(thread_id)?;

            let mut thread = thread_manager.register_thread_create(thread_id);
            thread.instr_addr = regs.instr_addr();

            let event = DebugEvent::StateInit(DebugStateChange::ThreadCreated(thread));
            debug_events.push_back(event);
        }

        Ok(Self {
            inner: session,
            debug_events,
            breakpoint_manager,
            thread_manager,
            unwinder,
        })
    }

    /// Handles the case where a thread was stopped by some exception.
    ///
    /// # Note
    ///
    /// This function may push new debug events in the event queue.
    async fn handle_exception(
        &mut self,
        thread_id: u64,
        exception: sys::Exception,
    ) -> crate::Result<()> {
        if !exception.is_breakpoint_or_singlestep() {
            let thread = self
                .thread_manager
                .register_thread_stop(thread_id, Some(ThreadStopReason::Exception(exception)))
                .ok_or(crate::Error::UntrackedThread(thread_id))?;

            return self.resume(thread);
        }

        //
        // handle (potential) hardware watchpoint
        //

        let handled_hardware_watchpoint = self.inner.handle_internal_watchpoint(
            thread_id,
            SessionCx {
                breakpoint_manager: &mut self.breakpoint_manager,
                debug_events: &mut self.debug_events,
                unwinder: &mut self.unwinder,
                stopped_thread_id: Some(thread_id),
            },
        )?;

        if handled_hardware_watchpoint {
            let thread = self
                .thread_manager
                .register_thread_stop(thread_id, None)
                .ok_or(crate::Error::UntrackedThread(thread_id))?;

            return self.resume(thread);
        }

        // retrieve the associated breakpoint (if enabled)
        let mut regs = get_thread_registers(thread_id)?;
        let trap_addr = regs.instr_addr() - super::breakpoint::TRAP_OPCODES.len() as u64;
        let breakpoint = self
            .breakpoint_manager
            .get_breakpoint(trap_addr)
            .and_then(|bk| bk.enabled().then_some(bk));

        // update and get the thread state of the stopped thread
        let mut thread = self
            .thread_manager
            .register_thread_stop(
                thread_id,
                breakpoint.map(|bk| ThreadStopReason::Breakpoint(bk, false /* irrelevant */)),
            )
            .ok_or(crate::Error::UntrackedThread(thread_id))?;

        match thread.stopped_by.as_ref() {
            // the thread has triggered a breakpoint
            Some(ThreadStopReason::Breakpoint(breakpoint, is_breakpoint_of_thread)) => {
                // rewind the instruction pointer
                regs.set_instr_addr(breakpoint.addr);
                regs.assign_to_thread(self, &thread)?;

                // handle (possible) internal breakpoint of debugger
                self.inner
                    .handle_internal_breakpoint(
                        breakpoint.addr,
                        SessionCx {
                            breakpoint_manager: &mut self.breakpoint_manager,
                            debug_events: &mut self.debug_events,
                            unwinder: &mut self.unwinder,
                            stopped_thread_id: Some(thread_id),
                        },
                    )
                    .await?;

                if *is_breakpoint_of_thread {
                    thread.instr_addr = breakpoint.addr;

                    // we don't want the tracer to see the trap instruction
                    breakpoint.disable()?;

                    self.debug_events.push_back(DebugEvent::Breakpoint(thread));
                } else {
                    self.resume(thread)?;
                }
            }
            // the thread has single-stepped over some breakpoint and needs to
            // be resumed (silently)
            None if !thread.single_step && thread.stepped_over.is_some() => {
                self.resume(thread)?;
            }
            // the thread has most likely single-stepped
            None if thread.single_step => {
                thread.instr_addr = regs.instr_addr();
                self.debug_events.push_back(DebugEvent::Singlestep(thread));
            }
            None => {
                thread.stopped_by = Some(ThreadStopReason::Exception(exception));
                self.resume(thread)?;
            }
            Some(ThreadStopReason::Exception(_)) => {
                self.resume(thread)?;
            }
        }

        Ok(())
    }

    fn read_addr(&self, addr: u64) -> crate::Result<u64> {
        let bin_ctx = self.binary_ctx();

        if bin_ctx.is_big_container {
            let mut buf = [0u8; 8];
            self.read_memory(addr, &mut buf)?;

            if bin_ctx.is_little_endian {
                Ok(u64::from_le_bytes(buf))
            } else {
                Ok(u64::from_be_bytes(buf))
            }
        } else {
            let mut buf = [0u8; 4];
            self.read_memory(addr, &mut buf)?;

            if bin_ctx.is_little_endian {
                Ok(u32::from_le_bytes(buf) as u64)
            } else {
                Ok(u32::from_be_bytes(buf) as u64)
            }
        }
    }
}

impl DebugSession for Session {
    type RegisterStateX86 = sys::thread::Registers32;
    type RegisterStateX86_64 = sys::thread::Registers64;
    type RegisterStateArm = sys::thread::Registers32;
    type RegisterStateAarch64 = sys::thread::Registers64;

    type MappedBinary = sys::MappedElf;
    type StoppedThread = super::thread::StoppedThread;

    type Exception = sys::Exception;

    type Error = crate::Error;

    #[tracing::instrument(name = "DebugEventLoop", skip_all)]
    async fn wait_event(&mut self) -> Result<DebugEvent<Self>, Self::Error> {
        loop {
            if let Some(event) = self.debug_events.pop_front() {
                break Ok(event);
            }

            match self.inner.wait_for_debug_stop().await? {
                DebugStop::Exception {
                    thread_id,
                    exception,
                } => {
                    self.handle_exception(thread_id, exception).await?;
                }
                DebugStop::ThreadCreated { thread_id } => {
                    let regs = get_thread_registers(thread_id)?;

                    let mut thread = self.thread_manager.register_thread_create(thread_id);
                    thread.instr_addr = regs.instr_addr();

                    self.debug_events.push_back(DebugEvent::StateUpdate {
                        thread_id,
                        change: DebugStateChange::ThreadCreated(thread),
                    });
                }
                DebugStop::ThreadExited {
                    thread_id,
                    exit_code,
                } => {
                    let thread = self
                        .thread_manager
                        .register_thread_stop(thread_id, None)
                        .ok_or(crate::Error::UntrackedThread(thread_id))?;

                    self.resume(thread)?;

                    self.thread_manager.register_thread_exit(thread_id);

                    self.debug_events.push_back(DebugEvent::StateUpdate {
                        thread_id,
                        change: DebugStateChange::ThreadExited { exit_code },
                    });
                }
                DebugStop::Exited(status) => {
                    self.debug_events.push_back(DebugEvent::Exited(status));
                }
            }
        }
    }

    fn process_id(&self) -> u64 {
        self.inner.process_id()
    }

    fn binary_ctx(&self) -> BinaryContext {
        let ctx = self.inner.binary_ctx();

        BinaryContext {
            container_size: ctx.size(),
            is_big_container: ctx.is_big(),
            is_little_endian: ctx.is_little_endian(),
        }
    }

    fn add_breakpoint<'a>(
        &'a mut self,
        thread: impl Into<Option<&'a Self::StoppedThread>>,
        addr: u64,
    ) -> Result<(), Self::Error> {
        self.breakpoint_manager
            .add_breakpoint_or_increment_usage(addr)?;

        self.thread_manager
            .register_add_breakpoint(thread.into().map(|th| th.id()), addr);

        Ok(())
    }

    fn remove_breakpoint<'a>(
        &'a mut self,
        thread: impl Into<Option<&'a Self::StoppedThread>>,
        addr: u64,
    ) -> Result<(), Self::Error> {
        self.breakpoint_manager
            .remove_breakpoint_or_decrement_usage(addr);

        self.thread_manager
            .register_remove_breakpoint(thread.into().map(|th| th.id()), addr);

        Ok(())
    }

    fn read_memory(&self, addr: u64, buf: &mut [u8]) -> Result<(), Self::Error> {
        self.inner.read_memory(addr, buf).map_err(Into::into)
    }

    fn write_memory(&self, addr: u64, buf: &[u8]) -> Result<(), Self::Error> {
        self.inner.write_memory(addr, buf).map_err(Into::into)
    }

    fn get_registers(
        &mut self,
        thread: &Self::StoppedThread,
    ) -> Result<ThreadRegisters<Self>, Self::Error> {
        get_thread_registers(thread.id()).map(|regs| match regs {
            sys::thread::Registers::B32(regs) => {
                if cfg!(target_arch = "x86_64") {
                    ThreadRegisters::X86(regs)
                } else {
                    ThreadRegisters::Arm(regs)
                }
            }
            sys::thread::Registers::B64(regs) => {
                if cfg!(target_arch = "x86_64") {
                    ThreadRegisters::X86_64(regs)
                } else {
                    ThreadRegisters::Aarch64(regs)
                }
            }
        })
    }

    fn compute_backtrace(
        &mut self,
        thread: &Self::StoppedThread,
        depth: usize,
    ) -> Result<Vec<u64>, Self::Error> {
        let regs = get_thread_registers(thread.id())?;
        let pc = regs.instr_addr();

        let Some(unwind_regs) = regs.to_unwind() else {
            return Ok(Vec::new());
        };

        let mut read_stack = |stack_addr| {
            self.read_addr(stack_addr)
                .map_err(|_| tracing::error!(addr = stack_addr, "read memory during unwind"))
        };

        let mut unwind_cache = StackUnwinderCache::new();

        let mut frames = self
            .unwinder
            .iter_frames(pc, unwind_regs, &mut unwind_cache, &mut read_stack)
            .skip(1) // skip current frame
            .take(depth);

        let mut backtrace = Vec::with_capacity(depth);

        while let Ok(Some(frame)) = frames.next() {
            if let FrameAddress::ReturnAddress(addr) = frame {
                backtrace.push(addr.get());
            }
        }

        Ok(backtrace)
    }

    fn resume(&mut self, thread: Self::StoppedThread) -> Result<(), Self::Error> {
        let mut resume_by_single_step = thread.single_step;

        if let Some(breakpoint) = thread.stepped_over.as_ref() {
            breakpoint.enable()?;
        }

        if let Some(ThreadStopReason::Breakpoint(breakpoint, _)) = thread.stopped_by.as_ref() {
            breakpoint.disable()?;
            resume_by_single_step = true;
        }

        let thread_id = thread.id();

        let (stepping_over, exception) = match thread.stopped_by {
            Some(ThreadStopReason::Breakpoint(breakpoint, _)) => (Some(breakpoint), None),
            Some(ThreadStopReason::Exception(exception)) => (None, Some(exception)),
            None => (None, None),
        };

        sys::thread::resume_thread(thread_id, resume_by_single_step, exception)?;

        self.thread_manager
            .register_thread_resume(thread_id, thread.single_step, stepping_over);

        Ok(())
    }
}

pub struct SessionCx<'a> {
    breakpoint_manager: &'a mut BreakpointManager,
    debug_events: &'a mut VecDeque<DebugEvent<Session>>,
    unwinder: &'a mut StackUnwinder,
    stopped_thread_id: Option<u64>,
}

impl SessionCx<'_> {
    pub fn add_internal_breakpoint(&mut self, addr: u64) -> sys::Result<()> {
        self.breakpoint_manager
            .add_breakpoint_or_increment_usage(addr)
            .map(|_| ())
    }

    pub async fn on_binary_loaded(
        &mut self,
        binary: sys::MappedElf,
        unwind_module: Option<framehop::Module<Vec<u8>>>,
    ) {
        if let Some(module) = unwind_module {
            self.unwinder.add_module(module);
        };

        let change = DebugStateChange::BinaryLoaded(binary);

        let event = if let Some(thread_id) = self.stopped_thread_id {
            DebugEvent::StateUpdate { thread_id, change }
        } else {
            DebugEvent::StateInit(change)
        };

        self.debug_events.push_back(event);
    }

    pub fn on_binary_unloaded(&mut self, addr: u64) {
        self.unwinder.remove_module(addr);

        if let Some(thread_id) = self.stopped_thread_id {
            self.debug_events.push_back(DebugEvent::StateUpdate {
                thread_id,
                change: DebugStateChange::BinaryUnloaded { addr },
            });
        };
    }
}

fn get_thread_registers(thread_id: u64) -> crate::Result<sys::thread::Registers> {
    sys::thread::get_thread_registers(thread_id).map_err(Into::into)
}

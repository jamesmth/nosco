use framehop::{FrameAddress, MayAllocateDuringUnwind, Unwinder};
use nosco_symbol::elf::MappedElf;
use nosco_tracer::debugger::{BinaryContext, Thread, ThreadRegisters};
use nosco_tracer::debugger::{DebugEvent, DebugSession, DebugStateChange};
use wholesym::samply_symbols::pdb::FallibleIterator;

use super::DebugStop;
use super::breakpoint::BreakpointManager;
use super::thread::{ThreadManager, ThreadStopReason};
use crate::sys;
use crate::sys::process::TracedProcessHandle;

#[cfg(target_arch = "x86_64")]
pub type StackUnwinder = framehop::x86_64::UnwinderX86_64<Vec<u8>, MayAllocateDuringUnwind>;
#[cfg(target_arch = "aarch64")]
pub type StackUnwinder = framehop::aarch64::UnwinderAarch64<Vec<u8>, MayAllocateDuringUnwind>;

#[cfg(target_arch = "x86_64")]
pub type StackUnwinderCache = framehop::x86_64::CacheX86_64<MayAllocateDuringUnwind>;
#[cfg(target_arch = "aarch64")]
pub type StackUnwinderCache = framehop::aarch64::CacheAarch64<MayAllocateDuringUnwind>;

/// Debugging session created by [Debugger](crate::Debugger).
pub struct Session {
    inner: sys::Session,

    /// Breakpoint manager.
    breakpoint_manager: BreakpointManager,

    /// Thread manager.
    thread_manager: ThreadManager,

    /// Stack frame unwinder.
    unwinder: StackUnwinder,
}

impl Session {
    #[tracing::instrument(name = "DebugSessionInit", skip_all)]
    pub(super) async fn from_suspended_process(
        debuggee_handle: TracedProcessHandle,
        other_thread_ids: &[u64],
        thread_manager: ThreadManager,
    ) -> crate::Result<(Self, Vec<sys::MappedBinary>)> {
        let mut breakpoint_manager = BreakpointManager::new();

        let (debug_session, mut loaded_binaries) = sys::Session::from_suspended_process(
            debuggee_handle,
            other_thread_ids,
            &mut breakpoint_manager,
        )
        .await?;

        let mut unwinder = StackUnwinder::new();

        for binary in loaded_binaries.iter_mut() {
            match binary.to_unwind_module().await {
                Ok(unwind_module) => unwinder.add_module(unwind_module),
                Err(e) => tracing::warn!(error = %e),
            }
        }

        let debug_session = Self {
            inner: debug_session,
            breakpoint_manager,
            thread_manager,
            unwinder,
        };

        Ok((debug_session, loaded_binaries))
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
    ) -> crate::Result<Option<DebugEvent<Self>>> {
        if !exception.is_breakpoint_or_singlestep() {
            let thread = self
                .thread_manager
                .register_thread_stop(thread_id, Some(ThreadStopReason::Exception(exception)))
                .ok_or(crate::Error::UntrackedThread(thread_id))?;

            self.resume(thread)?;

            return Ok(None);
        }

        //
        // handle (potential) hardware watchpoint
        //

        let handled_hardware_watchpoint = self
            .inner
            .handle_internal_watchpoint(thread_id, &mut self.breakpoint_manager)?;

        if handled_hardware_watchpoint {
            let thread = self
                .thread_manager
                .register_thread_stop(thread_id, None)
                .ok_or(crate::Error::UntrackedThread(thread_id))?;

            self.resume(thread)?;

            return Ok(None);
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

        let debug_event = match thread.stopped_by.as_ref() {
            // the thread has triggered a breakpoint
            Some(ThreadStopReason::Breakpoint(breakpoint, is_breakpoint_of_thread)) => {
                // rewind the instruction pointer
                regs.set_instr_addr(breakpoint.addr);
                regs.assign_to_thread(self, &thread)?;

                // handle (possible) internal breakpoint of debugger
                let changes = self
                    .inner
                    .handle_internal_breakpoint(breakpoint.addr, &mut self.unwinder)
                    .await?;

                if *is_breakpoint_of_thread {
                    thread.instr_addr = breakpoint.addr;

                    // we don't want the tracer to see the trap instruction
                    breakpoint.disable(thread.id())?;

                    Some(DebugEvent::Breakpoint { thread, changes })
                } else if thread.single_step {
                    thread.instr_addr = regs.instr_addr();

                    Some(DebugEvent::Singlestep { thread, changes })
                } else if let Some(changes) = changes {
                    Some(DebugEvent::StateUpdate { thread, changes })
                } else {
                    self.resume(thread)?;
                    None
                }
            }
            // the thread has single-stepped over some breakpoint and needs to
            // be resumed (silently)
            None if !thread.single_step && thread.stepped_over.is_some() => {
                self.resume(thread)?;
                None
            }
            // the thread has most likely single-stepped
            None if thread.single_step => {
                thread.instr_addr = regs.instr_addr();
                Some(DebugEvent::Singlestep {
                    thread,
                    changes: None,
                })
            }
            None => {
                thread.stopped_by = Some(ThreadStopReason::Exception(exception));
                self.resume(thread)?;
                None
            }
            Some(ThreadStopReason::Exception(_)) => {
                self.resume(thread)?;
                None
            }
        };

        Ok(debug_event)
    }

    fn read_addr(
        &self,
        thread: &<Self as DebugSession>::StoppedThread,
        addr: u64,
    ) -> crate::Result<u64> {
        let bin_ctx = self.binary_ctx();

        if bin_ctx.is_big_container {
            let mut buf = [0u8; 8];
            self.read_memory(thread, addr, &mut buf)?;

            if bin_ctx.is_little_endian {
                Ok(u64::from_le_bytes(buf))
            } else {
                Ok(u64::from_be_bytes(buf))
            }
        } else {
            let mut buf = [0u8; 4];
            self.read_memory(thread, addr, &mut buf)?;

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

    type MappedBinary = MappedElf;
    type StoppedThread = super::thread::StoppedThread;

    type Exception = sys::Exception;

    type Error = crate::Error;

    #[tracing::instrument(name = "DebugEventLoop", skip_all)]
    async fn wait_event(&mut self) -> Result<DebugEvent<Self>, Self::Error> {
        loop {
            match self.inner.wait_for_debug_stop().await? {
                DebugStop::Exception {
                    thread_id,
                    exception,
                } => {
                    if let Some(event) = self.handle_exception(thread_id, exception).await? {
                        break Ok(event);
                    } else {
                        continue;
                    }
                }
                DebugStop::ThreadCreated {
                    thread_id,
                    new_thread_id,
                } => {
                    let mut thread = self
                        .thread_manager
                        .register_thread_stop(thread_id, None)
                        .ok_or(crate::Error::UntrackedThread(thread_id))?;
                    thread.instr_addr = get_thread_registers(thread_id)?.instr_addr();

                    let mut new_thread = self.thread_manager.register_thread_create(new_thread_id);
                    new_thread.instr_addr = get_thread_registers(new_thread_id)?.instr_addr();

                    break Ok(DebugEvent::StateUpdate {
                        thread,
                        changes: vec![DebugStateChange::ThreadCreated(new_thread)],
                    });
                }
                DebugStop::ThreadExited {
                    thread_id,
                    exit_code,
                } => {
                    let mut thread = self
                        .thread_manager
                        .register_thread_stop(thread_id, None)
                        .ok_or(crate::Error::UntrackedThread(thread_id))?;
                    thread.instr_addr = get_thread_registers(thread_id)?.instr_addr();

                    self.thread_manager.register_thread_exit(thread_id);

                    break Ok(DebugEvent::StateUpdate {
                        thread,
                        changes: vec![DebugStateChange::ThreadExited { exit_code }],
                    });
                }
                DebugStop::Exited(status) => {
                    break Ok(DebugEvent::Exited(status));
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

    fn add_breakpoint(
        &mut self,
        thread: &Self::StoppedThread,
        all_threads: bool,
        addr: u64,
    ) -> Result<(), Self::Error> {
        let process_id = thread.id();
        self.breakpoint_manager
            .add_breakpoint_or_increment_usage(process_id, addr)?;

        self.thread_manager
            .register_add_breakpoint((!all_threads).then_some(thread.id()), addr);

        Ok(())
    }

    fn remove_breakpoint(
        &mut self,
        thread: &Self::StoppedThread,
        all_threads: bool,
        addr: u64,
    ) -> Result<(), Self::Error> {
        let process_id = thread.id();
        self.breakpoint_manager
            .remove_breakpoint_or_decrement_usage(process_id, addr);

        self.thread_manager
            .register_remove_breakpoint((!all_threads).then_some(thread.id()), addr);

        Ok(())
    }

    fn read_memory(
        &self,
        thread: &Self::StoppedThread,
        addr: u64,
        buf: &mut [u8],
    ) -> Result<(), Self::Error> {
        sys::mem::read_process_memory(thread.id(), addr, buf).map_err(Into::into)
    }

    fn write_memory(
        &self,
        thread: &Self::StoppedThread,
        addr: u64,
        buf: &[u8],
    ) -> Result<(), Self::Error> {
        sys::mem::write_process_memory(thread.id(), addr, buf).map_err(Into::into)
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
            self.read_addr(thread, stack_addr)
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

        let thread_id = thread.id();

        if let Some(breakpoint) = thread.stepped_over.as_ref() {
            breakpoint.enable(thread_id)?;
        }

        let (stepping_over, exception) = match thread.stopped_by {
            Some(ThreadStopReason::Breakpoint(breakpoint, _)) => {
                breakpoint.disable(thread_id)?;
                resume_by_single_step = true;
                (Some(breakpoint), None)
            }
            Some(ThreadStopReason::Exception(exception)) => (None, Some(exception)),
            None => (None, None),
        };

        sys::thread::resume_thread(thread_id, resume_by_single_step, exception)?;

        self.thread_manager
            .register_thread_resume(thread_id, thread.single_step, stepping_over);

        Ok(())
    }
}

fn get_thread_registers(thread_id: u64) -> crate::Result<sys::thread::Registers> {
    sys::thread::get_thread_registers(thread_id).map_err(Into::into)
}

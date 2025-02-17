use std::collections::VecDeque;

use capstone::arch::BuildsCapstone;

use nosco_tracer::debugger::{CpuInstruction, CpuInstructionType};
use nosco_tracer::debugger::{DebugEvent, DebugSession, DebugStateChange};
use nosco_tracer::debugger::{Registers, Thread};

use super::breakpoint::BreakpointManager;
use super::thread::ThreadManager;
use super::DebugStop;
use crate::sys;
use crate::sys::process::TracedProcessHandle;

#[cfg(target_arch = "aarch64")]
const MAX_OPCODES_LEN: usize = 4;
#[cfg(target_arch = "x86_64")]
const MAX_OPCODES_LEN: usize = 15;

/// Debugging session created by [Debugger](crate::Debugger).
pub struct Session {
    inner: sys::Session,

    /// Events that happened within the debuggee, but where not waited for yet.
    debug_events: VecDeque<DebugEvent<Self>>,

    /// Breakpoint manager.
    breakpoint_manager: BreakpointManager,

    /// Thread manager.
    thread_manager: ThreadManager,

    /// Instruction disassembler.
    disass: capstone::Capstone,
}

impl Session {
    #[tracing::instrument(name = "DebugSessionInit", skip_all)]
    pub(super) async fn init(
        debuggee_handle: TracedProcessHandle,
        other_thread_ids: &[u64],
    ) -> crate::Result<Self> {
        let disass = if cfg!(target_arch = "x86_64") {
            capstone::Capstone::new()
                .x86()
                .mode(capstone::arch::x86::ArchMode::Mode64) // FIXME: mode may change at debuggee's runtime?
                .build()?
        } else if cfg!(target_arch = "aarch64") {
            capstone::Capstone::new()
                .arm64()
                .mode(capstone::arch::arm64::ArchMode::Arm)
                .build()?
        } else {
            unimplemented!("bad arch")
        };

        let mut breakpoint_manager = BreakpointManager::new(debuggee_handle.raw_id());

        let mut debug_events = VecDeque::new();

        let main_thread_id = debuggee_handle.raw_id();

        let session = sys::Session::init(
            debuggee_handle,
            other_thread_ids,
            SessionCx::new(&mut breakpoint_manager, &mut debug_events),
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
            let mut regs = get_thread_registers(thread_id)?;

            let mut thread = thread_manager.register_thread_create(thread_id);
            thread.instr_addr = *regs.instr_addr_mut();

            let event = DebugEvent::StateInit(DebugStateChange::ThreadCreated(thread));
            debug_events.push_back(event);
        }

        Ok(Self {
            inner: session,
            debug_events,
            breakpoint_manager,
            thread_manager,
            disass,
        })
    }

    /// Handles the case where a thread was stopped by some trap.
    ///
    /// # Note
    ///
    /// This function may push new debug events in the event queue.
    fn handle_trap(&mut self, thread_id: u64) -> crate::Result<()> {
        //
        // handle (potential) hardware watchpoint
        //

        let is_hardware_watchpoint = self.inner.handle_internal_watchpoint(
            thread_id,
            SessionCx::new(&mut self.breakpoint_manager, &mut self.debug_events),
        )?;

        if is_hardware_watchpoint {
            let Some(thread) = self.thread_manager.register_thread_stop(thread_id, None) else {
                unreachable!("unknown trapped thread: {thread_id}");
            };
            self.resume(thread)?;
            return Ok(());
        }

        // retrieve the associated breakpoint (if enabled)
        let mut regs = get_thread_registers(thread_id)?;
        let trap_addr = *regs.instr_addr_mut() - super::breakpoint::TRAP_OPCODES.len() as u64;
        let breakpoint = self
            .breakpoint_manager
            .get_breakpoint(trap_addr)
            .and_then(|bk| bk.enabled().then_some(bk));

        // update and get the thread state of the stopped thread
        let Some(mut thread) = self
            .thread_manager
            .register_thread_stop(thread_id, breakpoint)
        else {
            // TODO: error, return unknown trapped thread
            unreachable!("unknown trapped thread: {thread_id}");
        };

        match thread.stopped_by.as_ref() {
            // the thread has triggered a breakpoint
            Some((is_breakpoint_of_thread, breakpoint)) => {
                // rewind the instruction pointer
                *regs.instr_addr_mut() = breakpoint.addr;
                self.set_registers(&thread, regs)?;

                // handle (possible) internal breakpoint of debugger
                self.inner
                    .handle_internal_breakpoint(breakpoint.addr, |change| {
                        self.debug_events
                            .push_back(DebugEvent::StateUpdate { thread_id, change })
                    })?;

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
                thread.instr_addr = *regs.instr_addr_mut();
                self.debug_events.push_back(DebugEvent::Singlestep(thread));
            }
            None => {
                unreachable!("unknown trap reason at {trap_addr:#x}");
            }
        }

        Ok(())
    }
}

impl DebugSession for Session {
    type Registers = sys::thread::ThreadRegisters;
    type MappedBinary = sys::MappedBinary;
    type StoppedThread = super::thread::StoppedThread;

    type Error = crate::Error;

    #[tracing::instrument(name = "DebugEventLoop", skip_all)]
    async fn wait_event(&mut self) -> Result<DebugEvent<Self>, Self::Error> {
        loop {
            if let Some(event) = self.debug_events.pop_front() {
                break Ok(event);
            }

            match self.inner.wait_for_debug_stop().await? {
                DebugStop::Trap { thread_id } => {
                    self.handle_trap(thread_id)?;
                }
                DebugStop::ThreadCreated { thread_id } => {
                    let mut regs = get_thread_registers(thread_id)?;

                    let mut thread = self.thread_manager.register_thread_create(thread_id);
                    thread.instr_addr = *regs.instr_addr_mut();

                    self.debug_events.push_back(DebugEvent::StateUpdate {
                        thread_id,
                        change: DebugStateChange::ThreadCreated(thread),
                    });
                }
                DebugStop::ThreadExited {
                    thread_id,
                    exit_code,
                } => {
                    let Some(thread) = self.thread_manager.register_thread_stop(thread_id, None)
                    else {
                        // TODO: error, return unknown trapped thread
                        unreachable!("unknown trapped thread: {thread_id}");
                    };

                    self.resume(thread)?;

                    self.thread_manager.register_thread_exit(thread_id);

                    self.debug_events.push_back(DebugEvent::StateUpdate {
                        thread_id,
                        change: DebugStateChange::ThreadExited { exit_code },
                    });
                }
                DebugStop::Exited { exit_code } => {
                    self.debug_events
                        .push_back(DebugEvent::Exited { exit_code });
                }
            }
        }
    }

    fn process_id(&self) -> u64 {
        self.inner.process_id()
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
            .remove_breakpoint_or_decrement_usage(addr)?;

        self.thread_manager
            .register_remove_breakpoint(thread.into().map(|th| th.id()), addr);

        Ok(())
    }

    fn read_cpu_instruction(&self, addr: u64) -> Result<CpuInstruction, Self::Error> {
        let mut opcodes = [0u8; MAX_OPCODES_LEN];
        self.read_memory(addr, &mut opcodes)?;

        let asm = self.disass.disasm_count(&opcodes, addr, 1)?;

        let Some(instr) = asm.first() else {
            unreachable!("FIXME error");
        };

        let ty = match instr.mnemonic() {
            #[cfg(target_arch = "x86_64")]
            Some("call") => CpuInstructionType::FnCall,
            #[cfg(target_arch = "aarch64")]
            Some("bl") | Some("blaa") | Some("blaaz") | Some("blab") | Some("blabz")
            | Some("blr") | Some("blraa") | Some("blraaz") | Some("blrab") | Some("blrabz") => {
                CpuInstructionType::FnCall
            }
            #[cfg(target_arch = "x86_64")]
            Some("ret") => CpuInstructionType::FnRet,
            #[cfg(target_arch = "aarch64")]
            Some("ret") | Some("retaa") | Some("retab") => CpuInstructionType::FnRet,
            _ => CpuInstructionType::Other,
        };

        Ok(CpuInstruction {
            ty,
            opcodes: opcodes.to_vec(),
        })
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
    ) -> Result<Self::Registers, Self::Error> {
        get_thread_registers(thread.id())
    }

    fn set_registers(
        &mut self,
        thread: &Self::StoppedThread,
        regs: Self::Registers,
    ) -> Result<(), Self::Error> {
        sys::thread::set_thread_registers(thread.id(), regs).map_err(Into::into)
    }

    fn compute_return_address(
        &self,
        _thread: &Self::StoppedThread,
        regs: &mut Self::Registers,
    ) -> Result<Option<u64>, Self::Error> {
        if let Some(ret_addr) = *regs.ret_addr_mut() {
            return Ok(Some(ret_addr));
        }

        #[cfg(target_arch = "aarch64")]
        {
            Ok(*regs.ret_addr_mut())
        }

        #[cfg(target_arch = "x86_64")]
        {
            //
            // Retrieve the current return address with naive heuristics.
            //

            let filter_has_call_at_addr = |ret_addr: u64| -> Option<u64> {
                let prev_addr = ret_addr.checked_sub(MAX_OPCODES_LEN as u64)?;

                let mut buf = [0u8; MAX_OPCODES_LEN];
                self.read_memory(prev_addr, &mut buf).ok()?;

                for i in (0..(buf.len() - 3)).rev() {
                    let addr = prev_addr + i as u64;
                    let Ok(asm) = self.disass.disasm_count(&buf[i..], addr, 1) else {
                        continue;
                    };

                    if matches!(asm.first().and_then(|ins| ins.mnemonic()), Some("call")) {
                        return Some(ret_addr);
                    }
                }

                None
            };

            let bin_ctx = self.inner.binary_ctx();

            let get_retaddr_at = |addr| -> Option<u64> {
                let addr = if bin_ctx.is_big() {
                    let mut buf = [0u8; 8];
                    self.read_memory(addr, &mut buf)
                        .ok()
                        .map(|_| u64::from_le_bytes(buf))
                } else {
                    let mut buf = [0u8; 4];
                    self.read_memory(addr, &mut buf)
                        .ok()
                        .map(|_| u32::from_le_bytes(buf) as u64)
                };

                addr.and_then(filter_has_call_at_addr)
            };

            let ret_addr = get_retaddr_at(*regs.stack_ptr_mut())
                .or_else(|| {
                    get_retaddr_at(regs.stack_ptr_mut().checked_add(bin_ctx.size() as u64)?)
                })
                .or_else(|| {
                    get_retaddr_at(regs.frame_ptr_mut().checked_add(bin_ctx.size() as u64)?)
                });

            *regs.ret_addr_mut() = ret_addr;

            Ok(ret_addr)
        }
    }

    fn resume(&mut self, thread: Self::StoppedThread) -> Result<(), Self::Error> {
        let mut resume_by_single_step = thread.single_step;

        if let Some(breakpoint) = thread.stepped_over.as_ref() {
            breakpoint.enable()?;
        }

        if let Some((_, breakpoint)) = thread.stopped_by.as_ref() {
            breakpoint.disable()?;
            resume_by_single_step = true;
        }

        sys::thread::resume_thread(thread.id(), resume_by_single_step)?;

        self.thread_manager.register_thread_resume(
            thread.id(),
            thread.single_step,
            thread.stopped_by.map(|(_, bk)| bk),
        );

        Ok(())
    }
}

pub struct SessionCx<'a> {
    breakpoint_manager: &'a mut BreakpointManager,
    debug_events: &'a mut VecDeque<DebugEvent<Session>>,
}

impl<'a> SessionCx<'a> {
    fn new(
        breakpoint_manager: &'a mut BreakpointManager,
        debug_events: &'a mut VecDeque<DebugEvent<Session>>,
    ) -> Self {
        Self {
            breakpoint_manager,
            debug_events,
        }
    }

    pub fn add_internal_breakpoint(&mut self, addr: u64) -> sys::Result<()> {
        self.breakpoint_manager
            .add_breakpoint_or_increment_usage(addr)
            .map(|_| ())
    }

    pub fn push_debug_event(&mut self, event: DebugEvent<Session>) {
        self.debug_events.push_back(event);
    }
}

fn get_thread_registers(thread_id: u64) -> crate::Result<sys::thread::ThreadRegisters> {
    sys::thread::get_thread_registers(thread_id).map_err(Into::into)
}

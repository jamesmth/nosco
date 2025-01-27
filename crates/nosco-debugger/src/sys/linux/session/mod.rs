mod auxv;
mod elf;
mod rdebug;
mod watchpoint;

use std::path::Path;
use std::sync::Arc;

use indexmap::IndexSet;

use nix::libc::{PTRACE_EVENT_CLONE, PTRACE_EVENT_EXIT};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;

use nosco_tracer::debugger::{DebugEvent, DebugSession, DebugStateChange};

use wholesym::{SymbolManager, SymbolManagerConfig};

pub use self::rdebug::LinkMap;
use self::rdebug::RDebug;
use super::mem;
use crate::common::binary::MappedBinary;
use crate::common::session::SessionCx;
use crate::common::DebugStop;

pub struct Session {
    /// Debuggee PID.
    pid: Pid,

    /// RDebug context of the debuggee.
    rdebug_cx: RDebugContext,

    /// Current link map in the debuggee.
    link_map: IndexSet<LinkMap>,

    /// Binary symbol resolver.
    symbol_manager: Arc<SymbolManager>,

    /// Executable address of the debuggee.
    exe_addr: u64,
}

impl Session {
    /// Initializes a new debug session with the given process ID.
    pub async fn init(
        main_thread_id: u64,
        _thread_pids: &[u64],
        mut session_cx: SessionCx<'_>,
    ) -> crate::sys::Result<Self> {
        let debuggee_pid = Pid::from_raw(main_thread_id as i32);

        let symbol_manager = Arc::new(SymbolManager::with_config(SymbolManagerConfig::default()));

        let mut scan = self::elf::scan_debuggee_exe(debuggee_pid).await?;

        scan.lms
            .iter()
            .map(|lm| MappedBinary::new(lm.base_addr, Path::new(&lm.name), symbol_manager.clone()))
            .map(DebugStateChange::BinaryLoaded)
            .for_each(|change| session_cx.push_debug_event(DebugEvent::StateInit(change)));

        let rdebug_cx = RDebugContext::init(
            scan.rdebug_addr_loc,
            scan.rdebug_addr,
            debuggee_pid,
            scan.elf_ctx,
            &mut session_cx,
        )?;

        if let RDebugContext::Init(ref rdebug) = rdebug_cx {
            rdebug.update_lm(&mut scan.lms, scan.exe_addr, &symbol_manager, |change| {
                session_cx.push_debug_event(DebugEvent::StateInit(change))
            })?;
        }

        Ok(Session {
            pid: debuggee_pid,
            rdebug_cx,
            link_map: scan.lms,
            symbol_manager,
            exe_addr: scan.exe_addr,
        })
    }

    pub fn handle_internal_breakpoint<S>(
        &mut self,
        addr: u64,
        on_state_change: impl FnMut(DebugStateChange<S>),
    ) -> crate::sys::Result<()>
    where
        S: DebugSession<MappedBinary = MappedBinary>,
    {
        let RDebugContext::Init(ref mut rdebug) = self.rdebug_cx else {
            return Ok(());
        };

        if addr == rdebug.rbrk_addr {
            tracing::debug!("internal breakpoint (r_brk) triggered");

            // refresh the link map to detect loaded/unloaded binaries
            rdebug.refresh(
                &mut self.link_map,
                self.exe_addr,
                &self.symbol_manager,
                on_state_change,
            )?;
        }

        Ok(())
    }

    pub fn handle_internal_watchpoint(
        &mut self,
        thread_id: u64,
        mut session_cx: SessionCx<'_>,
    ) -> crate::sys::Result<bool> {
        if !self::watchpoint::check_trap_is_watchpoint(thread_id)? {
            return Ok(false);
        }

        tracing::debug!("internal watchpoint (r_debug) triggered");

        self::watchpoint::remove_hardware_watchpoint(self.pid)?;

        let (rdebug_addr_loc, rdebug_addr, elf_ctx) = match self.rdebug_cx {
            RDebugContext::Uninit {
                rdebug_addr,
                elf_ctx,
            } => {
                (0 /* irrelevant */, rdebug_addr, elf_ctx)
            }
            RDebugContext::UninitLoc {
                rdebug_addr_loc,
                elf_ctx,
            } => {
                let mut rdebug_addr = ptrace::read(self.pid, rdebug_addr_loc as *mut _)? as u64;

                if !elf_ctx.is_big() {
                    rdebug_addr &= 0xffffffff;
                }

                (rdebug_addr_loc, rdebug_addr, elf_ctx)
            }
            _ => return Ok(true),
        };

        self.rdebug_cx = RDebugContext::init(
            rdebug_addr_loc,
            rdebug_addr,
            self.pid,
            elf_ctx,
            &mut session_cx,
        )?;

        Ok(true)
    }

    pub fn read_memory(&self, addr: u64, buf: &mut [u8]) -> crate::sys::Result<()> {
        self::mem::read_process_memory(self.pid.as_raw() as u64, addr, buf)
    }

    pub fn write_memory(&self, addr: u64, buf: &[u8]) -> crate::sys::Result<()> {
        self::mem::write_process_memory(self.pid.as_raw() as u64, addr, buf)
    }

    pub async fn wait_for_debug_stop(&mut self) -> crate::sys::Result<DebugStop> {
        // FIXME: this action blocks the async runtime
        let status = waitpid(self.pid, None)?;

        let stop = match status {
            WaitStatus::Stopped(pid, Signal::SIGTRAP) => DebugStop::Trap {
                thread_id: pid.as_raw() as u64,
            },
            WaitStatus::PtraceEvent(_pid, Signal::SIGTRAP, PTRACE_EVENT_CLONE) => {
                // check if new thread (read regs args for specific flag)
                // - if not new thread, but spawned process, detach from new process
                unimplemented!("clone");
            }
            WaitStatus::PtraceEvent(pid, Signal::SIGTRAP, PTRACE_EVENT_EXIT) => {
                let exit_code = ptrace::getevent(pid)? as i32;

                DebugStop::ThreadExited {
                    thread_id: pid.as_raw() as u64,
                    exit_code,
                }
            }
            WaitStatus::Exited(_, exit_code) => DebugStop::Exited { exit_code },
            _ => return Err(crate::sys::Error::BadChildWait(status)),
        };

        Ok(stop)
    }
}

enum RDebugContext {
    /// The `r_debug` struct is initialized.
    Init(RDebug),

    /// The `r_debug` struct address is not initialized yet.
    UninitLoc {
        /// The `r_debug` struct address' location (in _DYNAMIC).
        rdebug_addr_loc: u64,

        /// ELF context (e.g., endianness) in the debuggee.
        elf_ctx: goblin::container::Ctx,
    },

    /// The `r_debug` struct content is not initialized yet.
    Uninit {
        /// The `r_debug` struct address.
        rdebug_addr: u64,

        /// ELF context (e.g., endianness) in the debuggee.
        elf_ctx: goblin::container::Ctx,
    },
}

impl RDebugContext {
    fn init(
        rdebug_addr_loc: u64,
        rdebug_addr: u64,
        debuggee_pid: Pid,
        elf_ctx: goblin::container::Ctx,
        session_cx: &mut SessionCx<'_>,
    ) -> crate::sys::Result<Self> {
        let cx = if rdebug_addr != 0 {
            tracing::debug!(
                addr = format_args!("{rdebug_addr:#x}"),
                "r_debug address is set"
            );

            let rdebug = RDebug::fetch(debuggee_pid, elf_ctx, rdebug_addr)?;

            if rdebug.rbrk_addr != 0 {
                tracing::debug!(
                    addr = format_args!("{:#x}", rdebug.rbrk_addr),
                    "r_brk is set"
                );

                Self::Init(rdebug)
            } else {
                tracing::debug!("r_brk is not set");

                Self::Uninit {
                    rdebug_addr,
                    elf_ctx,
                }
            }
        } else {
            tracing::debug!("r_debug address is not set");

            Self::UninitLoc {
                rdebug_addr_loc,
                elf_ctx,
            }
        };

        match cx {
            RDebugContext::Init(ref rdebug) => {
                // Add a breakpoint to `r_brk`, which is called by the run-time linker
                // whenever its state is changed (e.g., new library loaded).
                session_cx.add_internal_breakpoint(rdebug.rbrk_addr)?;
            }
            RDebugContext::Uninit {
                rdebug_addr,
                elf_ctx,
            } => {
                // Add a watchpoint to the `r_brk` field of the `r_debug` struct, to detect
                // when the run-time linker initializes it.
                let field_addr = rdebug_addr + elf_ctx.size() as u64 * 2;
                self::watchpoint::add_hardware_watchpoint(debuggee_pid, elf_ctx, field_addr, true)?;
            }
            RDebugContext::UninitLoc {
                rdebug_addr_loc,
                elf_ctx,
            } => {
                // Add a watchpoint to the `r_debug` struct address, to detect when
                // the run-time linker initializes it.
                self::watchpoint::add_hardware_watchpoint(
                    debuggee_pid,
                    elf_ctx,
                    rdebug_addr_loc,
                    true,
                )?;
            }
        }

        Ok(cx)
    }
}

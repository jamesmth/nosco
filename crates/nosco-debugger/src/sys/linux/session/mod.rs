mod auxv;
mod elf;
mod rdebug;
mod watchpoint;

use std::path::Path;
use std::sync::Arc;

use framehop::Unwinder;
use indexmap::IndexSet;
use nix::libc::{PTRACE_EVENT_CLONE, PTRACE_EVENT_EXIT};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use nosco_symbol::elf::{LinkMap, MappedElf};
use nosco_tracer::debugger::{DebugStateChange, ExitStatus};
use wholesym::{SymbolManager, SymbolManagerConfig};

use self::rdebug::RDebug;
use super::process::TracedProcessHandle;
use super::{Exception, mem};
use crate::common::DebugStop;
use crate::common::breakpoint::BreakpointManager;
use crate::common::session::StackUnwinder;

pub struct Session {
    /// Debuggee handle.
    debuggee_handle: TracedProcessHandle,

    /// RDebug context of the debuggee.
    rdebug_cx: RDebugContext,

    /// Current link map in the debuggee.
    link_map: IndexSet<LinkMap>,

    /// Binary symbol resolver.
    symbol_manager: Arc<SymbolManager>,

    /// Binary context (size, endianness) of the debuggee.
    elf_ctx: goblin::container::Ctx,

    /// Executable address of the debuggee.
    exe_addr: u64,
}

impl Session {
    /// Initializes a new debug session with the given process ID.
    pub async fn from_suspended_process(
        debuggee_handle: TracedProcessHandle,
        _thread_pids: &[u64],
        breakpoint_manager: &mut BreakpointManager,
    ) -> crate::Result<(Self, Vec<MappedElf>)> {
        let mut symbol_manager = SymbolManager::with_config(SymbolManagerConfig::default());
        symbol_manager.set_observer(Some(Arc::new(SymbolManagerObserver)));
        let symbol_manager = Arc::new(symbol_manager);

        let mut scan = self::elf::scan_debuggee_exe(debuggee_handle.id()).await?;

        let rdebug_cx = RDebugContext::init(
            scan.rdebug_addr_loc,
            scan.rdebug_addr,
            debuggee_handle.id(),
            scan.elf_ctx,
            scan.exe_addr,
            breakpoint_manager,
        )?;

        if let RDebugContext::Init(ref rdebug) = rdebug_cx {
            scan.lms = rdebug.fetch_link_maps()?;
        }

        let mut loaded_binaries = Vec::new();

        for lm in scan.lms.iter() {
            let binary = MappedElf::from_link_map(lm, symbol_manager.clone()).await?;
            loaded_binaries.push(binary);
        }

        let debug_session = Session {
            debuggee_handle,
            rdebug_cx,
            link_map: scan.lms,
            symbol_manager,
            elf_ctx: scan.elf_ctx,
            exe_addr: scan.exe_addr,
        };

        Ok((debug_session, loaded_binaries))
    }

    pub async fn handle_internal_breakpoint(
        &mut self,
        addr: u64,
        unwinder: &mut StackUnwinder,
    ) -> crate::Result<Option<Vec<DebugStateChange<crate::Session>>>> {
        let mut debug_state_changes = None;

        let RDebugContext::Init(ref mut rdebug) = self.rdebug_cx else {
            return Ok(debug_state_changes);
        };

        if addr == rdebug.rbrk_addr {
            tracing::debug!("internal breakpoint (r_brk) triggered");

            // refresh the link map to detect loaded/unloaded binaries
            if let Some(new_link_map) = rdebug.refresh()? {
                for lm in new_link_map.difference(&self.link_map) {
                    let mut binary =
                        MappedElf::from_link_map(lm, self.symbol_manager.clone()).await?;

                    match binary.to_unwind_module().await {
                        Ok(unwind_module) => unwinder.add_module(unwind_module),
                        Err(e) => tracing::warn!(error = %e),
                    }

                    debug_state_changes
                        .get_or_insert_default()
                        .push(DebugStateChange::BinaryLoaded(binary));
                }

                self.link_map.difference(&new_link_map).for_each(|lm| {
                    unwinder.remove_module(addr);

                    debug_state_changes
                        .get_or_insert_default()
                        .push(DebugStateChange::BinaryUnloaded { addr: lm.base_addr })
                });

                self.link_map = new_link_map;
            }
        }

        Ok(debug_state_changes)
    }

    pub fn handle_internal_watchpoint(
        &mut self,
        thread_id: u64,
        breakpoint_manager: &mut BreakpointManager,
    ) -> crate::sys::Result<bool> {
        if !self::watchpoint::check_trap_is_watchpoint(thread_id)? {
            return Ok(false);
        }

        tracing::debug!("internal watchpoint (r_debug) triggered");

        self::watchpoint::remove_hardware_watchpoint(self.debuggee_handle.id())?;

        let (rdebug_addr_loc, rdebug_addr) = match self.rdebug_cx {
            RDebugContext::Uninit { rdebug_addr } => {
                (0 /* irrelevant */, rdebug_addr)
            }
            RDebugContext::UninitLoc { rdebug_addr_loc } => {
                let mut rdebug_addr =
                    ptrace::read(self.debuggee_handle.id(), rdebug_addr_loc as *mut _)? as u64;

                if !self.elf_ctx.is_big() {
                    rdebug_addr &= 0xffffffff;
                }

                (rdebug_addr_loc, rdebug_addr)
            }
            _ => return Ok(true),
        };

        self.rdebug_cx = RDebugContext::init(
            rdebug_addr_loc,
            rdebug_addr,
            self.debuggee_handle.id(),
            self.elf_ctx,
            self.exe_addr,
            breakpoint_manager,
        )?;

        Ok(true)
    }

    /// Returns the binary context (size, endianness) of the debuggee.
    pub fn binary_ctx(&self) -> goblin::container::Ctx {
        self.elf_ctx
    }

    pub const fn process_id(&self) -> u64 {
        self.debuggee_handle.raw_id()
    }

    pub async fn wait_for_debug_stop(&mut self) -> crate::sys::Result<DebugStop> {
        loop {
            let status = waitpid(None, Some(WaitPidFlag::__WNOTHREAD))?;

            let stop = match status {
                WaitStatus::Stopped(pid, signal) => DebugStop::Exception {
                    thread_id: pid.as_raw() as u64,
                    exception: Exception(signal),
                },
                WaitStatus::PtraceEvent(pid, Signal::SIGTRAP, PTRACE_EVENT_CLONE) => {
                    let main_pid = self.debuggee_handle.id();
                    let new_pid = ptrace::getevent(pid).map(|id| Pid::from_raw(id as i32))?;

                    if let Ok(true) =
                        tokio::fs::try_exists(format!("/proc/{main_pid}/task/{new_pid}")).await
                    {
                        match waitpid(new_pid, None)? {
                            WaitStatus::Stopped(_, Signal::SIGSTOP) => (),
                            status => return Err(crate::sys::Error::BadChildWait(status)),
                        };

                        DebugStop::ThreadCreated {
                            thread_id: pid.as_raw() as u64,
                            new_thread_id: new_pid.as_raw() as u64,
                        }
                    } else {
                        ptrace::detach(new_pid, None)?;
                        continue;
                    }
                }
                WaitStatus::PtraceEvent(pid, Signal::SIGTRAP, PTRACE_EVENT_EXIT) => {
                    let exit_code = ptrace::getevent(pid)? as i32;

                    DebugStop::ThreadExited {
                        thread_id: pid.as_raw() as u64,
                        exit_code,
                    }
                }
                WaitStatus::Exited(pid, exit_code) => {
                    if pid == self.debuggee_handle.id() {
                        DebugStop::Exited(ExitStatus::ExitCode(exit_code))
                    } else {
                        continue;
                    }
                }
                WaitStatus::Signaled(_, signal, _) => {
                    DebugStop::Exited(ExitStatus::Exception(Exception(signal)))
                }
                _ => return Err(crate::sys::Error::BadChildWait(status)),
            };

            break Ok(stop);
        }
    }
}

enum RDebugContext {
    /// The `r_debug` struct is initialized.
    Init(RDebug),

    /// The `r_debug` struct address is not initialized yet.
    UninitLoc {
        /// The `r_debug` struct address' location (in _DYNAMIC).
        rdebug_addr_loc: u64,
    },

    /// The `r_debug` struct content is not initialized yet.
    Uninit {
        /// The `r_debug` struct address.
        rdebug_addr: u64,
    },
}

impl RDebugContext {
    fn init(
        rdebug_addr_loc: u64,
        rdebug_addr: u64,
        debuggee_pid: Pid,
        elf_ctx: goblin::container::Ctx,
        exe_addr: u64,
        breakpoint_manager: &mut BreakpointManager,
    ) -> crate::sys::Result<Self> {
        let cx = if rdebug_addr != 0 {
            tracing::debug!(
                addr = format_args!("{rdebug_addr:#x}"),
                "r_debug address is set"
            );

            let rdebug = RDebug::fetch(debuggee_pid, elf_ctx, exe_addr, rdebug_addr)?;

            if rdebug.rbrk_addr != 0 {
                tracing::debug!(
                    addr = format_args!("{:#x}", rdebug.rbrk_addr),
                    "r_brk is set"
                );

                Self::Init(rdebug)
            } else {
                tracing::debug!("r_brk is not set");

                Self::Uninit { rdebug_addr }
            }
        } else {
            tracing::debug!("r_debug address is not set");

            Self::UninitLoc { rdebug_addr_loc }
        };

        match cx {
            RDebugContext::Init(ref rdebug) => {
                // Add a breakpoint to `r_brk`, which is called by the run-time linker
                // whenever its state is changed (e.g., new library loaded).
                breakpoint_manager.add_breakpoint_or_increment_usage(
                    debuggee_pid.as_raw() as u64,
                    rdebug.rbrk_addr,
                )?;
            }
            RDebugContext::Uninit { rdebug_addr } => {
                // Add a watchpoint to the `r_brk` field of the `r_debug` struct, to detect
                // when the run-time linker initializes it.
                let field_addr = rdebug_addr + elf_ctx.size() as u64 * 2;
                self::watchpoint::add_hardware_watchpoint(debuggee_pid, elf_ctx, field_addr, true)?;
            }
            RDebugContext::UninitLoc { rdebug_addr_loc } => {
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

struct SymbolManagerObserver;
impl wholesym::SymbolManagerObserver for SymbolManagerObserver {
    fn on_download_canceled(&self, _download_id: u64) {}
    fn on_download_started(&self, _download_id: u64) {}
    fn on_download_progress(
        &self,
        _download_id: u64,
        _bytes_so_far: u64,
        _total_bytes: Option<u64>,
    ) {
    }

    fn on_new_download_before_connect(&self, download_id: u64, url: &str) {
        tracing::debug!(download_id, url, "downloading");
    }

    fn on_download_completed(
        &self,
        download_id: u64,
        _uncompressed_size_in_bytes: u64,
        _time_until_headers: std::time::Duration,
        _time_until_completed: std::time::Duration,
    ) {
        tracing::debug!(download_id, "download completed");
    }

    fn on_download_failed(&self, download_id: u64, reason: wholesym::DownloadError) {
        tracing::debug!(download_id, error = %reason, "download failed");
    }

    fn on_file_created(&self, path: &Path, _size_in_bytes: u64) {
        tracing::debug!(path = %path.display(), "file created");
    }

    fn on_file_accessed(&self, path: &Path) {
        tracing::debug!(path = %path.display(), "file accessed");
    }

    fn on_file_missed(&self, path: &Path) {
        tracing::debug!(path = %path.display(), "file missed");
    }
}

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::sys;

#[cfg(target_arch = "aarch64")]
pub const TRAP_OPCODES: [u8; 4] = [0x0, 0x0, 0x20, 0xd4];
#[cfg(target_arch = "x86_64")]
pub const TRAP_OPCODES: [u8; 1] = [0xcc];

pub struct BreakpointManager {
    /// BreakpointManager placed within the debuggee.
    bks: HashMap<u64, BreakpointContext>,

    /// Process ID of the debuggee.
    debuggee_process_id: u64,
}

impl BreakpointManager {
    pub fn new(debuggee_process_id: u64) -> Self {
        Self {
            bks: HashMap::new(),
            debuggee_process_id,
        }
    }
}

impl BreakpointManager {
    pub fn get_breakpoint(&self, addr: u64) -> Option<Breakpoint> {
        self.bks.get(&addr).map(|cx| Breakpoint {
            orig_opcodes: cx.orig_opcodes,
            enabled: cx.enabled.clone(),
            deleted: cx.deleted.clone(),
            debuggee_process_id: self.debuggee_process_id,
            addr,
        })
    }

    pub fn add_breakpoint_or_increment_usage(&mut self, addr: u64) -> sys::Result<Breakpoint> {
        let cx = match self.bks.entry(addr) {
            Entry::Occupied(mut e) => {
                e.get_mut().ref_count = e.get_mut().ref_count.saturating_add(1);
                e.into_mut()
            }
            Entry::Vacant(v) => {
                let mut orig_opcodes = [0u8; TRAP_OPCODES.len()];

                sys::mem::read_process_memory(self.debuggee_process_id, addr, &mut orig_opcodes)?;

                v.insert(BreakpointContext {
                    orig_opcodes,
                    ref_count: 1,
                    enabled: Arc::default(),
                    deleted: Arc::default(),
                })
            }
        };

        let bk = Breakpoint {
            orig_opcodes: cx.orig_opcodes,
            enabled: cx.enabled.clone(),
            deleted: cx.deleted.clone(),
            debuggee_process_id: self.debuggee_process_id,
            addr,
        };

        bk.enable()?;

        Ok(bk)
    }

    pub fn remove_breakpoint_or_decrement_usage(&mut self, addr: u64) -> sys::Result<()> {
        let mut bk = match self.bks.entry(addr) {
            Entry::Occupied(e) => e,
            Entry::Vacant(_) => return Ok(()),
        };

        bk.get_mut().ref_count = bk.get().ref_count.saturating_sub(1);

        if bk.get().ref_count == 0 {
            let (addr, bk) = bk.remove_entry();
            bk.deleted.swap(true, Ordering::Acquire);
            sys::mem::write_process_memory(self.debuggee_process_id, addr, &bk.orig_opcodes)?;
        }

        Ok(())
    }
}

struct BreakpointContext {
    orig_opcodes: [u8; TRAP_OPCODES.len()],
    ref_count: usize,
    enabled: Arc<AtomicBool>,
    deleted: Arc<AtomicBool>,
}

#[derive(Clone)]
pub struct Breakpoint {
    pub addr: u64,
    orig_opcodes: [u8; TRAP_OPCODES.len()],
    enabled: Arc<AtomicBool>,
    deleted: Arc<AtomicBool>,
    debuggee_process_id: u64,
}

impl Breakpoint {
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    pub fn deleted(&self) -> bool {
        self.deleted.load(Ordering::Acquire)
    }

    pub fn enable(&self) -> sys::Result<()> {
        if !self.enabled() && !self.deleted() {
            sys::mem::write_process_memory(self.debuggee_process_id, self.addr, &TRAP_OPCODES)?;
            self.enabled.swap(true, Ordering::Acquire);
        }

        Ok(())
    }

    pub fn disable(&self) -> sys::Result<()> {
        if self.enabled() & !self.deleted() {
            sys::mem::write_process_memory(
                self.debuggee_process_id,
                self.addr,
                &self.orig_opcodes,
            )?;
            self.enabled.swap(false, Ordering::Acquire);
        }

        Ok(())
    }
}
